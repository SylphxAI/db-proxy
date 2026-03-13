/**
 * MySQL Protocol Handler — Bun native API
 *
 * Supports two routing modes:
 *
 * 1. SNI routing (requires SSL/TLS from client):
 *    Client → SSLRequest → TLS bridge → SNI extraction → AuthSwitchRequest dance → Backend
 *
 *    Flow:
 *      Proxy → Client: fake HandshakeV10 (seq=0, caching_sha2_password)
 *      Client → Proxy: SSLRequest (seq=1)
 *      Client ↔ TLS bridge: TLS handshake (SNI = id12.db.sylphx.net)
 *      Client → Bridge: HandshakeResponse41 (seq=2, auth with fake salt — discarded)
 *      Bridge → Backend: TCP connect
 *      Backend → Bridge: HandshakeV10 (seq=0, real salt — consumed, not forwarded)
 *      Bridge → Client: AuthSwitchRequest (seq=3, mysql_native_password + real salt)
 *      Client → Bridge: AuthSwitchResponse (seq=4, hash(password, real_salt))
 *      Bridge → Backend: HandshakeResponse41 (seq=1, username + real auth)
 *      Backend → Bridge: OK/Error (seq=2) → relay to client as seq=5
 *      ─── transparent piping ───
 *
 * 2. Plaintext routing (SSL optional, Neon-style):
 *    Client → HandshakeResponse41{user="realuser@id12"} →
 *    proxy resolves backend, performs AuthSwitchRequest dance so client
 *    re-authenticates against the real backend salt. No passwords stored.
 *
 *    Flow:
 *      Proxy → Client: fake HandshakeV10 (seq=0)
 *      Client → Proxy: HandshakeResponse41 (seq=1, has @id12 in user)
 *      Proxy → Backend: TCP connect
 *      Backend → Proxy: real HandshakeV10 (seq=0, real salt)
 *      Proxy → Client: AuthSwitchRequest (seq=2, real plugin + real salt)
 *      Client → Proxy: AuthSwitchResponse (seq=3, hash(password, real_salt))
 *      Proxy → Backend: HandshakeResponse41 (seq=1, realUser + new auth)
 *      Backend → Proxy: OK/Error (seq=2) → relay to client as seq=4
 *      ─── transparent piping ───
 *
 *    Note: mysql_native_password is fully supported. caching_sha2_password
 *    requires SSL (falls back to SNI mode).
 *
 * Connection string formats:
 *   TLS/SNI:    Server=28701772e2ae.db.sylphx.net;User=crazycube;SslMode=Required
 *   Plaintext:  Server=28701772e2ae.db.sylphx.net;User=crazycube@28701772e2ae;SslMode=None
 */

import * as fs from 'node:fs'
import type { BackendTarget } from './router.ts'
import { trackConnect, trackDisconnect, trackHandshakeTimeout } from './metrics.ts'

const TLS_BRIDGE_PORT = 13306
let connectionIdCounter = 1

// Max bytes buffered per connection before handshake completes.
// Prevents memory exhaustion from slow or malicious clients.
const MAX_PENDING_BYTES = 1024 * 1024 // 1MB

// Connections that don't complete handshake within this window are dropped.
// Prevents socket exhaustion from abandoned connections, port scanners, etc.
const HANDSHAKE_TIMEOUT_MS = 30_000

function pendingSize(bufs: Uint8Array[]): number {
	let n = 0
	for (const b of bufs) n += b.length
	return n
}

// ── Socket write helper ────────────────────────────────────────────────────
// Avoids scattered `as unknown as { write: ... }` type casts throughout.

function socketWrite(sock: unknown, data: Uint8Array): void {
	;(sock as { write(d: Uint8Array): void }).write(data)
}

function socketEnd(sock: unknown): void {
	;(sock as { end(): void }).end()
}

// ── MySQL packet helpers ───────────────────────────────────────────────────

function writePktHeader(buf: Buffer, payloadLen: number, seqId: number) {
	buf.writeUIntLE(payloadLen, 0, 3)
	buf[3] = seqId & 0xff
}

// Pre-computed constants for buildFakeHandshakeV10
const FAKE_VERSION = Buffer.from('8.0.36\0')
const FAKE_PLUGIN = Buffer.from('caching_sha2_password\0')
// Match real MySQL 8.0 server capabilities (Percona 8.0.45 advertises 0xdfffffff)
// Exclude MULTI_FACTOR_AUTH, QUERY_ATTRIBUTES, DEPRECATE_EOF — MySQL 9.x features
// that change the auth handshake in ways the proxy doesn't support
const CAP_LO = 0xffff
const CAP_HI = 0xc6ff

function buildFakeHandshakeV10(connectionId: number): { packet: Buffer; salt: Buffer } {
	const salt = Buffer.allocUnsafe(20)
	crypto.getRandomValues(salt)

	// Pre-calculate payload size:
	// 1 (proto) + 7 (version) + 4 (connId) + 8 (salt1) + 1 (filler)
	// + 2 (capLo) + 1 (charset) + 2 (status) + 2 (capHi) + 1 (authLen)
	// + 10 (reserved) + 12 (salt2) + 1 (null) + 22 (plugin) = 74
	const payloadLen = 74
	const pkt = Buffer.allocUnsafe(4 + payloadLen)
	writePktHeader(pkt, payloadLen, 0)

	let off = 4
	pkt[off++] = 0x0a // protocol version
	FAKE_VERSION.copy(pkt, off)
	off += FAKE_VERSION.length
	pkt.writeUInt32LE(connectionId, off)
	off += 4
	salt.copy(pkt, off, 0, 8) // auth_plugin_data_part_1
	off += 8
	pkt[off++] = 0x00 // filler
	pkt.writeUInt16LE(CAP_LO, off)
	off += 2
	pkt[off++] = 0x21 // charset utf8mb4
	pkt.writeUInt16LE(0x0002, off) // status_flags
	off += 2
	pkt.writeUInt16LE(CAP_HI, off)
	off += 2
	pkt[off++] = 21 // auth_plugin_data_len (8+12+1=21)
	pkt.fill(0, off, off + 10) // reserved
	off += 10
	salt.copy(pkt, off, 8, 20) // auth_plugin_data_part_2
	off += 12
	pkt[off++] = 0x00 // null terminator for part2
	FAKE_PLUGIN.copy(pkt, off) // caching_sha2_password\0
	// off += FAKE_PLUGIN.length

	return { packet: pkt, salt }
}

function isSslRequest(data: Buffer): boolean {
	if (data.length < 36) return false
	const len = data.readUIntLE(0, 3)
	if (len !== 32) return false
	if (data[3] !== 1) return false
	return (data.readUInt32LE(4) & 0x0800) !== 0
}

interface ClientHandshakeInfo {
	capabilities: number
	maxPacketSize: number
	charset: number
	username: string // raw (includes @id12 in plaintext mode, clean in TLS mode)
	database: string
	seqId: number
}

function parseHandshakeResponse41(data: Buffer): ClientHandshakeInfo | null {
	if (data.length < 36) return null
	const pktLen = data.readUIntLE(0, 3)
	const seqId = data[3]
	if (data.length < 4 + pktLen || pktLen < 32) return null

	const p = data.subarray(4, 4 + pktLen)
	const capabilities = p.readUInt32LE(0)
	const maxPacketSize = p.readUInt32LE(4)
	const charset = p[8]

	let offset = 32

	// username (null-terminated)
	const userEnd = p.indexOf(0, offset)
	if (userEnd < 0) return null
	const username = p.subarray(offset, userEnd).toString('utf8')
	offset = userEnd + 1

	// skip auth_response (we'll get a new one via AuthSwitchRequest)
	if (capabilities & 0x00200000) {
		// CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
		const authLen = p[offset]
		if (authLen < 0xfb) {
			offset += 1 + authLen
		} else if (authLen === 0xfc) {
			offset += 3 + p.readUInt16LE(offset + 1)
		} else if (authLen === 0xfd) {
			offset += 4 + p.readUIntLE(offset + 1, 3)
		} else {
			offset += 9 + Number(p.readBigUInt64LE(offset + 1))
		}
	} else if (capabilities & 0x8000) {
		// CLIENT_SECURE_CONNECTION
		const authLen = p[offset]
		offset += 1 + authLen
	} else {
		const authEnd = p.indexOf(0, offset)
		offset = authEnd < 0 ? p.length : authEnd + 1
	}

	// database (if CLIENT_CONNECT_WITH_DB)
	let database = ''
	if (capabilities & 0x0008) {
		const dbEnd = p.indexOf(0, offset)
		if (dbEnd >= 0) {
			database = p.subarray(offset, dbEnd).toString('utf8')
			offset = dbEnd + 1
		}
	}

	return { capabilities, maxPacketSize, charset, username, database, seqId }
}

interface BackendGreeting {
	authPluginData: Buffer // 20 bytes of random salt
	authPluginName: string
}

function parseBackendHandshakeV10(data: Buffer): BackendGreeting | null {
	if (data.length < 4) return null
	const pktLen = data.readUIntLE(0, 3)
	if (data.length < 4 + pktLen) return null
	const p = data.subarray(4, 4 + pktLen)
	if (p.length < 33 || p[0] !== 0x0a) return null

	let offset = 1
	const vEnd = p.indexOf(0, offset)
	if (vEnd < 0) return null
	offset = vEnd + 1 + 4 // +4 for connection_id

	const authData1 = p.subarray(offset, offset + 8)
	offset += 8 + 1 // +1 filler

	const capLo = p.readUInt16LE(offset)
	offset += 2
	offset += 1 + 2 // charset + status_flags
	const capHi = p.readUInt16LE(offset)
	offset += 2
	const capabilities = (capHi << 16) | capLo

	const authDataLen = p[offset]
	offset += 1
	offset += 10 // reserved

	const part2Len = Math.max(13, authDataLen - 8)
	const authData2 = p.subarray(offset, offset + part2Len - 1)
	offset += part2Len

	let authPluginName = 'mysql_native_password'
	if (capabilities & 0x00080000) {
		const nameEnd = p.indexOf(0, offset)
		if (nameEnd >= 0) authPluginName = p.subarray(offset, nameEnd).toString('utf8')
	}

	return { authPluginData: Buffer.concat([authData1, authData2]), authPluginName }
}

/** AuthSwitchRequest: 0xFE + plugin_name\0 + auth_plugin_data + \0 */
function buildAuthSwitchRequest(plugin: string, salt: Buffer, seqId: number): Buffer {
	const pluginBuf = Buffer.from(`${plugin}\0`, 'utf8')
	const payloadLen = 1 + pluginBuf.length + salt.length + 1
	const pkt = Buffer.allocUnsafe(4 + payloadLen)
	writePktHeader(pkt, payloadLen, seqId)
	let off = 4
	pkt[off++] = 0xfe
	pluginBuf.copy(pkt, off)
	off += pluginBuf.length
	salt.copy(pkt, off)
	off += salt.length
	pkt[off] = 0x00 // Null terminator after salt — required by MySQL 9.x clients
	return pkt
}

/** Extract raw auth bytes from an AuthSwitchResponse / auth plugin packet */
function extractAuthBytes(data: Buffer): Buffer {
	if (data.length < 4) return Buffer.alloc(0)
	const pktLen = data.readUIntLE(0, 3)
	return data.subarray(4, 4 + pktLen)
}

/** Build HandshakeResponse41 for backend (seq=1) */
function buildHandshakeResponse41(opts: {
	username: string
	authResponse: Buffer
	database: string
	authPlugin: string
	charset: number
	maxPacketSize: number
}): Buffer {
	const CAP =
		0x00000001 | // CLIENT_LONG_PASSWORD
		0x00000004 | // CLIENT_FOUND_ROWS
		0x00000008 | // CLIENT_CONNECT_WITH_DB
		0x00000200 | // CLIENT_PROTOCOL_41
		0x00008000 | // CLIENT_SECURE_CONNECTION
		0x00080000 | // CLIENT_PLUGIN_AUTH
		0x00200000 // CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA

	const userBuf = Buffer.from(`${opts.username}\0`, 'utf8')
	const dbBuf = opts.database ? Buffer.from(`${opts.database}\0`) : Buffer.from([0x00])
	const pluginBuf = Buffer.from(`${opts.authPlugin}\0`, 'utf8')

	// Fixed: 4 (caps) + 4 (max_pkt) + 1 (charset) + 23 (reserved) = 32
	const payloadLen = 32 + userBuf.length + 1 + opts.authResponse.length + dbBuf.length + pluginBuf.length
	const pkt = Buffer.allocUnsafe(4 + payloadLen)
	writePktHeader(pkt, payloadLen, 1) // seq=1

	let off = 4
	pkt.writeUInt32LE(CAP, off)
	off += 4
	pkt.writeUInt32LE(opts.maxPacketSize || 16777216, off)
	off += 4
	pkt[off++] = opts.charset
	pkt.fill(0, off, off + 23) // reserved
	off += 23
	userBuf.copy(pkt, off)
	off += userBuf.length
	pkt[off++] = opts.authResponse.length
	opts.authResponse.copy(pkt, off)
	off += opts.authResponse.length
	dbBuf.copy(pkt, off)
	off += dbBuf.length
	pluginBuf.copy(pkt, off)

	return pkt
}

/**
 * Patch the seq byte in a MySQL packet.
 * Must copy — Bun owns the original rawData buffer and may reuse it.
 */
function patchSeq(data: Uint8Array, newSeq: number): Buffer {
	const buf = Buffer.from(data)
	buf[3] = newSeq & 0xff
	return buf
}

function buildMysqlError(message: string, seqId = 2): Buffer {
	const msgBuf = Buffer.from(message, 'utf8')
	const payloadLen = 1 + 2 + 1 + 5 + msgBuf.length
	const pkt = Buffer.allocUnsafe(4 + payloadLen)
	writePktHeader(pkt, payloadLen, seqId)
	let off = 4
	pkt[off++] = 0xff // ERR_Packet
	pkt.writeUInt16LE(0x0415, off) // error code 1045
	off += 2
	pkt[off++] = 0x23 // '#' sql state marker
	pkt.write('28000', off, 'ascii') // sql state
	off += 5
	msgBuf.copy(pkt, off)
	return pkt
}

// ── Types ──────────────────────────────────────────────────────────────────

type TlsData = {
	sni: string
	id12: string
	resolvedBackend: BackendTarget | null
	handshakeResolved: boolean // true after async resolve() in handshake() completes
	state: 'wait_client_handshake' | 'wait_backend_greeting' | 'wait_auth_switch_resp' | 'piping'
	backend: ReturnType<typeof Bun.connect> | null
	clientBuf: Uint8Array[] // buffers client data arriving before handshake resolution
	savedClient: ClientHandshakeInfo | null
	backendPlugin: string
	isFirstBackendResponse: boolean
	handshakeTimer: ReturnType<typeof setTimeout> | null
}

type PlainData = {
	state: 'greeting_sent' | 'bridging' | 'auth_switch_sent' | 'piping'
	bridge: ReturnType<typeof Bun.connect> | null
	backend: ReturnType<typeof Bun.connect> | null
	pendingBuf: Uint8Array[]
	savedClient: ClientHandshakeInfo | null
	realUser: string
	backendPlugin: string
	isFirstBackendResponse: boolean
	handshakeTimer: ReturnType<typeof setTimeout> | null
}

// ── Main export ────────────────────────────────────────────────────────────

export function startMysqlProxy(
	port: number,
	certPath: string,
	keyPath: string,
	resolve: (id12: string) => Promise<BackendTarget | null>,
): void {
	const cert = fs.readFileSync(certPath)
	const key = fs.readFileSync(keyPath)

	// ── TLS Bridge: auth dance helper ────────────────────────────────────
	// Processes client data inside the TLS tunnel. Called from both
	// handshake() (for buffered data) and data() (for live data).
	function handleTlsClientData(socket: any, rawData: Uint8Array) {
		const { state, id12 } = socket.data as TlsData

		// ── Client sends HandshakeResponse41 (seq=2) after TLS ────────
		if (state === 'wait_client_handshake') {
			if (!socket.data.handshakeResolved) {
				// handshake() hasn't finished resolving yet — buffer
				if (pendingSize(socket.data.clientBuf) + rawData.length > MAX_PENDING_BYTES) {
					console.warn('[mysql:sni] client buffer overflow, dropping connection')
					socket.end()
					return
				}
				socket.data.clientBuf.push(Buffer.from(rawData))
				return
			}

			const d = Buffer.from(rawData)
			const info = parseHandshakeResponse41(d)
			if (!info) {
				console.warn('[mysql:sni] could not parse HandshakeResponse41')
				socket.end()
				return
			}

			socket.data.savedClient = info
			socket.data.state = 'wait_backend_greeting'

			const target = socket.data.resolvedBackend!
			console.log(`[mysql:sni] ${id12} (${info.username}) -> ${target.host}:${target.port}`)

			// Connect to backend MySQL
			Bun.connect({
				hostname: target.host,
				port: target.port,
				socket: {
					open() {
						/* wait for backend HandshakeV10 */
					},

					data(backSock, backData) {
						const st = socket.data.state

						if (st === 'wait_backend_greeting') {
							const greeting = parseBackendHandshakeV10(Buffer.from(backData))
							if (!greeting) {
								console.error('[mysql:sni] failed to parse backend HandshakeV10')
								socket.end()
								return
							}

							const plugin = 'mysql_native_password'
							socket.data.backendPlugin = plugin

							const switchSeq = (socket.data.savedClient?.seqId ?? 2) + 1
							const authSwitch = buildAuthSwitchRequest(plugin, greeting.authPluginData, switchSeq)
							socket.write(authSwitch)

							socket.data.backend = backSock
							socket.data.state = 'wait_auth_switch_resp'
							socket.data.isFirstBackendResponse = true
							return
						}

						if (st === 'piping') {
							if (socket.data.isFirstBackendResponse) {
								const clientSeq = (socket.data.savedClient?.seqId ?? 2) + 3
								socket.data.isFirstBackendResponse = false
								socket.write(patchSeq(backData, clientSeq))
							} else {
								socket.write(backData)
							}
							return
						}

						socket.write(backData)
					},

					close() {
						socket.end()
					},
					error(_, e) {
						if (e.message !== 'ECONNRESET') {
							console.error(`[mysql:sni] backend error ${id12}:`, e.message)
						}
						socket.end()
					},
				},
			})
			return
		}

		// ── Client sends AuthSwitchResponse (seq=4) ───────────────────
		if (state === 'wait_auth_switch_resp') {
			const info = socket.data.savedClient!
			const newAuthBytes = extractAuthBytes(Buffer.from(rawData))

			const resp = buildHandshakeResponse41({
				username: info.username,
				authResponse: newAuthBytes,
				database: info.database,
				authPlugin: socket.data.backendPlugin,
				charset: info.charset,
				maxPacketSize: info.maxPacketSize,
			})

			if (!socket.data.backend) {
				console.warn('[mysql:sni] backend not ready for HandshakeResponse41')
				socket.end()
				return
			}

			socketWrite(socket.data.backend, resp)
			socket.data.state = 'piping'
			if (socket.data.handshakeTimer) {
				clearTimeout(socket.data.handshakeTimer)
				socket.data.handshakeTimer = null
			}
			return
		}

		// ── Transparent post-auth pipe ────────────────────────────────
		if (state === 'piping') {
			if (socket.data.backend) {
				socketWrite(socket.data.backend, rawData)
			}
		}
	}

	// ── Internal TLS Bridge (SNI mode) ──────────────────────────────────
	Bun.listen<TlsData>({
		hostname: '127.0.0.1',
		port: TLS_BRIDGE_PORT,
		tls: { cert, key },
		socket: {
			open(socket) {
				socket.data = {
					sni: '',
					id12: '',
					resolvedBackend: null,
					handshakeResolved: false,
					state: 'wait_client_handshake',
					backend: null,
					clientBuf: [],
					savedClient: null,
					backendPlugin: 'mysql_native_password',
					isFirstBackendResponse: false,
					handshakeTimer: setTimeout(() => {
						trackHandshakeTimeout()
						console.warn('[mysql:sni] handshake timeout, dropping connection')
						socket.end()
					}, HANDSHAKE_TIMEOUT_MS),
				}
			},

			async handshake(socket, success) {
				if (!success) {
					socket.end()
					return
				}

				const sni = socket.getServername() ?? ''
				if (!sni) {
					socket.end()
					return
				}

				const id12 = sni.split('.')[0]
				socket.data.sni = sni
				socket.data.id12 = id12

				let backend: BackendTarget | null = null
				try {
					backend = await resolve(id12)
				} catch (err) {
					console.error(`[mysql:sni] router error ${id12}:`, err)
					socket.end()
					return
				}

				if (!backend) {
					console.warn(`[mysql:sni] unknown id12: ${id12}`)
					socket.write(buildMysqlError(`Database "${id12}" not found`, 3))
					socket.end()
					return
				}

				trackConnect('mysql_tls')
				socket.data.resolvedBackend = backend
				socket.data.handshakeResolved = true

				// If client data arrived before resolve() completed, process it now
				if (socket.data.clientBuf.length > 0) {
					const buffered = Buffer.concat(socket.data.clientBuf)
					socket.data.clientBuf.length = 0
					handleTlsClientData(socket, buffered)
				}
			},

			data(socket, rawData) {
				handleTlsClientData(socket, rawData)
			},

			close(socket) {
				if (socket.data.handshakeTimer) clearTimeout(socket.data.handshakeTimer)
				if (socket.data.backend) {
					socketEnd(socket.data.backend)
					trackDisconnect('mysql_tls')
				}
			},

			error(_, err) {
				if (err.message !== 'ECONNRESET') console.error('[mysql:tls]', err.message)
			},
		},
	})

	console.log(`[mysql] Internal TLS bridge on 127.0.0.1:${TLS_BRIDGE_PORT}`)

	// ── Public Plain TCP Server ──────────────────────────────────────────
	Bun.listen<PlainData>({
		hostname: '0.0.0.0',
		port,
		socket: {
			open(socket) {
				const connId = connectionIdCounter++
				const { packet } = buildFakeHandshakeV10(connId)
				socket.data = {
					state: 'greeting_sent',
					bridge: null,
					backend: null,
					pendingBuf: [],
					savedClient: null,
					realUser: '',
					backendPlugin: 'mysql_native_password',
					isFirstBackendResponse: false,
					handshakeTimer: setTimeout(() => {
						trackHandshakeTimeout()
						console.warn('[mysql:plain] handshake timeout, dropping connection')
						socket.end()
					}, HANDSHAKE_TIMEOUT_MS),
				}
				socket.write(packet)
			},

			data(socket, rawData) {
				const { state } = socket.data

				// ── Client response to our greeting ───────────────────────
				if (state === 'greeting_sent') {
					const d = Buffer.from(rawData)

					// SSLRequest → SNI/TLS mode
					if (isSslRequest(d)) {
						socket.data.state = 'bridging'

						// Buffer any bytes beyond the 36-byte SSLRequest packet.
						// When the client sends SSLRequest and immediately starts the TLS
						// handshake, TCP may coalesce them into a single segment. Without
						// this, the TLS ClientHello bytes are silently dropped and the
						// handshake hangs indefinitely.
						if (d.length > 36) {
							socket.data.pendingBuf.push(Buffer.from(d.subarray(36)))
						}

						Bun.connect({
							hostname: '127.0.0.1',
							port: TLS_BRIDGE_PORT,
							socket: {
								open(bridge) {
									for (const c of socket.data.pendingBuf) bridge.write(c)
									socket.data.pendingBuf.length = 0
									socket.data.bridge = bridge as unknown as ReturnType<typeof Bun.connect>
								},
								data(_, d) {
									socket.write(d)
								},
								close() {
									socket.end()
								},
								error(_, e) {
									console.error('[mysql] bridge error:', e.message)
									socket.end()
								},
							},
						})
						return
					}

					// HandshakeResponse41 → plaintext routing
					const info = parseHandshakeResponse41(d)
					if (!info) {
						console.warn('[mysql:plain] could not parse HandshakeResponse41')
						socket.end()
						return
					}

					const user = info.username
					const atIdx = user.lastIndexOf('@')
					if (atIdx === -1) {
						socket.write(
							buildMysqlError(
								'Plaintext routing requires user@<db-id> format, e.g. crazycube@28701772e2ae',
							),
						)
						socket.end()
						return
					}

					const id12 = user.slice(atIdx + 1)
					const realUser = user.slice(0, atIdx)
					socket.data.savedClient = info
					socket.data.realUser = realUser
					socket.data.state = 'auth_switch_sent'

					resolve(id12)
						.then((backend) => {
							if (!backend) {
								socket.write(buildMysqlError(`Database "${id12}" not found`))
								socket.end()
								return
							}

							trackConnect('mysql_plain')
							console.log(`[mysql:plain] ${id12} (${realUser}) -> ${backend.host}:${backend.port}`)

							Bun.connect({
								hostname: backend.host,
								port: backend.port,
								socket: {
									open() {
										/* wait for greeting */
									},

									data(backSock, backData) {
										const st = socket.data.state

										if (st === 'auth_switch_sent') {
											const greeting = parseBackendHandshakeV10(Buffer.from(backData))
											if (!greeting) {
												console.error('[mysql:plain] failed to parse backend HandshakeV10')
												socket.end()
												return
											}

											const plugin = greeting.authPluginName
											socket.data.backendPlugin = plugin

											if (plugin === 'caching_sha2_password') {
												console.warn(`[mysql:plain] ${id12}: caching_sha2_password requires SSL`)
												socket.write(
													buildMysqlError(
														`User "${realUser}" uses caching_sha2_password which requires SSL. Add SslMode=Required or change auth plugin to mysql_native_password.`,
													),
												)
												socket.end()
												return
											}

											const authSwitch = buildAuthSwitchRequest(plugin, greeting.authPluginData, 2)
											socket.write(authSwitch)

											socket.data.backend = backSock as unknown as ReturnType<typeof Bun.connect>
											socket.data.isFirstBackendResponse = true
											return
										}

										if (st === 'piping') {
											if (socket.data.isFirstBackendResponse) {
												socket.data.isFirstBackendResponse = false
												socket.write(patchSeq(backData, 4))
											} else {
												socket.write(backData)
											}
											return
										}

										socket.write(backData)
									},

									close() {
										socket.end()
									},
									error(_, e) {
										if (e.message !== 'ECONNRESET') {
											console.error(`[mysql:plain] backend error ${id12}:`, e.message)
										}
										socket.end()
									},
								},
							})
						})
						.catch((err) => {
							console.error('[mysql:plain] resolve error:', err)
							socket.write(buildMysqlError('Internal routing error'))
							socket.end()
						})
					return
				}

				// ── SNI/TLS bridge pipe ───────────────────────────────────
				if (state === 'bridging') {
					if (socket.data.bridge) {
						socketWrite(socket.data.bridge, rawData)
					} else {
						if (pendingSize(socket.data.pendingBuf) + rawData.length > MAX_PENDING_BYTES) {
							console.warn('[mysql] bridge buffer overflow, dropping connection')
							socket.end()
							return
						}
						// Deep copy — Bun may reuse the rawData buffer after callback returns
						socket.data.pendingBuf.push(Buffer.from(rawData))
					}
					return
				}

				// ── Client sends AuthSwitchResponse (seq=3) ───────────────
				if (state === 'auth_switch_sent') {
					const info = socket.data.savedClient!
					const newAuthBytes = extractAuthBytes(Buffer.from(rawData))

					const resp = buildHandshakeResponse41({
						username: socket.data.realUser,
						authResponse: newAuthBytes,
						database: info.database,
						authPlugin: socket.data.backendPlugin,
						charset: info.charset,
						maxPacketSize: info.maxPacketSize,
					})

					if (!socket.data.backend) {
						console.warn('[mysql:plain] backend not ready for HandshakeResponse41')
						socket.end()
						return
					}

					socketWrite(socket.data.backend, resp)
					socket.data.state = 'piping'
					if (socket.data.handshakeTimer) {
						clearTimeout(socket.data.handshakeTimer)
						socket.data.handshakeTimer = null
					}
					return
				}

				// ── Transparent post-auth pipe ────────────────────────────
				if (state === 'piping') {
					if (socket.data.backend) {
						socketWrite(socket.data.backend, rawData)
					}
				}
			},

			close(socket) {
				if (socket.data.handshakeTimer) clearTimeout(socket.data.handshakeTimer)
				if (socket.data.bridge) socketEnd(socket.data.bridge)
				if (socket.data.backend) {
					socketEnd(socket.data.backend)
					trackDisconnect('mysql_plain')
				}
			},

			error(_, err) {
				if (err.message !== 'ECONNRESET') console.error('[mysql] client error:', err.message)
			},
		},
	})

	console.log(`[mysql] :${port} — SNI/TLS + plaintext user@id12 (mysql_native_password)`)
}
