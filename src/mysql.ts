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

const TLS_BRIDGE_PORT = 13306
let connectionIdCounter = 1

// ── MySQL packet helpers ───────────────────────────────────────────────────

function writePktHeader(buf: Buffer, payloadLen: number, seqId: number) {
	buf.writeUIntLE(payloadLen, 0, 3)
	buf[3] = seqId & 0xff
}

function buildFakeHandshakeV10(connectionId: number): { packet: Buffer; salt: Buffer } {
	const salt = Buffer.allocUnsafe(20)
	crypto.getRandomValues(salt)
	const authData1 = salt.subarray(0, 8)
	const authData2 = salt.subarray(8, 20)

	const version = Buffer.from('8.0.36\0')
	const connIdBuf = Buffer.allocUnsafe(4)
	connIdBuf.writeUInt32LE(connectionId)

	// Match real MySQL 8.0 server capabilities (Percona 8.0.45 advertises 0xdfffffff)
	// Required: SSL (0x0800), PROTOCOL_41 (0x0200), SECURE_CONNECTION (0x8000),
	//   PLUGIN_AUTH (0x00080000), CONNECT_WITH_DB (0x0008)
	const capLo = 0xffff
	// Exclude MULTI_FACTOR_AUTH (0x10000000), QUERY_ATTRIBUTES (0x08000000), DEPRECATE_EOF (0x01000000)
	// These MySQL 9.x features change the auth handshake in ways the proxy doesn't support
	const capHi = 0xc6ff
	const capLoBuf = Buffer.allocUnsafe(2)
	capLoBuf.writeUInt16LE(capLo)
	const capHiBuf = Buffer.allocUnsafe(2)
	capHiBuf.writeUInt16LE(capHi)

	const payload = Buffer.concat([
		Buffer.from([0x0a]), // protocol version
		version, // server version
		connIdBuf, // connection_id
		authData1, // auth_plugin_data_part_1 (8 bytes)
		Buffer.from([0x00]), // filler
		capLoBuf, // capability_flags_1
		Buffer.from([0x21]), // character_set (utf8mb4)
		Buffer.from([0x02, 0x00]), // status_flags
		capHiBuf, // capability_flags_2
		Buffer.from([21]), // auth_plugin_data_len (8+12+1=21)
		Buffer.alloc(10), // reserved
		authData2, // auth_plugin_data_part_2 (12 bytes)
		Buffer.from([0x00]), // null terminator for part2
		Buffer.from('caching_sha2_password\0'), // Use caching_sha2 in greeting so AuthSwitchRequest to mysql_native_password is a genuine plugin change (MySQL 9.x rejects same-plugin switches)
	])

	const packet = Buffer.allocUnsafe(4 + payload.length)
	writePktHeader(packet, payload.length, 0)
	payload.copy(packet, 4)
	return { packet, salt }
}

function isSslRequest(data: Buffer): boolean {
	// SSL request: 32-byte packet with seq=1 and CLIENT_SSL bit set
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
	// bytes 9-31: reserved

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
	if (p.length < 33 || p[0] !== 0x0a) return null // not HandshakeV10

	// skip protocol version byte
	let offset = 1
	// skip server version (null-terminated)
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
	const payload = Buffer.concat([
		Buffer.from([0xfe]),
		Buffer.from(`${plugin}\0`, 'utf8'),
		salt,
		Buffer.from([0x00]), // Null terminator after salt — required by MySQL 9.x clients
	])
	const pkt = Buffer.allocUnsafe(4 + payload.length)
	writePktHeader(pkt, payload.length, seqId)
	payload.copy(pkt, 4)
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

	const capBuf = Buffer.allocUnsafe(4)
	capBuf.writeUInt32LE(CAP)
	const maxPktBuf = Buffer.allocUnsafe(4)
	maxPktBuf.writeUInt32LE(opts.maxPacketSize || 16777216)
	// MySQL HandshakeResponse41 fixed header: 4 (caps) + 4 (max_pkt) + 1 (charset) + 23 (reserved) = 32
	const reserved = Buffer.alloc(24)
	reserved[0] = opts.charset

	const dbBuf = opts.database ? Buffer.from(`${opts.database}\0`) : Buffer.from([0x00])

	const payload = Buffer.concat([
		capBuf,
		maxPktBuf,
		reserved,
		Buffer.from(`${opts.username}\0`),
		Buffer.from([opts.authResponse.length]),
		opts.authResponse,
		dbBuf,
		Buffer.from(`${opts.authPlugin}\0`),
	])

	const pkt = Buffer.allocUnsafe(4 + payload.length)
	writePktHeader(pkt, payload.length, 1) // seq=1 (response to backend greeting)
	payload.copy(pkt, 4)
	return pkt
}

/** Patch the seq byte in a MySQL packet */
function patchSeq(data: Uint8Array, newSeq: number): Buffer {
	const buf = Buffer.from(data)
	buf[3] = newSeq & 0xff
	return buf
}

function buildMysqlError(message: string, seqId = 2): Buffer {
	const msg = Buffer.from(message, 'utf8')
	const payload = Buffer.concat([
		Buffer.from([0xff]), // ERR_Packet
		Buffer.from([0x15, 0x04]), // error code 1045
		Buffer.from('#'), // sql state marker
		Buffer.from('28000'), // sql state
		msg,
	])
	const pkt = Buffer.allocUnsafe(4 + payload.length)
	writePktHeader(pkt, payload.length, seqId)
	payload.copy(pkt, 4)
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
}

type PlainData = {
	state: 'greeting_sent' | 'bridging' | 'auth_switch_sent' | 'piping'
	bridge: ReturnType<typeof Bun.connect> | null
	backend: ReturnType<typeof Bun.connect> | null
	pendingBuf: Uint8Array[]
	// saved during plaintext handshake
	savedClient: ClientHandshakeInfo | null
	realUser: string
	backendPlugin: string
	isFirstBackendResponse: boolean // seq rewrite needed only for first packet after auth
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
				socket.data.clientBuf.push(Buffer.from(rawData).slice())
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
							// Backend sends HandshakeV10 — consume it, extract salt
							const greeting = parseBackendHandshakeV10(Buffer.from(backData))
							if (!greeting) {
								console.error('[mysql:sni] failed to parse backend HandshakeV10')
								socket.end()
								return
							}

							// Always use mysql_native_password for the AuthSwitchRequest
							const plugin = 'mysql_native_password'
							socket.data.backendPlugin = plugin

							// AuthSwitchRequest: seq = client's HandshakeResponse41 seq + 1
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
								// Backend OK/Error at seq=2 → patch to client's expected seq
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

			const back = socket.data.backend as any
			if (!back) {
				console.warn('[mysql:sni] backend not ready for HandshakeResponse41')
				socket.end()
				return
			}

			back.write(resp)
			socket.data.state = 'piping'
			return
		}

		// ── Transparent post-auth pipe ────────────────────────────────
		if (state === 'piping') {
			const back = socket.data.backend as any
			if (back) {
				back.write(rawData)
			}
		}
	}

	// ── Internal TLS Bridge (SNI mode) ──────────────────────────────────
	// After TLS handshake, performs AuthSwitchRequest dance with the client
	// (same as plaintext mode) so the client re-authenticates with the real
	// backend salt. The backend's HandshakeV10 is consumed, not forwarded.
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

				socket.data.resolvedBackend = backend
				socket.data.handshakeResolved = true

				// If client data arrived before resolve() completed, process it now
				if (socket.data.clientBuf.length > 0) {
					const buffered = Buffer.concat(socket.data.clientBuf.map((c: Uint8Array) => Buffer.from(c)))
					socket.data.clientBuf.length = 0
					handleTlsClientData(socket, buffered)
				}
			},

			data(socket, rawData) {
				handleTlsClientData(socket, rawData)
			},

			close(socket) {
				;(socket.data.backend as any)?.end?.()
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
											// First packet from backend = HandshakeV10
											const greeting = parseBackendHandshakeV10(Buffer.from(backData))
											if (!greeting) {
												console.error('[mysql:plain] failed to parse backend HandshakeV10')
												socket.end()
												return
											}

											const plugin = greeting.authPluginName
											socket.data.backendPlugin = plugin

											// Refuse caching_sha2_password without SSL
											// (needs full auth over plaintext, which requires password in clear)
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

											// Send AuthSwitchRequest to client with real backend salt (seq=2)
											const authSwitch = buildAuthSwitchRequest(plugin, greeting.authPluginData, 2)
											socket.write(authSwitch)

											// Save backend socket — we'll write to it when client responds
											socket.data.backend = backSock as unknown as ReturnType<typeof Bun.connect>
											socket.data.isFirstBackendResponse = true
											return
										}

										if (st === 'piping') {
											if (socket.data.isFirstBackendResponse) {
												// First response from backend after auth = OK or Error
												// Client is at seq=3 so expects seq=4 in response
												socket.data.isFirstBackendResponse = false
												socket.write(patchSeq(backData, 4))
											} else {
												socket.write(backData)
											}
											return
										}

										// Flush any buffered post-handshake data
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
						;(socket.data.bridge as unknown as { write: (d: Uint8Array) => void }).write(rawData)
					} else {
						// Deep copy — Bun may reuse the rawData buffer after callback returns
						socket.data.pendingBuf.push(Buffer.from(rawData))
					}
					return
				}

				// ── Client sends AuthSwitchResponse (seq=3) ───────────────
				if (state === 'auth_switch_sent') {
					const info = socket.data.savedClient!
					const newAuthBytes = extractAuthBytes(Buffer.from(rawData))

					// Build HandshakeResponse41 for backend with fresh auth bytes
					const resp = buildHandshakeResponse41({
						username: socket.data.realUser,
						authResponse: newAuthBytes,
						database: info.database,
						authPlugin: socket.data.backendPlugin,
						charset: info.charset,
						maxPacketSize: info.maxPacketSize,
					})

					const back = socket.data.backend as unknown as { write: (d: Buffer) => void } | null
					if (!back) {
						console.warn('[mysql:plain] backend not ready for HandshakeResponse41')
						socket.end()
						return
					}

					back.write(resp)
					socket.data.state = 'piping'
					return
				}

				// ── Transparent post-auth pipe ────────────────────────────
				if (state === 'piping') {
					const back = socket.data.backend as unknown as { write: (d: Uint8Array) => void } | null
					if (back) {
						back.write(rawData)
					}
				}
			},

			close(socket) {
				;(socket.data.bridge as unknown as { end: () => void } | null)?.end()
				;(socket.data.backend as unknown as { end: () => void } | null)?.end()
			},

			error(_, err) {
				if (err.message !== 'ECONNRESET') console.error('[mysql] client error:', err.message)
			},
		},
	})

	console.log(`[mysql] :${port} — SNI/TLS + plaintext user@id12 (mysql_native_password)`)
}
