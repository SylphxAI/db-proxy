/**
 * Postgres Protocol Handler — Bun native API
 *
 * Supports two routing modes:
 *
 * 1. SNI routing (requires SSL/TLS from client):
 *    Client → SSLRequest → 'S' → TLS bridge → SNI extraction → backend
 *
 * 2. Plaintext routing (SSL optional, Neon-style):
 *    Client → StartupMessage{user="realuser@id12"} →
 *    proxy strips @id12, rewrites user, connects to backend directly.
 *    All auth (SCRAM-SHA-256, MD5, trust...) is relayed transparently.
 *    Proxy never sees passwords.
 *
 * Connection string format for plaintext:
 *   postgresql://app@25e3b05c46dc:pass@25e3b05c46dc.db.sylphx.net:5432/db?sslmode=disable
 */

import * as fs from 'node:fs'
import type { BackendTarget } from './router.ts'
import { trackConnect, trackDisconnect } from './metrics.ts'

const SSL_REQUEST = Buffer.from([0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f])
const PROTOCOL_V3 = 0x00030000
const TLS_BRIDGE_PORT = 15432

// Max bytes buffered per connection before handshake completes.
// Prevents memory exhaustion from slow or malicious clients.
const MAX_PENDING_BYTES = 1024 * 1024 // 1MB

function pendingSize(bufs: Uint8Array[]): number {
	let n = 0
	for (const b of bufs) n += b.length
	return n
}

function buildPgError(code: string, message: string): Buffer {
	const body = Buffer.from(`SERROR\0C${code}\0M${message}\0\0`)
	const out = Buffer.allocUnsafe(1 + 4 + body.length)
	out[0] = 0x45
	out.writeUInt32BE(4 + body.length, 1)
	body.copy(out, 5)
	return out
}

// ── StartupMessage helpers ─────────────────────────────────────────────────

function parseStartupMessage(data: Buffer): Record<string, string> | null {
	if (data.length < 8) return null
	const msgLen = data.readUInt32BE(0)
	if (data.length < msgLen) return null
	if (data.readUInt32BE(4) !== PROTOCOL_V3) return null

	const params: Record<string, string> = {}
	let i = 8
	while (i < msgLen - 1) {
		const kEnd = data.indexOf(0, i)
		if (kEnd < 0 || kEnd === i) break
		const key = data.subarray(i, kEnd).toString('utf8')
		i = kEnd + 1
		const vEnd = data.indexOf(0, i)
		if (vEnd < 0) break
		params[key] = data.subarray(i, vEnd).toString('utf8')
		i = vEnd + 1
	}
	return params
}

/**
 * Rebuild StartupMessage with a new username.
 * All other params preserved (database, application_name, etc.)
 */
function rewriteStartupUser(data: Buffer, newUser: string): Buffer {
	const params = parseStartupMessage(data)
	if (!params) return data
	params.user = newUser

	const parts: Buffer[] = []
	for (const [k, v] of Object.entries(params)) {
		parts.push(Buffer.from(`${k}\0${v}\0`, 'utf8'))
	}
	parts.push(Buffer.from([0x00])) // final null terminator

	const paramsBuf = Buffer.concat(parts)
	const total = 8 + paramsBuf.length
	const result = Buffer.allocUnsafe(total)
	result.writeUInt32BE(total, 0)
	result.writeUInt32BE(PROTOCOL_V3, 4)
	paramsBuf.copy(result, 8)
	return result
}

// ── Socket write helper ────────────────────────────────────────────────────
// Bun.connect returns a typed socket but TypeScript doesn't expose write/end
// cleanly across the plain↔TLS boundary. This helper avoids scattered `as any`.

function socketWrite(sock: unknown, data: Uint8Array): void {
	;(sock as { write(d: Uint8Array): void }).write(data)
}

function socketEnd(sock: unknown): void {
	;(sock as { end(): void }).end()
}

// ── Types ──────────────────────────────────────────────────────────────────

type TlsData = {
	sni: string
	backend: ReturnType<typeof Bun.connect> | null
	clientBuf: Uint8Array[]
}

type PlainData = {
	state: 'init' | 'bridging' | 'plaintext'
	bridge: ReturnType<typeof Bun.connect> | null
	backend: ReturnType<typeof Bun.connect> | null
	pendingBuf: Uint8Array[]
}

// ── Main export ────────────────────────────────────────────────────────────

export function startPostgresProxy(
	port: number,
	certPath: string,
	keyPath: string,
	resolve: (id12: string) => Promise<BackendTarget | null>,
): void {
	const cert = fs.readFileSync(certPath)
	const key = fs.readFileSync(keyPath)

	// ── Internal TLS Bridge (SNI mode) ──────────────────────────────────
	Bun.listen<TlsData>({
		hostname: '127.0.0.1',
		port: TLS_BRIDGE_PORT,
		tls: { cert, key },
		socket: {
			open(socket) {
				socket.data = { sni: '', backend: null, clientBuf: [] }
			},

			async handshake(socket, success) {
				if (!success) {
					socket.end()
					return
				}

				const sni = socket.getServername() ?? ''
				if (!sni) {
					socket.write(buildPgError('28000', 'TLS SNI hostname required'))
					socket.end()
					return
				}

				const id12 = sni.split('.')[0]
				let backend: BackendTarget | null = null
				try {
					backend = await resolve(id12)
				} catch (err) {
					console.error(`[pg:sni] router error for ${id12}:`, err)
					socket.write(buildPgError('08006', 'Internal routing error'))
					socket.end()
					return
				}

				if (!backend) {
					socket.write(buildPgError('3D000', `Database "${id12}" not found`))
					socket.end()
					return
				}

				trackConnect('pg_tls')
				console.log(`[pg:sni] ${id12} -> ${backend.host}:${backend.port}`)

				Bun.connect({
					hostname: backend.host,
					port: backend.port,
					socket: {
						open(back) {
							for (const c of socket.data.clientBuf) back.write(c)
							socket.data.clientBuf.length = 0
							socket.data.backend = back as unknown as ReturnType<typeof Bun.connect>
						},
						data(_, d) {
							socket.write(d)
						},
						close() {
							socket.end()
						},
						error(_, e) {
							if (e.message !== 'ECONNRESET') {
								console.error(`[pg:sni] backend error ${id12}:`, e.message)
							}
							socket.end()
						},
					},
				})
			},

			data(socket, rawData) {
				if (socket.data.backend) {
					socketWrite(socket.data.backend, rawData)
				} else {
					// Deep copy — Bun may reuse the rawData buffer after callback returns
					if (pendingSize(socket.data.clientBuf) + rawData.length > MAX_PENDING_BYTES) {
						console.warn('[pg:tls] client buffer overflow, dropping connection')
						socket.end()
						return
					}
					socket.data.clientBuf.push(Buffer.from(rawData))
				}
			},

			close(socket) {
				if (socket.data.backend) {
					socketEnd(socket.data.backend)
					trackDisconnect('pg_tls')
				}
			},

			error(_, err) {
				if (err.message !== 'ECONNRESET') console.error('[pg:tls]', err.message)
			},
		},
	})

	// ── Public Plain TCP Server ──────────────────────────────────────────
	Bun.listen<PlainData>({
		hostname: '0.0.0.0',
		port,
		socket: {
			open(socket) {
				socket.data = { state: 'init', bridge: null, backend: null, pendingBuf: [] }
			},

			data(socket, rawData) {
				const { state } = socket.data

				// ── First message: decide routing mode ────────────────────
				if (state === 'init') {
					const d = Buffer.from(rawData)

					// SSLRequest → SNI/TLS mode
					if (d.equals(SSL_REQUEST)) {
						socket.write('S')
						socket.data.state = 'bridging'
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
									console.error('[pg] bridge error:', e.message)
									socket.end()
								},
							},
						})
						return
					}

					// StartupMessage → try plaintext routing
					const params = parseStartupMessage(d)
					if (params) {
						const user = params.user ?? ''
						const atIdx = user.lastIndexOf('@')

						if (atIdx !== -1) {
							// user@id12 format — plaintext routing
							const id12 = user.slice(atIdx + 1)
							const realUser = user.slice(0, atIdx)
							socket.data.state = 'plaintext'

							resolve(id12)
								.then((backend) => {
									if (!backend) {
										socket.write(buildPgError('3D000', `Database "${id12}" not found`))
										socket.end()
										return
									}

									trackConnect('pg_plain')
									console.log(`[pg:plain] ${id12} (${realUser}) -> ${backend.host}:${backend.port}`)
									const rewritten = rewriteStartupUser(d, realUser)

									Bun.connect({
										hostname: backend.host,
										port: backend.port,
										socket: {
											open(back) {
												back.write(rewritten)
												for (const c of socket.data.pendingBuf) back.write(c)
												socket.data.pendingBuf.length = 0
												socket.data.backend = back as unknown as ReturnType<typeof Bun.connect>
											},
											data(_, d) {
												socket.write(d)
											},
											close() {
												socket.end()
											},
											error(_, e) {
												if (e.message !== 'ECONNRESET') {
													console.error(`[pg:plain] backend error ${id12}:`, e.message)
												}
												socket.end()
											},
										},
									})
								})
								.catch((err) => {
									console.error('[pg:plain] resolve error:', err)
									socket.write(buildPgError('08006', 'Internal routing error'))
									socket.end()
								})
							return
						}

						// StartupMessage without @id12 — reject with helpful message
						socket.write(
							buildPgError(
								'28000',
								'Plaintext connection requires user@<db-id> format, e.g. app@25e3b05c46dc. Or use SSL for SNI routing.',
							),
						)
						socket.end()
						return
					}

					socket.write(buildPgError('08P01', 'Unexpected first message'))
					socket.end()
					return
				}

				// ── SNI/TLS mode pipe ─────────────────────────────────────
				if (state === 'bridging') {
					if (socket.data.bridge) {
						socketWrite(socket.data.bridge, rawData)
					} else {
						if (pendingSize(socket.data.pendingBuf) + rawData.length > MAX_PENDING_BYTES) {
							console.warn('[pg] bridge buffer overflow, dropping connection')
							socket.end()
							return
						}
						// Deep copy — Bun may reuse the rawData buffer after callback returns
						socket.data.pendingBuf.push(Buffer.from(rawData))
					}
					return
				}

				// ── Plaintext mode pipe ───────────────────────────────────
				if (state === 'plaintext') {
					if (socket.data.backend) {
						socketWrite(socket.data.backend, rawData)
					} else {
						if (pendingSize(socket.data.pendingBuf) + rawData.length > MAX_PENDING_BYTES) {
							console.warn('[pg:plain] pending buffer overflow, dropping connection')
							socket.end()
							return
						}
						// Deep copy — Bun may reuse the rawData buffer after callback returns
						socket.data.pendingBuf.push(Buffer.from(rawData))
					}
				}
			},

			close(socket) {
				if (socket.data.bridge) socketEnd(socket.data.bridge)
				if (socket.data.backend) {
					socketEnd(socket.data.backend)
					trackDisconnect('pg_plain')
				}
			},

			error(_, err) {
				if (err.message !== 'ECONNRESET') console.error('[pg] client error:', err.message)
			},
		},
	})

	console.log(`[postgres] :${port} — SNI/TLS + plaintext user@id12`)
}
