/**
 * Redis Protocol Handler — Bun native API
 *
 * SNI-based TLS routing for managed Redis instances.
 *
 * Pattern:
 *   Client → rediss:// (TLS) → SNI extraction → backend (plaintext internal)
 *
 * Unlike Postgres/MySQL, Redis has no inner-protocol SSL negotiation.
 * We listen directly with TLS; after the handshake we extract the SNI,
 * resolve the backend, and pipe data bidirectionally — pure TCP.
 *
 * Connection string format:
 *   rediss://{id12}.db.sylphx.net:6379
 */

import * as fs from "node:fs";
import { trackConnect, trackDisconnect, trackHandshakeTimeout } from "./metrics.ts";
import type { BackendTarget } from "./router.ts";

const HANDSHAKE_TIMEOUT_MS = 30_000;
const MAX_PENDING_BYTES = 1024 * 1024; // 1MB

function pendingSize(bufs: Uint8Array[]): number {
	let n = 0;
	for (const b of bufs) n += b.length;
	return n;
}

function socketWrite(sock: unknown, data: Uint8Array): void {
	(sock as { write(d: Uint8Array): void }).write(data);
}

function socketEnd(sock: unknown): void {
	(sock as { end(): void }).end();
}

type RedisData = {
	backend: ReturnType<typeof Bun.connect> | null;
	clientBuf: Uint8Array[];
	handshakeTimer: ReturnType<typeof setTimeout> | null;
};

export function startRedisProxy(
	port: number,
	certPath: string,
	keyPath: string,
	resolve: (id12: string) => Promise<BackendTarget | null>,
): void {
	const cert = fs.readFileSync(certPath);
	const key = fs.readFileSync(keyPath);

	Bun.listen<RedisData>({
		hostname: "0.0.0.0",
		port,
		tls: { cert, key },
		socket: {
			open(socket) {
				socket.data = {
					backend: null,
					clientBuf: [],
					handshakeTimer: setTimeout(() => {
						trackHandshakeTimeout();
						console.warn("[redis:tls] handshake timeout, dropping connection");
						socket.end();
					}, HANDSHAKE_TIMEOUT_MS),
				};
			},

			async handshake(socket, success) {
				if (!success) {
					socket.end();
					return;
				}

				const sni = socket.getServername() ?? "";
				if (!sni) {
					console.warn("[redis:tls] no SNI hostname, dropping connection");
					socket.end();
					return;
				}

				const id12 = sni.split(".")[0];
				let backend: BackendTarget | null = null;
				try {
					backend = await resolve(id12);
				} catch (err) {
					console.error(`[redis:sni] router error for ${id12}:`, err);
					socket.end();
					return;
				}

				if (!backend) {
					console.warn(`[redis:sni] backend not found for ${id12}, dropping connection`);
					socket.end();
					return;
				}

				trackConnect("redis_tls");
				console.log(`[redis:sni] ${id12} -> ${backend.host}:${backend.port}`);

				if (socket.data.handshakeTimer) {
					clearTimeout(socket.data.handshakeTimer);
					socket.data.handshakeTimer = null;
				}

				Bun.connect({
					hostname: backend.host,
					port: backend.port,
					socket: {
						open(back) {
							for (const c of socket.data.clientBuf) back.write(c);
							socket.data.clientBuf.length = 0;
							socket.data.backend = back as unknown as ReturnType<typeof Bun.connect>;
						},
						data(_, d) {
							socket.write(d);
						},
						close() {
							socket.end();
						},
						error(_, e) {
							if (e.message !== "ECONNRESET") {
								console.error(`[redis:sni] backend error ${id12}:`, e.message);
							}
							socket.end();
						},
					},
				});
			},

			data(socket, rawData) {
				if (socket.data.backend) {
					socketWrite(socket.data.backend, rawData);
				} else {
					if (pendingSize(socket.data.clientBuf) + rawData.length > MAX_PENDING_BYTES) {
						console.warn("[redis:tls] client buffer overflow, dropping connection");
						socket.end();
						return;
					}
					// Deep copy — Bun may reuse the rawData buffer after callback returns
					socket.data.clientBuf.push(Buffer.from(rawData));
				}
			},

			close(socket) {
				if (socket.data.handshakeTimer) clearTimeout(socket.data.handshakeTimer);
				if (socket.data.backend) {
					socketEnd(socket.data.backend);
					trackDisconnect("redis_tls");
				}
			},

			error(_, err) {
				if (err.message !== "ECONNRESET") console.error("[redis:tls]", err.message);
			},
		},
	});

	console.log(`[redis] :${port} — SNI/TLS`);
}
