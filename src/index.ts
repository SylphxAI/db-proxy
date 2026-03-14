/**
 * Sylphx Database Proxy
 *
 * Protocol-aware TCP proxy with SNI-based routing for managed databases.
 *
 * Architecture (Neon Proxy pattern):
 *   *.db.sylphx.net:5432 → Postgres: SSLRequest → SNI/TLS → CNPG Pooler
 *                          Postgres: StartupMessage{user@id12} → plaintext → CNPG Pooler
 *   *.db.sylphx.net:3306 → MySQL:    SSLRequest → SNI/TLS → Percona HAProxy
 *                          MySQL:    HandshakeResponse{user@id12} → AuthSwitch → Percona HAProxy
 *
 * Bridge pattern (Bun 1.3.x compatible):
 *   Public plain TCP server handles protocol greeting + SSL negotiation.
 *   Loopback bridge to internal tls.createServer for TLS termination + SNI.
 *   SNI id[:12] → database_resources → K8s internal host.
 */

import { getMetrics } from "./metrics.ts";
import { startMysqlProxy } from "./mysql.ts";
import { startPostgresProxy } from "./postgres.ts";
import { startRedisProxy } from "./redis.ts";
import { checkHealth, getCacheSize, resolveDatabase, resolveRedis } from "./router.ts";

const TLS_CERT_PATH = process.env.TLS_CERT_PATH ?? "/certs/tls.crt";
const TLS_KEY_PATH = process.env.TLS_KEY_PATH ?? "/certs/tls.key";
const PG_PORT = Number(process.env.PG_PORT) || 5432;
const MYSQL_PORT = Number(process.env.MYSQL_PORT) || 3306;
const REDIS_PORT = Number(process.env.REDIS_PORT) || 6379;
const SHUTDOWN_TIMEOUT_MS = 30_000;

// Start Postgres proxy (plain TCP :5432 → bridge → internal TLS :15432 → CNPG)
startPostgresProxy(PG_PORT, TLS_CERT_PATH, TLS_KEY_PATH, resolveDatabase);

// Start MySQL proxy (plain TCP :3306 → bridge → internal TLS :13306 → Percona)
startMysqlProxy(MYSQL_PORT, TLS_CERT_PATH, TLS_KEY_PATH, resolveDatabase);

// Start Redis proxy (direct TLS :6379 → SNI extraction → internal plaintext → Redis master)
startRedisProxy(REDIS_PORT, TLS_CERT_PATH, TLS_KEY_PATH, resolveRedis);

// ── Health + metrics endpoint (HTTP :8080) ──────────────────────────────────

let shuttingDown = false;

const httpServer = Bun.serve({
	port: 8080,
	fetch(req) {
		const url = new URL(req.url);

		// Liveness probe — always 200 unless shutting down
		if (url.pathname === "/healthz") {
			return new Response(shuttingDown ? "shutting down" : "ok", {
				status: shuttingDown ? 503 : 200,
			});
		}

		// Readiness probe — verifies Platform DB connection is alive
		if (url.pathname === "/readyz" || url.pathname === "/health") {
			if (shuttingDown) {
				return new Response("shutting down", { status: 503 });
			}
			return checkHealth().then((ok) =>
				ok ? new Response("ok", { status: 200 }) : new Response("platform db unreachable", { status: 503 }),
			);
		}

		if (url.pathname === "/metrics") {
			const metrics = getMetrics();
			return Response.json({
				...metrics,
				cache_size: getCacheSize(),
				shutting_down: shuttingDown,
			});
		}

		return new Response("not found", { status: 404 });
	},
});

console.log("[health] HTTP health + metrics endpoint on :8080");

console.log(`[startup] sylphx-db-proxy ready
  Postgres : *.db.sylphx.net:${PG_PORT}
  MySQL    : *.db.sylphx.net:${MYSQL_PORT}
  Redis    : *.db.sylphx.net:${REDIS_PORT}
  Health   : :8080/healthz (liveness), :8080/readyz (readiness)
  Metrics  : :8080/metrics
  Routing  : SNI id[:12] -> database_resources -> K8s internal host`);

// ── Graceful shutdown ───────────────────────────────────────────────────────
// On SIGTERM: stop accepting new connections (K8s readiness probe fails),
// wait for existing connections to drain, then exit.

function gracefulShutdown(signal: string) {
	if (shuttingDown) return;
	shuttingDown = true;
	console.log(`[shutdown] ${signal} received — draining connections`);

	// Stop HTTP server (K8s probe fails → stops sending new traffic)
	httpServer.stop();

	// Give existing connections time to finish, then force exit
	setTimeout(() => {
		console.log("[shutdown] drain timeout reached, exiting");
		process.exit(0);
	}, SHUTDOWN_TIMEOUT_MS);
}

process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT", () => gracefulShutdown("SIGINT"));

// Prevent process crash from unexpected errors (e.g. Bun.connect ECONNREFUSED
// throwing synchronously instead of calling the error handler).
process.on("uncaughtException", (err) => {
	console.error("[uncaughtException] non-fatal, continuing:", err.message ?? err);
});

process.on("unhandledRejection", (reason) => {
	console.error("[unhandledRejection] non-fatal, continuing:", reason);
});
