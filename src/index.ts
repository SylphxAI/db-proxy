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

import { startMysqlProxy } from './mysql.ts'
import { startPostgresProxy } from './postgres.ts'
import { resolveDatabase } from './router.ts'
import { getMetrics } from './metrics.ts'

const TLS_CERT_PATH = process.env.TLS_CERT_PATH ?? '/certs/tls.crt'
const TLS_KEY_PATH = process.env.TLS_KEY_PATH ?? '/certs/tls.key'
const PG_PORT = Number(process.env.PG_PORT) || 5432
const MYSQL_PORT = Number(process.env.MYSQL_PORT) || 3306

// Start Postgres proxy (plain TCP :5432 → bridge → internal TLS :15432 → CNPG)
startPostgresProxy(PG_PORT, TLS_CERT_PATH, TLS_KEY_PATH, resolveDatabase)

// Start MySQL proxy (plain TCP :3306 → bridge → internal TLS :13306 → Percona)
startMysqlProxy(MYSQL_PORT, TLS_CERT_PATH, TLS_KEY_PATH, resolveDatabase)

// Health + metrics endpoint (HTTP :8080)
Bun.serve({
	port: 8080,
	fetch(req) {
		const url = new URL(req.url)
		if (url.pathname === '/health') {
			return new Response('ok', { status: 200 })
		}
		if (url.pathname === '/metrics') {
			return Response.json(getMetrics())
		}
		return new Response('not found', { status: 404 })
	},
})

console.log('[health] HTTP health + metrics endpoint on :8080')

console.log(`[startup] sylphx-db-proxy ready
  Postgres : *.db.sylphx.net:${PG_PORT}
  MySQL    : *.db.sylphx.net:${MYSQL_PORT}
  Metrics  : :8080/metrics
  Routing  : SNI id[:12] -> database_resources -> K8s internal host`)

// Graceful shutdown
process.on('SIGTERM', () => {
	console.log('[shutdown] SIGTERM received')
	process.exit(0)
})

// Prevent process crash from unexpected errors (e.g. Bun.connect ECONNREFUSED
// throwing synchronously instead of calling the error handler).
process.on('uncaughtException', (err) => {
	console.error('[uncaughtException] non-fatal, continuing:', err.message ?? err)
})

process.on('unhandledRejection', (reason) => {
	console.error('[unhandledRejection] non-fatal, continuing:', reason)
})
