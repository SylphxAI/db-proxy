/**
 * Database Router
 *
 * Resolves a 12-char hex ID (from SNI hostname) to a backend K8s service.
 * Backed by a TTL cache with a hard entry cap to prevent memory DoS.
 *
 * Cache semantics:
 *   - Hit (valid DB):   TTL 60s — reduces Platform DB load for active connections
 *   - Miss (not found): TTL 10s — limits DB hammering from bad/unknown IDs
 *   - Cap: 1 000 entries — evicts oldest on overflow
 */

import postgres from 'postgres'

export interface BackendTarget {
	host: string
	port: number
	provider: 'cnpg' | 'percona'
}

const DB_URL = process.env.DATABASE_URL
if (!DB_URL) throw new Error('DATABASE_URL is required')

const sql = postgres(DB_URL, {
	max: 5,
	idle_timeout: 30,
	connect_timeout: 10,
})

// ── Validated ID format ──────────────────────────────────────────────────────

/** A valid id12 is the first 12 hex chars of a UUID (without dashes). */
const ID12_RE = /^[0-9a-f]{12}$/

function isValidId12(id12: string): boolean {
	return ID12_RE.test(id12)
}

// ── TTL + capped cache ───────────────────────────────────────────────────────

type CacheEntry = { value: BackendTarget | null; expiresAt: number }

const cache = new Map<string, CacheEntry>()
const CACHE_HIT_TTL_MS = 60_000 // 60s for known databases
const CACHE_MISS_TTL_MS = 10_000 // 10s for unknown / not-found IDs
const CACHE_MAX_ENTRIES = 1_000

/**
 * Insert into cache. When the map is full, evict the oldest entry (FIFO).
 * Map iteration order is insertion order in V8/Bun, so the first key is oldest.
 */
function cacheSet(id12: string, entry: CacheEntry): void {
	if (cache.size >= CACHE_MAX_ENTRIES && !cache.has(id12)) {
		// Evict oldest entry
		const oldestKey = cache.keys().next().value
		if (oldestKey !== undefined) cache.delete(oldestKey)
	}
	cache.set(id12, entry)
}

// ── Resolver ─────────────────────────────────────────────────────────────────

export async function resolveDatabase(id12: string): Promise<BackendTarget | null> {
	// Validate before hitting the DB — rejects malformed / injection attempts
	if (!isValidId12(id12)) {
		console.warn(`[router] invalid id12 format: "${id12}"`)
		return null
	}

	const now = Date.now()
	const cached = cache.get(id12)
	if (cached && cached.expiresAt > now) return cached.value

	// Convert 12-char hex prefix back to UUID prefix for a proper index scan.
	// UUID format: xxxxxxxx-xxxx-... → first 12 hex chars span groups 1+2+half of 3.
	// We match on the text representation: xxxxxxxx-xxxx (12 hex chars = 8+4).
	const uuidPrefix = `${id12.slice(0, 8)}-${id12.slice(8, 12)}`

	const rows = await sql<{ provider: string; cluster_name: string; host: string | null; port: number | null }[]>`
		SELECT provider, cluster_name, host, port
		FROM database_resources
		WHERE id::text LIKE ${`${uuidPrefix}%`}
		LIMIT 1
	`

	if (rows.length === 0) {
		cacheSet(id12, { value: null, expiresAt: now + CACHE_MISS_TTL_MS })
		return null
	}

	const { provider, cluster_name, host, port } = rows[0]

	// Use stored host/port when available (authoritative).
	// Fallback to convention-based construction for backward compat.
	let targetHost: string
	let targetPort: number

	if (host) {
		targetHost = host
		targetPort = port ?? (provider === 'percona' ? 3306 : 5432)
	} else {
		targetHost =
			provider === 'percona'
				? `percona-haproxy.${cluster_name}.svc.cluster.local`
				: `${cluster_name}-pooler.${cluster_name}.svc.cluster.local`
		targetPort = provider === 'percona' ? 3306 : 5432
	}

	const target: BackendTarget = {
		host: targetHost,
		port: targetPort,
		provider: provider as 'cnpg' | 'percona',
	}

	cacheSet(id12, { value: target, expiresAt: now + CACHE_HIT_TTL_MS })
	console.log(`[router] ${id12} → ${target.host}:${target.port}`)
	return target
}
