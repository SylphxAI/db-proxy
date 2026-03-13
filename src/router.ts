/**
 * Database Router
 *
 * Resolves a 12-char hex ID (from SNI hostname or user@id12) to a backend
 * K8s service address. Backed by an LRU cache with hard entry cap.
 *
 * Cache semantics:
 *   - Hit (valid DB):   TTL 60s — reduces Platform DB load for active connections
 *   - Miss (not found): TTL 10s — limits DB hammering from bad/unknown IDs
 *   - Cap: 1 000 entries — evicts least-recently-used on overflow
 *
 * Pool sizing:
 *   max: 20 — this proxy is the gateway for ALL managed databases. Under burst
 *   load (cold start, cache expiry storm), many connections resolve concurrently.
 *   5 was too low — caused queueing under moderate load.
 *
 * Resolver timeout:
 *   5s — if Platform DB is unresponsive, fail fast rather than blocking the
 *   proxy's connection handling indefinitely.
 */

import postgres from 'postgres'
import { trackCacheHit, trackCacheMiss, trackResolverCall } from './metrics.ts'

export interface BackendTarget {
	host: string
	port: number
	provider: 'cnpg' | 'percona'
}

const DB_URL = process.env.DATABASE_URL
if (!DB_URL) throw new Error('DATABASE_URL is required')

const sql = postgres(DB_URL, {
	max: 20,
	idle_timeout: 30,
	connect_timeout: 10,
})

// ── Validated ID format ──────────────────────────────────────────────────────

/** A valid id12 is the first 12 hex chars of a UUID (without dashes). */
const ID12_RE = /^[0-9a-f]{12}$/

function isValidId12(id12: string): boolean {
	return ID12_RE.test(id12)
}

// ── LRU + TTL cache ─────────────────────────────────────────────────────────

type CacheEntry = { value: BackendTarget | null; expiresAt: number }

const cache = new Map<string, CacheEntry>()
const CACHE_HIT_TTL_MS = 60_000
const CACHE_MISS_TTL_MS = 10_000
const CACHE_MAX_ENTRIES = 1_000

/**
 * LRU cache get. On access, deletes and re-inserts the entry so it moves
 * to the end of Map iteration order (most-recently-used position).
 * Returns undefined if not found or expired.
 */
function cacheGet(id12: string): CacheEntry | undefined {
	const entry = cache.get(id12)
	if (!entry) return undefined
	if (entry.expiresAt <= Date.now()) {
		cache.delete(id12)
		return undefined
	}
	// Move to end (most-recently-used)
	cache.delete(id12)
	cache.set(id12, entry)
	return entry
}

/**
 * LRU cache set. When full, evicts the least-recently-used entry (first key
 * in Map iteration order — oldest access).
 */
function cacheSet(id12: string, entry: CacheEntry): void {
	// Delete first so re-insert goes to end
	cache.delete(id12)
	if (cache.size >= CACHE_MAX_ENTRIES) {
		const lruKey = cache.keys().next().value
		if (lruKey !== undefined) cache.delete(lruKey)
	}
	cache.set(id12, entry)
}

/** Expose cache size for metrics endpoint */
export function getCacheSize(): number {
	return cache.size
}

/** Deep health check — verifies the Platform DB connection is alive */
export async function checkHealth(): Promise<boolean> {
	try {
		await withTimeout(sql`SELECT 1`, 3_000, 'health-check')
		return true
	} catch {
		return false
	}
}

// ── Resolver timeout ────────────────────────────────────────────────────────

const RESOLVE_TIMEOUT_MS = 5_000

function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
	return new Promise((resolve, reject) => {
		const timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms)
		promise.then(
			(v) => {
				clearTimeout(timer)
				resolve(v)
			},
			(e) => {
				clearTimeout(timer)
				reject(e)
			},
		)
	})
}

// ── Resolver ─────────────────────────────────────────────────────────────────

export async function resolveDatabase(id12: string): Promise<BackendTarget | null> {
	if (!isValidId12(id12)) {
		console.warn(`[router] invalid id12 format: "${id12}"`)
		return null
	}

	const cached = cacheGet(id12)
	if (cached) {
		trackCacheHit()
		return cached.value
	}
	trackCacheMiss()

	// Convert 12-char hex prefix to UUID range bounds for a proper PK index scan.
	// Old approach: `WHERE id::text LIKE '...'` — casts UUID to text, can't use the
	// UUID btree index → sequential scan. New approach: construct exact UUID bounds
	// so Postgres uses the PK index directly (O(log n) vs O(n)).
	//
	// id12 = "25e3b05c46dc" → lower: 25e3b05c-46dc-0000-0000-000000000000
	//                        → upper: 25e3b05c-46dd-0000-0000-000000000000
	const lower = `${id12.slice(0, 8)}-${id12.slice(8, 12)}-0000-0000-000000000000`
	const num = BigInt(`0x${id12}`) + 1n
	const nextHex = num.toString(16).padStart(12, '0')
	const upper = `${nextHex.slice(0, 8)}-${nextHex.slice(8, 12)}-0000-0000-000000000000`

	const t0 = performance.now()
	let rows: { provider: string; cluster_name: string; host: string | null; port: number | null }[]
	try {
		rows = await withTimeout(
			sql<{ provider: string; cluster_name: string; host: string | null; port: number | null }[]>`
				SELECT provider, cluster_name, host, port
				FROM database_resources
				WHERE id >= ${lower}::uuid AND id < ${upper}::uuid
				LIMIT 1
			`,
			RESOLVE_TIMEOUT_MS,
			`resolve(${id12})`,
		)
		trackResolverCall(performance.now() - t0)
	} catch (err) {
		trackResolverCall(performance.now() - t0, true)
		throw err
	}

	if (rows.length === 0) {
		cacheSet(id12, { value: null, expiresAt: Date.now() + CACHE_MISS_TTL_MS })
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

	cacheSet(id12, { value: target, expiresAt: Date.now() + CACHE_HIT_TTL_MS })
	console.log(`[router] ${id12} → ${target.host}:${target.port}`)
	return target
}
