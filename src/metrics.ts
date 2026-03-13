/**
 * Lightweight connection metrics for observability.
 *
 * Tracks active/total connections per protocol mode, cache performance,
 * and resolver latency. Exposed via /metrics on the health HTTP server.
 */

const connections = {
	mysql_tls: 0,
	mysql_plain: 0,
	pg_tls: 0,
	pg_plain: 0,
}

const totals = {
	mysql_tls: 0,
	mysql_plain: 0,
	pg_tls: 0,
	pg_plain: 0,
}

const cache = {
	hits: 0,
	misses: 0,
}

const resolver = {
	calls: 0,
	errors: 0,
	totalMs: 0,
}

const timeouts = {
	handshake: 0,
}

export type ConnType = keyof typeof connections

export function trackConnect(type: ConnType): void {
	connections[type]++
	totals[type]++
}

export function trackDisconnect(type: ConnType): void {
	connections[type] = Math.max(0, connections[type] - 1)
}

export function trackCacheHit(): void {
	cache.hits++
}

export function trackCacheMiss(): void {
	cache.misses++
}

export function trackResolverCall(durationMs: number, error = false): void {
	resolver.calls++
	resolver.totalMs += durationMs
	if (error) resolver.errors++
}

export function trackHandshakeTimeout(): void {
	timeouts.handshake++
}

export function getMetrics(): object {
	const totalActive = connections.mysql_tls + connections.mysql_plain + connections.pg_tls + connections.pg_plain
	return {
		active_connections: { ...connections, total: totalActive },
		total_connections: { ...totals },
		cache: {
			...cache,
			hit_rate: cache.hits + cache.misses > 0 ? Math.round((cache.hits / (cache.hits + cache.misses)) * 10000) / 100 : 0,
		},
		resolver: {
			calls: resolver.calls,
			errors: resolver.errors,
			avg_ms: resolver.calls > 0 ? Math.round((resolver.totalMs / resolver.calls) * 100) / 100 : 0,
		},
		timeouts: { ...timeouts },
		uptime_s: Math.floor(process.uptime()),
	}
}
