FROM oven/bun:1.2-alpine AS builder

WORKDIR /app
COPY package.json bun.lock* ./
RUN bun install --frozen-lockfile --production

FROM oven/bun:1.2-alpine

RUN addgroup -g 101 -S proxy && adduser -u 100 -S -G proxy proxy

WORKDIR /app
COPY --from=builder /app/node_modules ./node_modules
COPY package.json ./
COPY src ./src

USER proxy:proxy

EXPOSE 5432 3306 8080

CMD ["bun", "src/index.ts"]
