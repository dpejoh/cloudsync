# CloudSync standalone server

# Build Stage
FROM node:22-alpine AS builder

WORKDIR /build

COPY package.json package-lock.json* ./
RUN npm ci || npm install

COPY tsconfig.json ./
COPY src/ ./src/

RUN npm run build:vps

# Production Runner Stage
FROM node:22-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production \
    PORT=3000 \
    HOST=0.0.0.0 \
    DATA_DIR=/data \
    WORKER_MODE=multi

# Copy compiled standalone bundle from builder stage
COPY --from=builder /build/dist/server.mjs ./server.mjs

# Create persistent storage mount point
RUN mkdir -p /data

VOLUME ["/data"]

EXPOSE 3000

# Health check endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/ || exit 1

CMD ["node", "server.mjs"]
