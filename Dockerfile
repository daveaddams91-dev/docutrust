# Multi-stage Dockerfile for DocuTrust
FROM node:20-alpine AS base
WORKDIR /app

# Copy root package.json
COPY package.json ./
COPY packages/core/package.json ./packages/core/
COPY packages/cli/package.json ./packages/cli/
COPY apps/api/package.json ./apps/api/
COPY apps/web/package.json ./apps/web/

# Copy source files
COPY packages/ ./packages/
COPY apps/ ./apps/

EXPOSE 4000 3000

# Start API by default
CMD ["node", "apps/api/src/server.js"]
