FROM node:25.9-alpine AS deps
WORKDIR /app
COPY apps/web/package.json apps/web/package-lock.json* ./
RUN npm install --legacy-peer-deps

FROM node:25.9-alpine AS builder
WORKDIR /app

# NEXT_PUBLIC_* values are inlined into the client bundle during `next build`.
# Pass them as build args from docker-compose so the runtime container has
# them baked in. Rebuilds are required when these change.
ARG NEXT_PUBLIC_API_URL
ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL}
ARG NEXT_PUBLIC_API_DIRECT_URL
ENV NEXT_PUBLIC_API_DIRECT_URL=${NEXT_PUBLIC_API_DIRECT_URL}

# Subdomain wiring — read by apps/web/middleware.ts during `next build`
# and inlined into the middleware bundle.
ARG NEXT_PUBLIC_LANDING_URL
ENV NEXT_PUBLIC_LANDING_URL=${NEXT_PUBLIC_LANDING_URL}
ARG NEXT_PUBLIC_APP_URL
ENV NEXT_PUBLIC_APP_URL=${NEXT_PUBLIC_APP_URL}
ARG NEXT_PUBLIC_DOCS_URL
ENV NEXT_PUBLIC_DOCS_URL=${NEXT_PUBLIC_DOCS_URL}
ARG NEXT_PUBLIC_APP_HOST_LOCAL
ENV NEXT_PUBLIC_APP_HOST_LOCAL=${NEXT_PUBLIC_APP_HOST_LOCAL}
ARG NEXT_PUBLIC_DOCS_HOST_LOCAL
ENV NEXT_PUBLIC_DOCS_HOST_LOCAL=${NEXT_PUBLIC_DOCS_HOST_LOCAL}

COPY --from=deps /app/node_modules ./node_modules
COPY apps/web ./
# public/ may be absent from the repo (git doesn't track empty dirs) — the
# runner stage copies it unconditionally, so guarantee it exists here.
RUN mkdir -p public
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

FROM node:25.9-alpine AS runner
WORKDIR /app
RUN npm install -g serve
COPY --from=builder /app/out ./out
EXPOSE 3000
CMD ["serve", "-l", "3000", "out"]
