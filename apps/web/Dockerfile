FROM node:25.9-alpine AS deps
WORKDIR /app
COPY apps/web/package.json apps/web/package-lock.json* ./
RUN npm install --legacy-peer-deps

FROM node:25.9-alpine AS builder
WORKDIR /app

# Proxy target for server-side Next.js → API container. Baked at build time
# because Next.js 15 evaluates next.config.js rewrites at build, not runtime.
ARG API_INTERNAL_URL=http://api:8000
ENV API_INTERNAL_URL=${API_INTERNAL_URL}

# NEXT_PUBLIC_* values are inlined into the client bundle during `next build`.
# Pass them as build args from docker-compose so the runtime container has
# them baked in. Rebuilds are required when these change.
ARG NEXT_PUBLIC_API_URL
ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL}
ARG NEXT_PUBLIC_API_DIRECT_URL
ENV NEXT_PUBLIC_API_DIRECT_URL=${NEXT_PUBLIC_API_DIRECT_URL}
ARG NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY
ENV NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=${NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY}
ARG NEXT_PUBLIC_CLERK_SIGN_IN_URL
ENV NEXT_PUBLIC_CLERK_SIGN_IN_URL=${NEXT_PUBLIC_CLERK_SIGN_IN_URL}
ARG NEXT_PUBLIC_CLERK_SIGN_UP_URL
ENV NEXT_PUBLIC_CLERK_SIGN_UP_URL=${NEXT_PUBLIC_CLERK_SIGN_UP_URL}
ARG NEXT_PUBLIC_CLERK_SIGN_IN_FALLBACK_REDIRECT_URL
ENV NEXT_PUBLIC_CLERK_SIGN_IN_FALLBACK_REDIRECT_URL=${NEXT_PUBLIC_CLERK_SIGN_IN_FALLBACK_REDIRECT_URL}
ARG NEXT_PUBLIC_CLERK_SIGN_UP_FALLBACK_REDIRECT_URL
ENV NEXT_PUBLIC_CLERK_SIGN_UP_FALLBACK_REDIRECT_URL=${NEXT_PUBLIC_CLERK_SIGN_UP_FALLBACK_REDIRECT_URL}

# Subdomain wiring — read by apps/web/middleware.ts during `next build`
# and inlined into the middleware bundle. Without these ARGs declared the
# subdomain router falls back to the code defaults (or worse, stale build
# cache), which is why /dashboard on pencheff.com used to redirect to
# localhost.
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
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV API_INTERNAL_URL=http://api:8000
COPY --from=builder /app/public ./public
COPY --from=builder /app/.next ./.next
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json
EXPOSE 3000
CMD ["npm", "run", "start"]
