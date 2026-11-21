# Standalone output (next.config.js) traces only the files actually
# needed at runtime, so the final image doesn't carry the full
# node_modules tree -- the standalone build itself WAS verified (built
# locally, .next/standalone/server.js confirmed present). The Docker
# image build itself could not be run end-to-end in the sandbox this was
# written in (its network policy blocks Docker Hub pulls) -- see
# DEPLOY.md for the honest scope of what was and wasn't tested here.
FROM node:20-slim AS builder

WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci

COPY . .

# Build-time public env vars: Next.js inlines NEXT_PUBLIC_* values into the
# client bundle at build time, not read at container start -- so these
# have to be real values at `docker build`, passed as build args, not
# left for docker-compose's runtime `environment:` to fill in later.
ARG NEXT_PUBLIC_SUPABASE_URL
ARG NEXT_PUBLIC_SUPABASE_ANON_KEY
ARG NEXT_PUBLIC_API_URL
ENV NEXT_PUBLIC_SUPABASE_URL=$NEXT_PUBLIC_SUPABASE_URL
ENV NEXT_PUBLIC_SUPABASE_ANON_KEY=$NEXT_PUBLIC_SUPABASE_ANON_KEY
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL

RUN npm run build

FROM node:20-slim

RUN groupadd -r app && useradd -r -g app app
WORKDIR /app

COPY --from=builder /build/.next/standalone ./
COPY --from=builder /build/.next/static ./.next/static
COPY --from=builder /build/public ./public

RUN chown -R app:app /app
USER app

ENV PORT=3000
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD node -e "require('http').get('http://127.0.0.1:3000/', r => process.exit(r.statusCode < 500 ? 0 : 1)).on('error', () => process.exit(1))"

CMD ["node", "server.js"]
