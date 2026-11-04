# Anchor service image (L5 §3, P3-12). Build from the repo root:
#   docker build -f infra/docker/anchor.Dockerfile -t afr/anchor:<git-sha> .
# The runtime image holds only @afr/anchor's production closure; it signs with KMS (AFR_ANCHOR_KMS_KEY_ID).
FROM node:22.23.3-bookworm-slim AS build
WORKDIR /src
RUN corepack enable
COPY . .
# only anchor's closure (+ the root for tsc): the recorder's native better-sqlite3 isn't needed here
RUN pnpm install --frozen-lockfile --filter "@afr/anchor..." --filter . \
 && pnpm --filter "@afr/anchor..." run build \
 && pnpm --filter @afr/anchor deploy --prod --legacy /out

FROM node:22.23.3-bookworm-slim
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build --chown=1000:1000 /out .
USER 1000
CMD ["node", "dist/main.js"]
