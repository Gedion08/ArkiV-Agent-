# Service images (L11 §2): one Dockerfile, one app per build. From the repo root:
#   docker build -f infra/docker/service.Dockerfile --build-arg APP=anchor -t afr/anchor:<git-sha> .
#   docker build -f infra/docker/service.Dockerfile --build-arg APP=api    -t afr/api:<git-sha> .
# The runtime image holds only @afr/$APP's production closure and runs dist/main.js as uid 1000.
ARG NODE=node:22.23.3-bookworm-slim

FROM ${NODE} AS build
ARG APP
RUN test -n "$APP" || (echo "--build-arg APP=anchor|api is required" && exit 1)
WORKDIR /src
RUN corepack enable
COPY . .
# only the app's closure (+ the root for tsc): the recorder's native better-sqlite3 isn't needed here
RUN pnpm install --frozen-lockfile --filter "@afr/${APP}..." --filter . \
 && pnpm --filter "@afr/${APP}..." run build \
 && pnpm --filter "@afr/${APP}" deploy --prod --legacy /out

FROM ${NODE}
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build --chown=1000:1000 /out .
USER 1000
CMD ["node", "dist/main.js"]
