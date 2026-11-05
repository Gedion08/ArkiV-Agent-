# Service images (L11 §2): one Dockerfile, one app per build. From the repo root:
#   docker build -f infra/docker/service.Dockerfile --build-arg APP=anchor -t afr/anchor:<git-sha> .
#   docker build -f infra/docker/service.Dockerfile --build-arg APP=api    -t afr/api:<git-sha> .
# The runtime image holds only @afr/$APP's production closure and runs dist/main.js as uid 1000.
# The api image also carries the dashboard's static build in /app/dashboard (ADR-026; AFR_DASHBOARD_DIR).
# VITE_WALLETCONNECT_PROJECT_ID (public Reown id) enables WalletConnect in that build.
ARG NODE=node:22.23.3-bookworm-slim

FROM ${NODE} AS build
ARG APP
ARG VITE_WALLETCONNECT_PROJECT_ID=
RUN test -n "$APP" || (echo "--build-arg APP=anchor|api is required" && exit 1)
WORKDIR /src
RUN corepack enable
COPY . .
# only the app's closure (+ the root for tsc): the recorder's native better-sqlite3 isn't needed here
RUN DASH=$([ "$APP" = api ] && echo "--filter @afr/dashboard...") \
 && pnpm install --frozen-lockfile --filter "@afr/${APP}..." $DASH --filter . \
 && pnpm --filter "@afr/${APP}..." run build \
 && if [ -n "$DASH" ]; then \
      VITE_WALLETCONNECT_PROJECT_ID="$VITE_WALLETCONNECT_PROJECT_ID" pnpm $DASH run build; \
    fi \
 && pnpm --filter "@afr/${APP}" deploy --prod --legacy /out \
 && if [ -n "$DASH" ]; then cp -r apps/dashboard/dist /out/dashboard; fi
# dashboard: built after the api (tsc and vite in parallel can exhaust Docker's memory) but before deploy,
# since a `pnpm run` after deploy re-installs the whole workspace, recorder's native build included

FROM ${NODE}
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build --chown=1000:1000 /out .
# Amazon RDS CAs (truststore.pki.rds.amazonaws.com/global/global-bundle.pem): Postgres URLs use
# sslmode=verify-full, and Node's bundled roots don't include them
COPY infra/docker/rds-global-bundle.pem /etc/ssl/rds-global-bundle.pem
ENV NODE_EXTRA_CA_CERTS=/etc/ssl/rds-global-bundle.pem
USER 1000
CMD ["node", "dist/main.js"]
