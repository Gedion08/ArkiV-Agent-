// Control-plane API + notifier worker
export const PACKAGE_NAME = "@afr/api";

export * from "./auth/recorder.js";
export * from "./db/migrations.js";
export * from "./db/tenancy.js";
export * from "./http.js";
export * from "./mail.js";
export * from "./notifier.js";
export * from "./openapi.js";
export { Alert, alertJson, type ChannelConfig, webhookUrlOk } from "./routes/alerts.js";
export * from "./secrets.js";
export * from "./server.js";
