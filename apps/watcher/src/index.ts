// Chain watcher + log auditor (L6). P4-01/02: head follower, watched set, observed txs; P4-03/04: batch
// reconciliation and the matcher; P4-05/06: log auditor and alert engine.
export const PACKAGE_NAME = "@afr/watcher";
export * from "./alerts.js";
export * from "./auditor.js";
export * from "./db.js";
export * from "./follower.js";
export * from "./matcher.js";
export * from "./reconcile.js";
export * from "./service.js";
