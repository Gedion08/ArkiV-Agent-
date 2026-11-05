// Chain watcher + log auditor (L6). P4-01/02: head follower, watched set, observed txs; P4-03/04: batch
// reconciliation and the matcher.
export const PACKAGE_NAME = "@afr/watcher";
export * from "./db.js";
export * from "./follower.js";
export * from "./matcher.js";
export * from "./reconcile.js";
