// L8 §5 notifier, v0: a polled `deliveries` table instead of a pg-boss queue (like checkpoint.validated).
// Rows come from afr_route_alert (alert opened / reopened / resolved) and POST /v1/channels/{id}/test. Each
// API instance claims due rows with SKIP LOCKED and a 5 min lease, sends, and reschedules failures: 10
// attempts over ≈ 24 h. Adapters: email (the Mailer) and signed webhooks (§4.10). Payloads go through the
// strict Alert schema (W10); failures are logged and stored by code only.
import { createHmac } from "node:crypto";
import { lookup } from "node:dns/promises";
import { BlockList, isIP } from "node:net";
import { jcsData } from "@afr/core";
import type { Logger } from "@afr/log";
import type { Pool } from "pg";
import type { Mailer } from "./mail.js";
import {
  ALERT_SELECT,
  Alert,
  type AlertRow,
  alertJson,
  type ChannelConfig,
  channelAad,
  webhookUrlOk,
} from "./routes/alerts.js";
import type { OrgSecrets } from "./secrets.js";

/** Delays after attempts 1…9; the 10th failure is final. Sums to ≈ 24 h. */
export const RETRY_DELAYS_S = [60, 300, 900, 1800, 3600, 7200, 14_400, 21_600, 36_000];
const LEASE_S = 300;
const TIMEOUT_MS = 10_000;

export interface NotifierOptions {
  pool: Pool;
  secrets: OrgSecrets;
  mailer?: Mailer;
  /** Base for alert links in emails. */
  dashboardOrigin?: string;
  /** Local dev and tests: webhooks to http:// and private addresses. */
  allowPrivateWebhooks?: boolean;
  logger?: Logger;
  fetch?: typeof fetch;
}

/** §4.10: `t=<unix>,v1=<hex HMAC-SHA256(secret, t + "." + body)>`. */
export const signWebhook = (secret: string, t: number, body: string) =>
  `t=${t},v1=${createHmac("sha256", secret).update(`${t}.${body}`).digest("hex")}`;

// loopback, private, link-local (cloud metadata), CGNAT, benchmarking, multicast and reserved
const BLOCKED = new BlockList();
for (const [a, p] of [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["224.0.0.0", 3],
] as const)
  BLOCKED.addSubnet(a, p, "ipv4");
for (const [a, p] of [
  ["::", 127],
  ["fc00::", 7],
  ["fe80::", 10],
  ["ff00::", 8],
] as const)
  BLOCKED.addSubnet(a, p, "ipv6");

export function blockedAddress(ip: string): boolean {
  const v4 = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip)?.[1];
  if (v4) return BLOCKED.check(v4, "ipv4");
  return isIP(ip) === 6 ? BLOCKED.check(ip, "ipv6") : BLOCKED.check(ip, "ipv4");
}

class SendError extends Error {
  constructor(
    readonly code: string,
    /** Retrying can't help (bad config). */
    readonly final = false,
  ) {
    super(code);
  }
}

interface Due {
  id: string;
  org_id: string;
  alert_id: string | null;
  event: string;
  delivery_id: string;
  attempts: number;
  channel_id: string;
  kind: string;
  name: string;
  config_kms: Buffer;
  enabled: boolean;
}

/** Claims and sends up to `limit` due deliveries; returns how many were attempted. */
export async function drainDeliveries(o: NotifierOptions, limit = 20): Promise<number> {
  const { rows } = await o.pool.query<Due>(
    `WITH due AS (
       UPDATE deliveries SET attempts = attempts + 1, next_at = now() + make_interval(secs => $2)
        WHERE id IN (SELECT id FROM deliveries WHERE status = 'pending' AND next_at <= now()
                      ORDER BY next_at LIMIT $1 FOR UPDATE SKIP LOCKED)
        RETURNING *)
     SELECT due.id, due.org_id, due.alert_id, due.event, due.delivery_id, due.attempts, c.id AS channel_id,
            c.kind, c.name, c.config_kms, c.enabled
       FROM due JOIN notification_channels c ON c.id = due.channel_id`,
    [limit, LEASE_S],
  );
  for (const d of rows) {
    try {
      await send(o, d);
      await o.pool.query("UPDATE deliveries SET status = 'sent', last_error = NULL WHERE id = $1", [
        d.id,
      ]);
    } catch (e) {
      const code = e instanceof SendError ? e.code : "SEND_FAILED";
      const final = (e instanceof SendError && e.final) || d.attempts > RETRY_DELAYS_S.length;
      await o.pool.query(
        `UPDATE deliveries SET last_error = $2, status = CASE WHEN $3 THEN 'failed' ELSE status END,
           next_at = now() + make_interval(secs => $4) WHERE id = $1`,
        [d.id, code, final, RETRY_DELAYS_S[d.attempts - 1] ?? 0],
      );
      o.logger?.warn({ event: "delivery_failed", code, attempts: d.attempts, final });
    }
  }
  return rows.length;
}

async function send(o: NotifierOptions, d: Due): Promise<void> {
  if (!d.enabled) throw new SendError("CHANNEL_DISABLED", true);
  if (d.kind !== "webhook" && d.kind !== "email") throw new SendError("KIND_UNSUPPORTED", true);
  const config = JSON.parse(
    new TextDecoder().decode(
      await o.secrets.open(d.org_id, d.config_kms, channelAad(d.channel_id)),
    ),
  ) as ChannelConfig;
  let alert: ReturnType<typeof alertJson> | undefined;
  let agent: { id: string; agent_id: string; name: string } | undefined;
  if (d.alert_id) {
    const row = (await o.pool.query<AlertRow>(`${ALERT_SELECT} WHERE al.id = $1`, [d.alert_id]))
      .rows[0];
    if (!row) throw new SendError("ALERT_GONE", true);
    // W10: nothing outside the strict shape leaves the API
    const parsed = Alert.safeParse(alertJson(row));
    if (!parsed.success) throw new SendError("PAYLOAD_SHAPE", true);
    alert = parsed.data;
    if (row.agent_id)
      agent = (
        await o.pool.query<{ id: string; agent_id: string; name: string }>(
          "SELECT id, agent_id, name FROM agents WHERE id = $1",
          [row.agent_id],
        )
      ).rows[0];
  }

  if (config.kind === "email") {
    if (!o.mailer) throw new SendError("NO_MAILER", true);
    // shortcut: every alert is mailed on its own; the digest for non-critical ones (§5.1) comes later
    await o.mailer.send({ to: config.to, ...emailFor(o, d, alert, agent) });
    return;
  }
  const body = jcsData(
    alert
      ? { type: d.event, alert, ...(agent ? { agent } : {}) }
      : { type: d.event, channel: { id: d.channel_id, name: d.name } },
  );
  await postWebhook(o, config, d, body);
}

function emailFor(
  o: NotifierOptions,
  d: Due,
  alert: ReturnType<typeof alertJson> | undefined,
  agent: { agent_id: string; name: string } | undefined,
) {
  if (!alert)
    return {
      subject: "[AFR] Test notification",
      text: `This is a test of the AFR notification channel "${d.name}".\n`,
    };
  const resolved = d.event === "alert.resolved";
  const lines = [
    `${alert.type} (${alert.severity}) is ${resolved ? `resolved (${alert.resolution})` : alert.status}.`,
    ...(agent ? [`Agent: ${agent.name} (${agent.agent_id})`] : []),
    ...(alert.lane !== null ? [`Lane: ${alert.lane}`] : []),
    ...Object.entries(alert.subject).map(([k, v]) => `${k}: ${v}`),
    ...(alert.evidence.explorer_url ? [`Explorer: ${alert.evidence.explorer_url}`] : []),
    `Seen ${alert.count} time(s), last at ${alert.last_seen_at}.`,
    ...(o.dashboardOrigin ? [`${o.dashboardOrigin}/alerts/${alert.id}`] : []),
  ];
  return {
    subject: `[AFR] ${alert.severity.toUpperCase()} ${alert.type}${resolved ? " resolved" : ""}`,
    text: `${lines.join("\n")}\n`,
  };
}

async function postWebhook(
  o: NotifierOptions,
  c: Extract<ChannelConfig, { kind: "webhook" }>,
  d: Due,
  body: string,
) {
  if (!webhookUrlOk(c.url, o.allowPrivateWebhooks))
    throw new SendError("WEBHOOK_URL_INVALID", true);
  if (!o.allowPrivateWebhooks) {
    // SSRF: no loopback, VPC or metadata targets.
    // shortcut: fetch resolves the name again (a DNS rebinding window); pin the checked address once an
    // HTTP agent with a custom lookup is a dependency.
    const host = new URL(c.url).hostname.replace(/^\[|\]$/g, "");
    const addrs = await lookup(host, { all: true, verbatim: true }).catch(() => {
      throw new SendError("DNS_FAILED");
    });
    if (!addrs.length || addrs.some((a) => blockedAddress(a.address)))
      throw new SendError("BLOCKED_ADDRESS", true);
  }
  const t = Math.floor(Date.now() / 1000);
  let res: Response;
  try {
    res = await (o.fetch ?? fetch)(c.url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "user-agent": "afr-webhooks/1",
        "x-afr-event": d.event,
        "x-afr-delivery": d.delivery_id,
        "x-afr-signature": signWebhook(c.secret, t, body),
      },
      body,
      redirect: "manual", // a redirect could point anywhere, past the address check
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch (e) {
    throw new SendError((e as Error).name === "TimeoutError" ? "TIMEOUT" : "CONNECT_FAILED");
  }
  await res.body?.cancel().catch(() => {});
  if (res.status < 200 || res.status >= 300) throw new SendError(`HTTP_${res.status}`);
}

/** Drains due deliveries every `everyMs` until stopped. */
export function startNotifier(o: NotifierOptions, everyMs = 5_000): { stop: () => Promise<void> } {
  let stopped = false;
  let timer: NodeJS.Timeout | undefined;
  let running: Promise<unknown> = Promise.resolve();
  const tick = () => {
    running = (async () => {
      try {
        while (!stopped && (await drainDeliveries(o)) > 0);
      } catch (e) {
        o.logger?.error({
          event: "notifier_failed",
          code: (e as { code?: string }).code ?? "ERROR",
        });
      }
      if (!stopped) timer = setTimeout(tick, everyMs);
    })();
  };
  tick();
  return {
    stop: async () => {
      stopped = true;
      clearTimeout(timer);
      await running;
    },
  };
}
