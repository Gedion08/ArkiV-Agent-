// Reads an agent URI (tokenURI). The content is untrusted: size-capped, parsed as JSON, never executed.
import { AfrError } from "@afr/core";

export interface FetchUriOptions {
  /** Injected for tests; defaults to global fetch. */
  fetch?: typeof globalThis.fetch;
  /** e.g. "https://ipfs.io": `ipfs://<cid>` reads `<gateway>/ipfs/<cid>`. Without it ipfs:// is unsupported. */
  ipfsGateway?: string;
  maxBytes?: number;
  timeoutMs?: number;
}

const DATA_RE = /^data:application\/json(;charset=utf-8)?(;base64)?,/i;

/** data: (inline), https: and ipfs: (through a gateway). Plain http is refused. */
export async function fetchUriJson(uri: string, o: FetchUriOptions = {}): Promise<unknown> {
  const maxBytes = o.maxBytes ?? 64 * 1024;
  let text: string;
  const m = DATA_RE.exec(uri);
  if (m) {
    const body = uri.slice(m[0].length);
    if (body.length > maxBytes * 2)
      throw new AfrError("URI_TOO_LARGE", "agent URI exceeds the size cap");
    try {
      text = m[2]
        ? new TextDecoder("utf-8", { fatal: true }).decode(
            Uint8Array.from(atob(body), (c) => c.charCodeAt(0)),
          )
        : decodeURIComponent(body);
    } catch {
      throw new AfrError("REGISTRATION_INVALID", "agent URI data is not valid base64/UTF-8");
    }
  } else {
    let url: string;
    if (uri.startsWith("https://")) url = uri;
    else if (uri.startsWith("ipfs://") && o.ipfsGateway)
      url = `${o.ipfsGateway.replace(/\/$/, "")}/ipfs/${uri.slice("ipfs://".length)}`;
    else
      throw new AfrError(
        "URI_UNSUPPORTED",
        "agent URI must be data:, https: or ipfs: (with a gateway)",
      );
    text = await fetchCapped(url, maxBytes, o);
  }
  if (new TextEncoder().encode(text).length > maxBytes)
    throw new AfrError("URI_TOO_LARGE", "agent URI exceeds the size cap");
  try {
    return JSON.parse(text);
  } catch {
    throw new AfrError("REGISTRATION_INVALID", "agent URI is not JSON");
  }
}

async function fetchCapped(url: string, maxBytes: number, o: FetchUriOptions): Promise<string> {
  let res: Response;
  try {
    res = await (o.fetch ?? fetch)(url, {
      redirect: "error",
      signal: AbortSignal.timeout(o.timeoutMs ?? 10_000),
    });
  } catch {
    throw new AfrError("URI_FETCH_FAILED", "agent URI could not be fetched");
  }
  if (!res.ok || !res.body)
    throw new AfrError("URI_FETCH_FAILED", `agent URI returned ${res.status}`);
  const chunks: Uint8Array[] = [];
  let n = 0;
  for await (const c of res.body as AsyncIterable<Uint8Array>) {
    n += c.length;
    if (n > maxBytes) throw new AfrError("URI_TOO_LARGE", "agent URI exceeds the size cap");
    chunks.push(c);
  }
  const all = new Uint8Array(n);
  let at = 0;
  for (const c of chunks) {
    all.set(c, at);
    at += c.length;
  }
  return new TextDecoder().decode(all);
}
