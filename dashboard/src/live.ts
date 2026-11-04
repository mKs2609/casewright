import { api, ApiError } from "./api";

/**
 * Follows the live feed (ADR-49). The gateway only says which incident changed; the dashboard then
 * fetches it through the ordinary API. So nothing but incident numbers arrives here, and a message
 * lost while reconnecting costs nothing: every new connection starts with "ready", and the
 * dashboard reloads what it shows.
 */

export type LiveState = "connecting" | "live" | "paused";

export interface LiveHandlers {
  onReady: () => void;
  onChanged: (incidentId: number) => void;
  onState: (state: LiveState) => void;
}

/** Delays before reconnecting. Exported for the tests, which shorten them. */
export const timing = {
  /** After the gateway ended the feed (its login expired): reconnect almost at once. */
  afterEnd: 500,
  /** After a failure: this, doubling each time up to the maximum. */
  firstRetry: 2_000,
  maxRetry: 60_000,
  /** A feed that ends sooner than this counts as a failure, so a broken server is not called in a tight loop. */
  minimumLife: 5_000,
};

const MAX_LINE = 1024;
const INCIDENT_NUMBER = /^\d{1,15}$/;

/** Starts following; the returned function stops. */
export function followIncidents(handlers: LiveHandlers): () => void {
  const stop = new AbortController();
  void run(handlers, stop.signal);
  return () => stop.abort();
}

async function run(handlers: LiveHandlers, signal: AbortSignal) {
  let failures = 0;
  while (!signal.aborted) {
    handlers.onState("connecting");
    const opened = Date.now();
    let wait: number;
    try {
      const body = await api.openFeed(signal);
      await readEvents(body, signal, (event, data) => {
        if (event === "ready") {
          handlers.onState("live");
          handlers.onReady();
        } else if (event === "incident" && INCIDENT_NUMBER.test(data)) {
          handlers.onChanged(Number(data));
        }
      });
      failures = Date.now() - opened < timing.minimumLife ? failures + 1 : 0;
      wait = failures === 0 ? timing.afterEnd : retryDelay(failures);
    } catch (failure) {
      if (signal.aborted) {
        return;
      }
      if (failure instanceof ApiError && failure.status === 401) {
        return; // The session is over: api.ts has already sent the app to the login screen.
      }
      failures += 1;
      // Too many tabs (429) or a full server (503): those do not clear up in seconds.
      const busy = failure instanceof ApiError && (failure.status === 429 || failure.status === 503);
      wait = busy ? timing.maxRetry : retryDelay(failures);
    }
    if (signal.aborted) {
      return;
    }
    handlers.onState("paused");
    await sleep(wait, signal);
  }
}

const retryDelay = (failures: number) => Math.min(timing.firstRetry * 2 ** (failures - 1), timing.maxRetry);

function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, ms);
    signal.addEventListener(
      "abort",
      () => {
        clearTimeout(timer);
        resolve();
      },
      { once: true },
    );
  });
}

/**
 * Reads Server-Sent Events: "event:" and "data:" lines, a blank line ending each message, and
 * lines starting with ":" ignored (the keep-alive). Only what this feed sends is understood.
 */
export async function readEvents(
  body: ReadableStream<Uint8Array>,
  signal: AbortSignal,
  onEvent: (event: string, data: string) => void,
): Promise<void> {
  const reader = body.getReader();
  const cancel = () => void reader.cancel().catch(() => {});
  signal.addEventListener("abort", cancel, { once: true });
  const decoder = new TextDecoder();
  let buffer = "";
  let event = "";
  let data = "";
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done || signal.aborted) {
        return;
      }
      buffer += decoder.decode(value, { stream: true });
      let end: number;
      while ((end = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, end).replace(/\r$/, "");
        buffer = buffer.slice(end + 1);
        if (line === "") {
          if (event) {
            onEvent(event, data);
          }
          event = "";
          data = "";
        } else if (line.startsWith("event:")) {
          event = line.slice(6).trim();
        } else if (line.startsWith("data:")) {
          data = line.slice(5).trim();
        }
      }
      if (buffer.length > MAX_LINE) {
        throw new ApiError(0, "The live feed sent something unexpected.");
      }
    }
  } finally {
    signal.removeEventListener("abort", cancel);
    reader.releaseLock();
  }
}
