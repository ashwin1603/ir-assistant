import { openStream } from "./api";

// Client for GET /api/stream (server-sent "data: {...}" lines with counts and ids only).
// Reconnects by itself: right away when the server ends a stream normally (it caps each
// stream's lifetime), with exponential backoff after errors. After FALLBACK_AFTER failures
// in a row it reports "fallback" so the app polls every 15s until the stream works again.
const FALLBACK_AFTER = 3;
const MAX_BACKOFF_MS = 30_000;
const SILENCE_MS = 40_000; // the server sends a heartbeat every 15s; silence this long = dead stream

export function connectLive({ onSignal, onStatus }) {
  let stopped = false;
  let failures = 0;
  let controller = null;
  let retryTimer = null;

  async function run() {
    controller = new AbortController();
    let silence = setTimeout(() => controller.abort(), SILENCE_MS);
    try {
      const res = await openStream("/stream", controller.signal);
      if (!res.ok || !res.body) throw new Error(`stream ${res.status}`);
      failures = 0;
      onStatus("live");
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        clearTimeout(silence);
        silence = setTimeout(() => controller.abort(), SILENCE_MS);
        buffer += decoder.decode(value, { stream: true });
        let end;
        while ((end = buffer.indexOf("\n\n")) >= 0) {
          const block = buffer.slice(0, end);
          buffer = buffer.slice(end + 2);
          for (const line of block.split("\n")) {
            if (!line.startsWith("data: ")) continue; // ": heartbeat" and "retry:" lines
            try {
              onSignal(JSON.parse(line.slice(6)));
            } catch {
              // ignore a malformed line
            }
          }
        }
      }
      if (!stopped) retryTimer = setTimeout(run, 250); // normal end of a capped stream
    } catch {
      if (stopped) return;
      failures += 1;
      onStatus(failures >= FALLBACK_AFTER ? "fallback" : "reconnecting");
      const delay = Math.min(MAX_BACKOFF_MS, 1000 * 2 ** (failures - 1)) + Math.random() * 500;
      retryTimer = setTimeout(run, delay);
    } finally {
      clearTimeout(silence);
    }
  }

  onStatus("connecting");
  run();
  return () => {
    stopped = true;
    clearTimeout(retryTimer);
    controller?.abort();
  };
}
