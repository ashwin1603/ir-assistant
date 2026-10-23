import { useState } from "react";
import { post, ApiError } from "../lib/api";

const ASK_TIMEOUT_MS = 40_000;

const SUGGESTED = [
  "What happened first?",
  "Which host?",
  "What is the risk level?",
  "Which techniques were used?",
  "What should I do?",
];

const MODE_LABELS = {
  deterministic: "from incident facts",
  ai: "AI answer · checked against facts",
  out_of_scope: "out of scope",
  fallback: "fallback",
};

export function AskPanel({ incidentId }) {
  const [messages, setMessages] = useState([]);
  const [question, setQuestion] = useState("");
  const [asking, setAsking] = useState(false);

  async function ask(text) {
    const q = text.trim();
    if (!q || asking) return;
    setAsking(true);
    setQuestion("");
    setMessages((prev) => [...prev, { role: "user", text: q }]);
    try {
      const result = await post(`/incidents/${incidentId}/ask`, { question: q }, ASK_TIMEOUT_MS);
      setMessages((prev) => [...prev, { role: "assistant", ...result, text: result.answer }]);
    } catch (err) {
      const text = err instanceof ApiError ? err.message : "Could not get an answer";
      setMessages((prev) => [...prev, { role: "error", text }]);
    } finally {
      setAsking(false);
    }
  }

  return (
    <div className="mb-6 rounded border border-slate-800 bg-slate-900/40 p-4">
      <div className="mb-3 flex flex-wrap gap-2">
        {SUGGESTED.map((s) => (
          <button
            key={s}
            onClick={() => ask(s)}
            disabled={asking}
            className="rounded-full border border-slate-700 px-3 py-1 text-xs text-slate-300 hover:bg-slate-800 disabled:opacity-50"
          >
            {s}
          </button>
        ))}
      </div>

      {messages.length > 0 && (
        <ul className="mb-3 max-h-80 space-y-2 overflow-y-auto">
          {messages.map((m, i) => (
            <li
              key={i}
              className={`rounded p-2 text-sm ${
                m.role === "user"
                  ? "ml-8 bg-sky-900/40 text-sky-100"
                  : m.role === "error"
                    ? "mr-8 bg-red-900/30 text-red-300"
                    : "mr-8 bg-slate-950/60 text-slate-300"
              }`}
            >
              <p className="whitespace-pre-wrap">{m.text}</p>
              {m.role === "assistant" && (
                <p className="mt-1 text-xs text-slate-500">
                  {MODE_LABELS[m.mode] || m.mode}
                  {m.cited?.length > 0 && <> · cites: {m.cited.join(", ")}</>}
                </p>
              )}
            </li>
          ))}
        </ul>
      )}
      {asking && <p className="mb-2 text-xs text-slate-500">Thinking...</p>}

      <form
        onSubmit={(e) => {
          e.preventDefault();
          ask(question);
        }}
        className="flex gap-2"
      >
        <input
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          maxLength={500}
          placeholder="Ask about this incident..."
          className="flex-1 rounded border border-slate-700 bg-slate-950 px-2 py-1 text-sm text-slate-200"
        />
        <button
          type="submit"
          disabled={asking || !question.trim()}
          className="rounded bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-500 disabled:opacity-50"
        >
          Ask
        </button>
      </form>
      <p className="mt-2 text-xs text-slate-500">
        Answers use only this incident&apos;s facts. Counts toward your hourly AI limit.
      </p>
    </div>
  );
}
