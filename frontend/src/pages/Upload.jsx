import { useRef, useState } from "react";
import { Link } from "react-router-dom";
import { upload } from "../lib/api";

const ALLOWED = [".evtx", ".json", ".csv"];
const MAX_MB = 20;

// Client-side checks are only for quick feedback; the backend enforces them again.
function precheck(file) {
  const ext = file.name.slice(file.name.lastIndexOf(".")).toLowerCase();
  if (!ALLOWED.includes(ext)) return `Unsupported file type. Allowed: ${ALLOWED.join(", ")}`;
  if (file.size > MAX_MB * 1024 * 1024) return `File too large (max ${MAX_MB} MB)`;
  if (file.size === 0) return "File is empty";
  return "";
}

export default function Upload() {
  const inputRef = useRef(null);
  const [dragging, setDragging] = useState(false);
  const [progress, setProgress] = useState(null);
  const [processing, setProcessing] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);

  function handleFile(file) {
    if (!file) return;
    setError("");
    setResult(null);
    const problem = precheck(file);
    if (problem) return setError(problem);

    setProgress(0);
    upload("/uploads", file, (pct) => {
      setProgress(pct);
      if (pct === 100) setProcessing(true);
    })
      .then(setResult)
      .catch((err) => setError(err.message || "Upload failed"))
      .finally(() => {
        setProgress(null);
        setProcessing(false);
      });
  }

  const busy = progress !== null;

  return (
    <div>
      <h1 className="mb-1 text-xl font-semibold text-slate-100">Upload Logs</h1>
      <p className="mb-4 text-sm text-slate-400">
        Get-WinEvent JSON export, CSV, or .evtx file — max {MAX_MB} MB. Events are normalized, deduplicated
        and run through detection.
      </p>

      <div
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragging(false);
          if (!busy) handleFile(e.dataTransfer.files[0]);
        }}
        onClick={() => !busy && inputRef.current?.click()}
        className={`flex cursor-pointer flex-col items-center justify-center rounded border-2 border-dashed px-6 py-14 text-sm transition-colors ${
          dragging ? "border-sky-500 bg-sky-950/30 text-sky-300" : "border-slate-700 text-slate-400 hover:border-slate-500"
        } ${busy ? "cursor-wait opacity-70" : ""}`}
      >
        <span className="mb-1 text-slate-200">Drag & drop a log file here</span>
        <span>or click to choose ({ALLOWED.join(", ")})</span>
        <input
          ref={inputRef}
          type="file"
          accept={ALLOWED.join(",")}
          className="hidden"
          onChange={(e) => {
            handleFile(e.target.files[0]);
            e.target.value = "";
          }}
        />
      </div>

      {busy && (
        <div className="mt-4">
          <div className="mb-1 text-xs text-slate-400">
            {processing ? "Parsing and running detection… (.evtx files can take a few minutes)" : `Uploading… ${progress}%`}
          </div>
          <div className="h-2 w-full overflow-hidden rounded bg-slate-800">
            <div
              className={`h-full bg-sky-600 transition-all ${processing ? "animate-pulse" : ""}`}
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>
      )}

      {error && (
        <div className="mt-4 rounded border border-red-900 bg-red-950/40 px-4 py-3 text-sm text-red-300">{error}</div>
      )}

      {result && (
        <div className="mt-4 rounded border border-emerald-900 bg-emerald-950/30 px-4 py-3 text-sm text-emerald-300">
          <div className="font-medium">{result.filename} uploaded</div>
          <div className="text-emerald-400/80">
            {result.parsed} events parsed · {result.inserted} new · {result.duplicates} duplicates skipped
          </div>
          <div className="mt-2 flex gap-4">
            <Link to="/events" className="text-sky-400 hover:underline">
              View in Log Explorer
            </Link>
            <Link to="/detections" className="text-sky-400 hover:underline">
              View Detections
            </Link>
          </div>
        </div>
      )}
    </div>
  );
}
