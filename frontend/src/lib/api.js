const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000/api";

let authToken = null;

// Last response of a few list endpoints, so the command palette can search what pages
// already loaded without new requests. Memory only; cleared on logout.
const CACHED_PATHS = new Set(["/incidents", "/detections", "/devices"]);
const responseCache = new Map();

export function cached(path) {
  return responseCache.get(path);
}

export function setAuthToken(token) {
  authToken = token;
  if (!token) responseCache.clear();
}

export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

async function request(path, options = {}, timeoutMs) {
  const headers = { "Content-Type": "application/json", ...options.headers };
  if (authToken) headers.Authorization = `Bearer ${authToken}`;

  const controller = new AbortController();
  const timer = timeoutMs ? setTimeout(() => controller.abort(), timeoutMs) : null;

  let res;
  try {
    res = await fetch(`${API_BASE_URL}${path}`, { ...options, headers, signal: controller.signal });
  } catch (err) {
    if (err.name === "AbortError") {
      throw new ApiError(`Request timed out after ${Math.round(timeoutMs / 1000)}s`, 0);
    }
    throw new ApiError("Network error", 0);
  } finally {
    if (timer) clearTimeout(timer);
  }

  if (!res.ok) {
    let detail = "Request failed";
    try {
      const body = await res.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      // ignore parse errors, keep generic message
    }
    throw new ApiError(detail, res.status);
  }

  if (res.status === 204) return null;
  return res.json();
}

export async function get(path) {
  const data = await request(path, { method: "GET" });
  if (CACHED_PATHS.has(path)) responseCache.set(path, data);
  return data;
}

export function post(path, body, timeoutMs) {
  return request(path, { method: "POST", body: JSON.stringify(body) }, timeoutMs);
}

// For the forced MFA enrolment at login: uses the setup-only token, not the session token.
export function postWithToken(path, body, token) {
  return request(path, { method: "POST", body: JSON.stringify(body), headers: { Authorization: `Bearer ${token}` } });
}

export function put(path, body) {
  return request(path, { method: "PUT", body: JSON.stringify(body) });
}

export function patch(path, body) {
  return request(path, { method: "PATCH", body: JSON.stringify(body) });
}

export function del(path) {
  return request(path, { method: "DELETE" });
}

// Opens a streaming response (GET /stream). The token goes in the Authorization header,
// never in the URL, which is why this uses fetch and not EventSource.
export function openStream(path, signal) {
  const headers = authToken ? { Authorization: `Bearer ${authToken}` } : {};
  return fetch(`${API_BASE_URL}${path}`, { headers, signal, cache: "no-store" });
}

// Authenticated file download: fetch with the bearer token, then save the blob.
// Returns the CSV export headers ({ rows, truncated }) when the server sends them.
export async function download(path, filename) {
  const headers = authToken ? { Authorization: `Bearer ${authToken}` } : {};
  let res;
  try {
    res = await fetch(`${API_BASE_URL}${path}`, { headers });
  } catch {
    throw new ApiError("Network error", 0);
  }
  if (!res.ok) {
    const reason = { 403: "Not authorized", 429: "Export quota exceeded; try again later" }[res.status];
    throw new ApiError(reason || "Download failed", res.status);
  }

  const url = URL.createObjectURL(await res.blob());
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
  return {
    rows: Number(res.headers.get("X-Export-Rows") ?? NaN),
    truncated: res.headers.get("X-Export-Truncated") === "true",
  };
}


// Multipart upload via XHR (fetch has no upload-progress events).
export function upload(path, file, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", `${API_BASE_URL}${path}`);
    if (authToken) xhr.setRequestHeader("Authorization", `Bearer ${authToken}`);

    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable && onProgress) onProgress(Math.round((e.loaded / e.total) * 100));
    };
    xhr.onload = () => {
      let body = null;
      try {
        body = JSON.parse(xhr.responseText);
      } catch {
        // keep generic message
      }
      if (xhr.status >= 200 && xhr.status < 300) return resolve(body);
      const detail = typeof body?.detail === "string" ? body.detail : "Upload failed";
      reject(new ApiError(detail, xhr.status));
    };
    xhr.onerror = () => reject(new ApiError("Network error", 0));

    const form = new FormData();
    form.append("file", file);
    xhr.send(form);
  });
}
