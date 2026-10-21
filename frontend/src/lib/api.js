const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000/api";

let authToken = null;

export function setAuthToken(token) {
  authToken = token;
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

export function get(path) {
  return request(path, { method: "GET" });
}

export function post(path, body, timeoutMs) {
  return request(path, { method: "POST", body: JSON.stringify(body) }, timeoutMs);
}
