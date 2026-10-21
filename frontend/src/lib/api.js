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
