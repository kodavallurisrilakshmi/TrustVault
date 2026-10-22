
const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

async function apiRequest(path, options = {}) {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers: {
      ...(options.body instanceof FormData
        ? {}
        : { "Content-Type": "application/json" }),
      ...(options.headers || {}),
    },
    credentials: "omit",
  });

  const contentType = response.headers.get("content-type") || "";
  const data = contentType.includes("application/json")
    ? await response.json()
    : await response.text();

  if (!response.ok) {
    const message =
      typeof data === "object" && data !== null
        ? data.detail || "Request failed"
        : data || "Request failed";

    throw new Error(message);
  }

  return data;
}

export const api = {
  get: (path, options = {}) =>
    apiRequest(path, { ...options, method: "GET" }),

  post: (path, body, options = {}) =>
    apiRequest(path, {
      ...options,
      method: "POST",
      body:
        body instanceof FormData ? body : JSON.stringify(body ?? {}),
    }),

  put: (path, body, options = {}) =>
    apiRequest(path, {
      ...options,
      method: "PUT",
      body: JSON.stringify(body ?? {}),
    }),

  delete: (path, options = {}) =>
    apiRequest(path, { ...options, method: "DELETE" }),
};

export { API_BASE_URL };
