
import { api } from "./api.js";

// Tokens exist only in application memory.
// They are not saved to localStorage or sessionStorage.
let accessToken = null;
let refreshToken = null;

export function getAccessToken() {
  return accessToken;
}

export function isAuthenticated() {
  return Boolean(accessToken);
}

export async function register({ email, full_name, password }) {
  return api.post("/api/v1/auth/register", {
    email,
    full_name,
    password,
  });
}

export async function login({ email, password }) {
  const tokens = await api.post("/api/v1/auth/login", {
    email,
    password,
  });

  accessToken = tokens.access_token;
  refreshToken = tokens.refresh_token;

  return getCurrentUser();
}

export async function getCurrentUser() {
  if (!accessToken) {
    throw new Error("Please log in first.");
  }

  return api.get("/api/v1/auth/me", {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });
}

export async function refreshSession() {
  if (!refreshToken) {
    throw new Error("No refresh token available. Please log in again.");
  }

  const tokens = await api.post("/api/v1/auth/refresh", {
    refresh_token: refreshToken,
  });

  accessToken = tokens.access_token;
  refreshToken = tokens.refresh_token;

  return tokens;
}

export async function logout() {
  try {
    if (accessToken) {
      await api.post(
        "/api/v1/auth/logout",
        {},
        {
          headers: {
            Authorization: `Bearer ${accessToken}`,
          },
        }
      );
    }
  } finally {
    accessToken = null;
    refreshToken = null;
  }
}
