/**
 * Centralized API configuration.
 * All pages/components should import API_BASE / WS_BASE / authHeaders from here
 * instead of hardcoding hosts or tokens. Values are driven by Vite env vars
 * (see ui/.env): VITE_API_BASE, VITE_WS_BASE, VITE_OSOP_TOKEN.
 */

export const API_BASE = import.meta.env.VITE_API_BASE || "http://127.0.0.1:8200";
export const WS_BASE = import.meta.env.VITE_WS_BASE || "ws://127.0.0.1:8200";
export const AUTH_TOKEN = import.meta.env.VITE_OSOP_TOKEN || "dev-token";

/** Standard auth headers; pass `extra` to merge additional headers (e.g. Content-Type). */
export const authHeaders = (extra: Record<string, string> = {}): Record<string, string> => ({
  Authorization: `Bearer ${AUTH_TOKEN}`,
  ...extra,
});
