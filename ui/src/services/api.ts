/**
 * Centralized API configuration.
 * All pages/components should import API_BASE / WS_BASE / authHeaders from here
 * instead of hardcoding hosts or tokens. Values are driven by Vite env vars
 * (see ui/.env): VITE_API_BASE, VITE_WS_BASE, VITE_OSOP_TOKEN.
 */

const proto = window.location.protocol === "https:" ? "https:" : "http:";
const wsProto = window.location.protocol === "https:" ? "wss:" : "ws:";

export const API_BASE = import.meta.env.VITE_API_BASE || `${proto}//127.0.0.1:8200`;
export const WS_BASE = import.meta.env.VITE_WS_BASE || `${wsProto}//127.0.0.1:8200`;
export const AUTH_TOKEN = (() => {
  const token = import.meta.env.VITE_OSOP_TOKEN;
  if (!token) {
    throw new Error(
      "VITE_OSOP_TOKEN is required at build time. Set it in your .env or CI environment."
    );
  }
  return token;
})();

/** Standard auth headers; pass `extra` to merge additional headers (e.g. Content-Type). */
export const authHeaders = (extra: Record<string, string> = {}): Record<string, string> => {
  return {
    Authorization: `Bearer ${AUTH_TOKEN}`,
    ...extra,
  };
};
