import { useState, useEffect, useCallback, useRef } from 'react';
import { API_BASE, authHeaders } from '../services/api';

export interface UseApiDataOptions {
  /** Polling interval in ms. 0 / undefined = no polling. */
  pollInterval?: number;
  /** Skip initial fetch (e.g. when a required ID isn't available yet). */
  skip?: boolean;
  /** Transform raw JSON before storing. */
  transform?: (raw: any) => any;
}

export interface UseApiDataResult<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  refetch: () => Promise<void>;
  lastUpdated: Date | null;
}

/**
 * Centralized data-fetching hook with auth, abort-on-unmount,
 * optional polling, and consistent loading/error state.
 *
 * Replaces the ad-hoc `useState` + `useCallback` + `fetch` pattern
 * that was duplicated across a dozen pages.
 */
export function useApiData<T = any>(
  path: string | null,
  options: UseApiDataOptions = {}
): UseApiDataResult<T> {
  const { pollInterval, skip, transform } = options;
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const isMounted = useRef(true);

  const url = path ? (path.startsWith('http') ? path : `${API_BASE}${path}`) : null;

  const fetchData = useCallback(async () => {
    if (!url || skip) {
      setLoading(false);
      return;
    }

    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    try {
      const resp = await fetch(url, {
        headers: authHeaders(),
        signal: controller.signal,
      });

      if (!isMounted.current) return;

      if (!resp.ok) {
        setError(`API Error: ${resp.status}`);
        return;
      }

      let json = await resp.json();
      if (transform) json = transform(json);

      setData(json);
      setError(null);
      setLastUpdated(new Date());
    } catch (e: any) {
      if (e.name === 'AbortError') return;
      if (isMounted.current) {
        setError(e.message || 'Network error');
      }
    } finally {
      if (isMounted.current) setLoading(false);
    }
  }, [url, skip, transform]);

  useEffect(() => {
    isMounted.current = true;
    fetchData();

    let timer: ReturnType<typeof setInterval> | undefined;
    if (pollInterval && pollInterval > 0) {
      timer = setInterval(fetchData, pollInterval);
    }

    return () => {
      isMounted.current = false;
      abortRef.current?.abort();
      if (timer) clearInterval(timer);
    };
  }, [fetchData, pollInterval]);

  return { data, loading, error, refetch: fetchData, lastUpdated };
}
