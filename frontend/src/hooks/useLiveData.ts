import { useSyncExternalStore } from 'react';
import type { Alert, Metric, SystemStatus } from '../lib/types';
import {
  fetchHealth, fetchMetrics, fetchThreats,
  type ThroughputTelemetry, fetchTelemetry,
} from '../lib/api';

/**
 * Single polling hook for live backend state.
 *
 * What changed and why: this hook used to run a 1-second `setInterval` that
 * mutated flows_per_second, throughput_mbps and detection_latency_ms with
 * Math.random() on every tick, and injected a synthetic alert with ~18%
 * probability whenever the backend was unreachable. The dashboard therefore
 * animated convincingly while connected to nothing. Every number below now
 * comes from /api/v1/metrics/throughput, and when the backend is down the UI
 * shows an error instead of inventing traffic.
 */

const INIT: Metric = {
  flows_per_second: 0, throughput_mbps: 0, detection_latency_ms: 0,
  active_threats: 0, total_detections: 0, chain_height: 0, uptime_seconds: 0,
};

const POLL_MS = 2000;

/**
 * Shared store: ONE poller for the whole app.
 *
 * Every component that called useLiveData() used to start its own 2 s
 * setInterval, so Layout + the current page polled twice in parallel. With the
 * extra /threats redirects that was ~480 req/min from one tab against a 120/min
 * per-IP limit, which is what caused the periodic 429 blackouts. Now all
 * callers subscribe to the same state; polling starts with the first
 * subscriber and stops when the last one unmounts. The hook's return shape is
 * unchanged, so no call site needed editing.
 */
type LiveState = {
  metrics: Metric;
  telemetry: ThroughputTelemetry | null;
  alerts: Alert[];
  paused: boolean;
  status: SystemStatus;
  backendUp: boolean;
  detectionActive: boolean;
  error: string | null;
  loading: boolean;
};

let state: LiveState = {
  metrics: INIT, telemetry: null, alerts: [], paused: false,
  status: 'SIMULATION', backendUp: false, detectionActive: false,
  error: null, loading: true,
};

const listeners = new Set<() => void>();
let timer: ReturnType<typeof setInterval> | null = null;
let inFlight = false;

function setState(patch: Partial<LiveState>) {
  state = { ...state, ...patch };
  listeners.forEach(l => l());
}

async function poll() {
  // Skip if paused or if the previous poll is still running (slow backend):
  // overlapping polls are how request counts pile up.
  if (state.paused || inFlight) return;
  inFlight = true;
  try {
    const health = await fetchHealth();
    if (!health.ok) {
      setState({ backendUp: false, detectionActive: false,
                 error: health.error || 'Backend unreachable', loading: false });
      return;
    }
    const engineError = health.detection_active === false
      // Engine down but API up: say so rather than showing an empty, healthy
      // looking board. "No threats" and "no detector" must not look alike.
      ? (health.degraded_reason || 'Detection engine unavailable')
      : null;
    try {
      const t = await fetchTelemetry();
      const [m, a] = await Promise.all([fetchMetrics(t), fetchThreats(40)]);
      setState({
        backendUp: true,
        detectionActive: Boolean(health.detection_active),
        error: engineError,
        metrics: { ...state.metrics, ...m },
        telemetry: t,
        alerts: a,
        status: (t.data_source as SystemStatus) || 'BACKEND_SEEDED',
        loading: false,
      });
    } catch (e) {
      setState({ backendUp: true, detectionActive: Boolean(health.detection_active),
                 error: (e as Error).message, loading: false });
    }
  } finally {
    inFlight = false;
  }
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  if (listeners.size === 1 && timer === null) {
    poll();
    timer = setInterval(poll, POLL_MS);
  }
  return () => {
    listeners.delete(listener);
    if (listeners.size === 0 && timer !== null) {
      clearInterval(timer);
      timer = null;
    }
  };
}

const getSnapshot = () => state;

const togglePause = () => setState({ paused: !state.paused });
const refresh = () => poll();

export function useLiveData() {
  const s = useSyncExternalStore(subscribe, getSnapshot, getSnapshot);
  return {
    metrics: s.metrics, telemetry: s.telemetry, alerts: s.alerts, paused: s.paused,
    togglePause,
    backendUp: s.backendUp, detectionActive: s.detectionActive,
    status: s.status, error: s.error, loading: s.loading,
    refresh,
  };
}
