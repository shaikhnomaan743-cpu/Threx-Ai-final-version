import { useState, useEffect, useRef, useCallback } from 'react';
import type { Alert, Metric, SystemStatus } from '../lib/types';
import { generateAlert, fetchHealth, fetchMetrics, fetchThreats } from '../lib/api';

const INIT: Metric = { flows_per_second:0, throughput_mbps:0, detection_latency_ms:12.93, active_threats:0, total_detections:0, chain_height:3680, uptime_seconds:0 };

export function useLiveData() {
  const [metrics, setMetrics] = useState<Metric>(INIT);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [paused, setPaused] = useState(false);
  const [status, setStatus] = useState<SystemStatus>('SIMULATION');
  const [backendUp, setBackendUp] = useState(false);
  const pRef = useRef(paused);
  useEffect(() => { pRef.current = paused; }, [paused]);
  const liveRef = useRef(false);

  useEffect(() => {
    fetchHealth().then(r => {
      setBackendUp(r.ok);
      if (r.ok && r.status) setStatus(r.status as SystemStatus);
    });
  }, []);

  // Prefer real backend alerts; fall back to the simulator only if it is down.
  useEffect(() => {
    let cancelled = false;
    fetchThreats(40).then(real => {
      if (cancelled) return;
      if (real.length) { liveRef.current = true; setAlerts(real); }
      else setAlerts(Array.from({length:20}, generateAlert));
    }).catch(() => setAlerts(Array.from({length:20}, generateAlert)));
    return () => { cancelled = true; };
  }, []);

  // Poll real metrics. Only the fields the backend cannot supply stay simulated.
  useEffect(() => {
    let cancelled = false;
    const pull = () => {
      if (pRef.current) return;
      fetchMetrics().then(m => {
        if (!cancelled && m) setMetrics(p => ({ ...p, ...m }));
      });
      if (liveRef.current) fetchThreats(40).then(r => { if (!cancelled && r.length) setAlerts(r); });
    };
    pull();
    const iv = setInterval(pull, 5000);
    return () => { cancelled = true; clearInterval(iv); };
  }, []);

  // tick
  useEffect(() => {
    const iv = setInterval(() => {
      if (pRef.current) return;
      setMetrics(p => ({
        ...p,
        flows_per_second: Math.max(60, Math.min(120, (p.flows_per_second||88) + (Math.random()-.48)*8)),
        throughput_mbps: Math.max(2, Math.min(8, (p.throughput_mbps||5.2) + (Math.random()-.5)*.3)),
        detection_latency_ms: 11 + Math.random()*4,
        uptime_seconds: p.uptime_seconds + 1,
        chain_height: p.chain_height + (Math.random()<.03?1:0),
      }));
      // Only synthesise alerts when there is no backend feeding us real ones.
      if (!liveRef.current && Math.random()<.18) setAlerts(p=>[generateAlert(),...p].slice(0,60));
    }, 1000);
    return ()=>clearInterval(iv);
  }, []);

  return { metrics, alerts, paused, togglePause:useCallback(()=>setPaused(p=>!p),[]), backendUp, status };
}
