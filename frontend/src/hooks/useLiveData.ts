import { useState, useEffect, useRef, useCallback } from 'react';
import type { Alert, Metric, SystemStatus } from '../lib/types';
import { generateAlert, fetchHealth } from '../lib/api';

const INIT: Metric = { flows_per_second:0, throughput_mbps:0, detection_latency_ms:12.93, active_threats:0, total_detections:0, chain_height:3680, uptime_seconds:0 };

export function useLiveData() {
  const [metrics, setMetrics] = useState<Metric>(INIT);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [paused, setPaused] = useState(false);
  const [status, setStatus] = useState<SystemStatus>('SIMULATION');
  const [backendUp, setBackendUp] = useState(false);
  const pRef = useRef(paused); pRef.current = paused;

  useEffect(() => {
    fetchHealth().then(r => {
      setBackendUp(r.ok);
      if (r.ok && r.status) setStatus(r.status as SystemStatus);
    });
  }, []);

  // seed alerts
  useEffect(() => { setAlerts(Array.from({length:20}, generateAlert)); }, []);

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
        total_detections: p.total_detections + (Math.random()<.15?1:0),
        active_threats: 180 + Math.round(Math.random()*40),
        chain_height: p.chain_height + (Math.random()<.03?1:0),
      }));
      if (Math.random()<.18) setAlerts(p=>[generateAlert(),...p].slice(0,60));
    }, 1000);
    return ()=>clearInterval(iv);
  }, []);

  return { metrics, alerts, paused, togglePause:useCallback(()=>setPaused(p=>!p),[]), backendUp, status };
}
