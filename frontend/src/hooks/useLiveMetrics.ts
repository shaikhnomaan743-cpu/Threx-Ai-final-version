import { useState, useEffect, useCallback } from "react";
import { liveSimulation } from "../services/liveSimulation";
import type { ThreatAlert, TrafficMetrics } from "../types";

export function useLiveAlerts() {
  const [alerts, setAlerts] = useState<ThreatAlert[]>(() => liveSimulation.getAlerts());

  useEffect(() => {
    return liveSimulation.subscribe(() => {
      setAlerts([...liveSimulation.getAlerts()]);
    });
  }, []);

  const updateStatus = useCallback((id: string, status: ThreatAlert["status"]) => {
    liveSimulation.updateThreatStatus(id, status);
    setAlerts([...liveSimulation.getAlerts()]);
  }, []);

  const addNote = useCallback((id: string, note: string) => {
    liveSimulation.addNote(id, note);
  }, []);

  return { alerts, updateStatus, addNote };
}

export function useLiveTrafficMetrics() {
  const [metrics, setMetrics] = useState<TrafficMetrics>(() => liveSimulation.getTrafficMetrics());

  useEffect(() => {
    return liveSimulation.subscribe(() => {
      setMetrics(liveSimulation.getTrafficMetrics());
    });
  }, []);

  return metrics;
}
