import type { ThreatAlert, ThreatClass, Severity, ThreatStatus, FlowMetadata, EvidenceFeature, TrafficMetrics } from "../types";
import { generateMockAlerts, generateTrafficMetrics } from "../data/mockData";

type Listener = () => void;

class LiveSimulationService {
  private alerts: ThreatAlert[] = [];
  private trafficMetrics: TrafficMetrics | null = null;
  private listeners: Set<Listener> = new Set();
  private intervalId: ReturnType<typeof setInterval> | null = null;
  private started = false;

  getAlerts(): ThreatAlert[] {
    if (this.alerts.length === 0) {
      this.alerts = generateMockAlerts(50);
    }
    return this.alerts;
  }

  getTrafficMetrics(): TrafficMetrics {
    if (!this.trafficMetrics) {
      this.trafficMetrics = generateTrafficMetrics();
    }
    return this.trafficMetrics;
  }

  subscribe(listener: Listener): () => void {
    this.listeners.add(listener);
    if (!this.started) this.start();
    return () => {
      this.listeners.delete(listener);
      if (this.listeners.size === 0) this.stop();
    };
  }

  private start() {
    if (this.started) return;
    this.started = true;
    this.intervalId = setInterval(() => {
      this.trafficMetrics = generateTrafficMetrics();
      const newAlerts = generateMockAlerts(1);
      this.alerts = [...newAlerts, ...this.alerts].slice(0, 100);
      this.listeners.forEach(l => l());
    }, 5000);
  }

  private stop() {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
    this.started = false;
  }

  updateThreatStatus(id: string, status: ThreatStatus) {
    const alert = this.alerts.find(a => a.id === id);
    if (alert) {
      alert.status = status;
      this.listeners.forEach(l => l());
    }
  }

  addNote(id: string, note: string) {
    const alert = this.alerts.find(a => a.id === id);
    if (alert) {
      if (!(alert as any)._analystNotes) (alert as any)._analystNotes = [];
      (alert as any)._analystNotes.push({ note, timestamp: new Date(), analyst: "Analyst" });
      this.listeners.forEach(l => l());
    }
  }

  getNotes(id: string): Array<{ note: string; timestamp: Date; analyst: string }> {
    const alert = this.alerts.find(a => a.id === id);
    return (alert as any)?._analystNotes || [];
  }

  injectSampleThreat() {
    const newAlerts = generateMockAlerts(1);
    this.alerts = [...newAlerts, ...this.alerts].slice(0, 100);
    this.listeners.forEach(l => l());
  }
}

export const liveSimulation = new LiveSimulationService();

// Convenience exports for useData hook
export function getBackendAlerts(): ThreatAlert[] {
  return liveSimulation.getAlerts();
}

export function getBackendMetrics(): TrafficMetrics {
  return liveSimulation.getTrafficMetrics();
}

export function subscribeToAlerts(listener: (alert: ThreatAlert) => void): () => void {
  return liveSimulation.subscribe(() => {
    const alerts = liveSimulation.getAlerts();
    if (alerts.length > 0) {
      listener(alerts[0]);
    }
  });
}

export function subscribeToMetrics(listener: (metrics: TrafficMetrics) => void): () => void {
  return liveSimulation.subscribe(() => {
    listener(liveSimulation.getTrafficMetrics());
  });
}
