import { useState, useEffect, useCallback } from "react";
import type { ThreatAlert, TrafficMetrics, DgaDetection, DnsTunnelingIndicator, TlsFingerprint, PortScanDetection, ExfiltrationAnomaly, ModelStatus, PipelineStage, SystemStatus } from "../types";
import { getBackendAlerts, getBackendMetrics, subscribeToAlerts, subscribeToMetrics } from "../services/liveSimulation";
import * as api from "../services/apiClient";
import { useAlertWebSocket, useMetricsWebSocket } from "./useWebSocket";

export type DataMode = "simulation" | "backend" | "live";

interface UseDataReturn {
  dataMode: DataMode;
  alerts: ThreatAlert[];
  metrics: TrafficMetrics;
  dgaDetections: DgaDetection[];
  dnsTunneling: DnsTunnelingIndicator[];
  tlsFingerprints: TlsFingerprint[];
  portScans: PortScanDetection[];
  exfilAnomalies: ExfiltrationAnomaly[];
  modelStatuses: ModelStatus[];
  pipelineStages: PipelineStage[];
  systemStatus: SystemStatus;
  loading: boolean;
  error: string | null;
  refresh: () => void;
}

export function useData(): UseDataReturn {
  const [dataMode, setDataMode] = useState<DataMode>("simulation");
  const [alerts, setAlerts] = useState<ThreatAlert[]>([]);
  const [metrics, setMetrics] = useState<TrafficMetrics>({
    packetsPerSecond: 0, flowsPerSecond: 0, bitsPerSecond: 0,
    activeFlows: 0, uniqueSourceIps: 0, uniqueDestIps: 0,
    topProtocols: [], topTalkers: [], topPorts: [],
  });
  const [dgaDetections, setDgaDetections] = useState<DgaDetection[]>([]);
  const [dnsTunneling, setDnsTunneling] = useState<DnsTunnelingIndicator[]>([]);
  const [tlsFingerprints, setTlsFingerprints] = useState<TlsFingerprint[]>([]);
  const [portScans, setPortScans] = useState<PortScanDetection[]>([]);
  const [exfilAnomalies, setExfilAnomalies] = useState<ExfiltrationAnomaly[]>([]);
  const [modelStatuses, setModelStatuses] = useState<ModelStatus[]>([]);
  const [pipelineStages, setPipelineStages] = useState<PipelineStage[]>([]);
  const [systemStatus, setSystemStatus] = useState<SystemStatus>({
    ingestHealth: "degraded", throughput: 0, uptime: 0, activeAlerts: 0,
    processedFlows: 0, droppedPackets: 0, cpuUsage: 0, memoryUsage: 0,
    diskUsage: 0, diodeStatus: "disconnected", lastFlowTimestamp: new Date(),
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadFromBackend = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const [a, m, d, dn, t, p, e, ms, ps, ss] = await Promise.all([
        api.getThreats(),
        api.getTrafficMetrics(),
        api.getDgaDetections(),
        api.getDnsTunnelingIndicators(),
        api.getTlsFingerprints(),
        api.getPortScanDetections(),
        api.getExfiltrationAnomalies(),
        api.getModelStatuses(),
        api.getPipelineStages(),
        api.getSystemStatus(),
      ]);
      setAlerts(a);
      setMetrics(m);
      setDgaDetections(d);
      setDnsTunneling(dn);
      setTlsFingerprints(t);
      setPortScans(p);
      setExfilAnomalies(e);
      setModelStatuses(ms);
      setPipelineStages(ps);
      setSystemStatus(ss);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load data");
    } finally {
      setLoading(false);
    }
  }, []);

  const loadFromSimulation = useCallback(() => {
    setLoading(true);
    setAlerts(getBackendAlerts());
    setMetrics(getBackendMetrics());
    setLoading(false);
  }, []);

  // websocket live handlers (enabled only when backend)
  const onWsAlert = useCallback((a: ThreatAlert) => {
    setAlerts((prev) => {
      if (prev.find((p) => p.id === a.id)) return prev;
      return [a, ...prev].slice(0, 1000);
    });
  }, []);
  const onWsMetrics = useCallback((m: any) => {
    if (m && typeof m.flows_per_second === "number") {
      setMetrics((prev) => ({
        ...prev,
        flowsPerSecond: m.flows_per_second,
        packetsPerSecond: m.packets_per_second ?? prev.packetsPerSecond,
        bitsPerSecond: m.bytes_per_second ? m.bytes_per_second * 8 : prev.bitsPerSecond,
        activeFlows: m.active_alerts ?? prev.activeFlows,
      }));
    }
  }, []);
  useAlertWebSocket(onWsAlert, dataMode === "backend");
  useMetricsWebSocket(onWsMetrics, dataMode === "backend");

  useEffect(() => {
    let unsubAlerts: (() => void) | undefined;
    let unsubMetrics: (() => void) | undefined;

    async function init() {
      const backendOk = await api.initBackend();
      if (backendOk) {
        setDataMode("backend");
        await loadFromBackend();
        // in backend mode, websockets will push live updates; keep simulation sub as fallback for metrics if ws drops
        unsubMetrics = subscribeToMetrics((newMetrics) => {
          // only apply if ws hasn't updated recently (ws will overwrite)
        });
      } else {
        setDataMode("simulation");
        loadFromSimulation();
        unsubAlerts = subscribeToAlerts((newAlert) => {
          setAlerts((prev) => [newAlert, ...prev].slice(0, 1000));
        });
        unsubMetrics = subscribeToMetrics((newMetrics) => {
          setMetrics(newMetrics);
        });
      }
    }
    init();

    return () => {
      unsubAlerts?.();
      unsubMetrics?.();
    };
  }, [loadFromBackend, loadFromSimulation]);

  const refresh = useCallback(() => {
    if (dataMode === "backend") {
      loadFromBackend();
    } else {
      loadFromSimulation();
    }
  }, [dataMode, loadFromBackend, loadFromSimulation]);

  return {
    dataMode, alerts, metrics, dgaDetections, dnsTunneling, tlsFingerprints,
    portScans, exfilAnomalies, modelStatuses, pipelineStages, systemStatus,
    loading, error, refresh,
  };
}
