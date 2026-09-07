import { useState, useEffect } from "react";
import { getIngestStatus } from "../services/apiClient";

type IngestSource = "LAB_REPLAY" | "PCAP_REPLAY" | "LIVE_INGEST" | "BACKEND_SEEDED";

const SOURCE_CONFIG: Record<string, { text: string; color: string; dotClass: string }> = {
  BACKEND_SEEDED: { text: "BACKEND SEEDED", color: "bg-green-500/20 text-green-400 border-green-500/30", dotClass: "bg-green-400 animate-pulse" },
  PCAP_REPLAY:  { text: "PCAP REPLAY", color: "bg-green-500/20 text-green-400 border-green-500/30", dotClass: "bg-green-400 animate-pulse" },
  LIVE_INGEST:  { text: "LIVE INGEST", color: "bg-blue-500/20 text-blue-400 border-blue-500/30", dotClass: "bg-blue-400 animate-pulse" },
  LAB_REPLAY:   { text: "LAB REPLAY", color: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30", dotClass: "bg-cyan-400 animate-pulse" },
};

function resolveSource(ingestSource: string | null): IngestSource {
  if (ingestSource && SOURCE_CONFIG[ingestSource]) return ingestSource as IngestSource;
  return "LAB_REPLAY";
}

export function DataModeIndicator({ ingestSource }: { ingestSource?: string | null }) {
  const [liveSource, setLiveSource] = useState<string | null>(ingestSource ?? null);

  useEffect(() => {
    if (!ingestSource) {
      getIngestStatus().then((st) => {
        if (st?.data_source) setLiveSource(st.data_source);
      }).catch(() => {});
    }
  }, [ingestSource]);

  const source = resolveSource(liveSource);
  const cfg = SOURCE_CONFIG[source] || SOURCE_CONFIG.LAB_REPLAY;

  return (
    <div className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-mono font-bold tracking-wider border ${cfg.color}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${cfg.dotClass}`} />
      {cfg.text}
    </div>
  );
}
