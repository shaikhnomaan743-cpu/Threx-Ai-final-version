import { useEffect, useRef, useState } from "react";
import { cn } from "../../lib/utils";

interface FlowVisualizationProps {
  sourceIp: string;
  destinationIp: string;
  sourcePort: number;
  destinationPort: number;
  protocol: string;
  packets: number;
  bytes: number;
  direction: "inbound" | "outbound" | "internal";
  className?: string;
}

export function FlowVisualization({ 
  sourceIp, 
  destinationIp, 
  sourcePort, 
  destinationPort, 
  protocol,
  packets,
  bytes,
  direction,
  className 
}: FlowVisualizationProps) {
  const [packetPositions, setPacketPositions] = useState<number[]>(Array(8).fill(0).map(() => Math.random()));
  const animationRef = useRef<number | null>(null);

  useEffect(() => {
    const animate = () => {
      setPacketPositions(prev => prev.map(pos => {
        const newPos = pos + 0.003;
        return newPos > 1 ? 0 : newPos;
      }));
      animationRef.current = requestAnimationFrame(animate);
    };
    animationRef.current = requestAnimationFrame(animate);
    return () => { if (animationRef.current) cancelAnimationFrame(animationRef.current); };
  }, []);

  const directionLabels = {
    inbound: "INBOUND",
    outbound: "OUTBOUND", 
    internal: "INTERNAL",
  };

  const directionColors = {
    inbound: "var(--color-threat-exfil)",
    outbound: "var(--color-threat-ddos)",
    internal: "var(--color-accent-cyan)",
  };

  return (
    <div className={cn("relative p-6", className)}>
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-12 h-12 rounded-[8px] bg-[var(--color-bg-elevated-2)] border border-[var(--color-border-card)] flex items-center justify-center">
            <svg className="w-6 h-6 text-[var(--color-text-secondary)]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
            </svg>
          </div>
          <div>
            <p className="text-xs text-[var(--color-text-muted)] uppercase tracking-wider">SOURCE</p>
            <p className="font-mono text-sm text-[var(--color-text-primary)] tabular-nums">{sourceIp}</p>
            <p className="text-xs text-[var(--color-text-muted)] font-mono">Port: {sourcePort}</p>
          </div>
        </div>
        
        <div className="flex items-center gap-4 px-4 py-2 bg-[var(--color-bg-elevated-2)] border border-[var(--color-border-card)] rounded-[6px]">
          <div className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: directionColors[direction] }} />
          <span className="text-xs font-medium text-[var(--color-text-secondary)] uppercase tracking-wider">{directionLabels[direction]}</span>
          <span className="text-xs text-[var(--color-text-muted)] font-mono">{protocol}</span>
        </div>

        <div className="flex items-center gap-3 text-right">
          <div>
            <p className="text-xs text-[var(--color-text-muted)] uppercase tracking-wider">DESTINATION</p>
            <p className="font-mono text-sm text-[var(--color-text-primary)] tabular-nums">{destinationIp}</p>
            <p className="text-xs text-[var(--color-text-muted)] font-mono">Port: {destinationPort}</p>
          </div>
          <div className="w-12 h-12 rounded-[8px] bg-[var(--color-bg-elevated-2)] border border-[var(--color-border-card)] flex items-center justify-center">
            <svg className="w-6 h-6 text-[var(--color-text-secondary)]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
          </div>
        </div>
      </div>

      <div className="relative h-16">
        <svg className="w-full h-full" viewBox="0 0 800 64" preserveAspectRatio="none">
          <defs>
            <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
              <polygon points="0 0, 10 3.5, 0 7" fill="var(--color-border-card)" />
            </marker>
            
            <linearGradient id="path-gradient" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="var(--color-border-card)" stopOpacity="0.3" />
              <stop offset="50%" stopColor="var(--color-accent-cyan)" stopOpacity="0.5" />
              <stop offset="100%" stopColor="var(--color-border-card)" stopOpacity="0.3" />
            </linearGradient>
          </defs>

          <path 
            d="M40,32 Q200,32 380,32 Q400,32 420,32 Q580,32 760,32" 
            stroke="url(#path-gradient)" 
            strokeWidth="2" 
            fill="none"
            strokeDasharray="8,4"
            markerEnd="url(#arrowhead)"
            className="animate-packet-flow"
          />

          {packetPositions.map((pos, i) => (
            <circle
              key={i}
              cx={40 + pos * 720}
              cy={32}
              r={3}
              fill="var(--color-accent-cyan)"
              opacity={0.8}
              filter="drop-shadow(0 0 4px var(--color-accent-cyan))"
            />
          ))}
        </svg>
      </div>

      <div className="grid grid-cols-3 gap-4 mt-6 pt-4 border-t border-[var(--color-border-card)]/50">
        <div className="text-center">
          <p className="text-2xl font-light tabular-nums font-mono text-[var(--color-text-primary)]">{packets.toLocaleString()}</p>
          <p className="text-xs text-[var(--color-text-muted)] uppercase tracking-wider">PACKETS</p>
        </div>
        <div className="text-center">
          <p className="text-2xl font-light tabular-nums font-mono text-[var(--color-text-primary)]">{(bytes / 1024 / 1024).toFixed(2)} MB</p>
          <p className="text-xs text-[var(--color-text-muted)] uppercase tracking-wider">BYTES</p>
        </div>
        <div className="text-center">
          <p className="text-2xl font-light tabular-nums font-mono text-[var(--color-text-primary)]">{(bytes * 8 / 1024 / 1024).toFixed(2)} Mb</p>
          <p className="text-xs text-[var(--color-text-muted)] uppercase tracking-wider">BITS</p>
        </div>
      </div>
    </div>
  );
}
