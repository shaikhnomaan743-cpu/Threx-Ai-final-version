import { Cpu, HardDrive, Server, Zap } from "lucide-react";
import { cn } from "../../lib/utils";

export function InfrastructureFooter() {
  const resources = {
    cpu: 23 + Math.random() * 15,
    ram: 45 + Math.random() * 20,
    disk: 67 + Math.random() * 10,
  };

  return (
    <div className="bg-[#12141a]/80 backdrop-blur-md border-t border-white/5 p-4">
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Ingest Status */}
        <div className="space-y-2">
          <h4 className="text-xs font-medium text-[var(--color-text-muted)] uppercase tracking-wider">Ingest Status</h4>
          <div className="bg-[#1a1d26]/50 rounded-[6px] p-3 space-y-2">
            <div className="flex justify-between text-xs">
              <span className="text-[var(--color-text-secondary)]">Interface</span>
              <span className="font-mono text-[var(--color-text-primary)]">eth0</span>
            </div>
            <div className="flex justify-between text-xs">
              <span className="text-[var(--color-text-secondary)]">Ingest Type</span>
              <span className="font-mono text-[var(--color-accent-cyan)]">SIMULATION</span>
            </div>
            <div className="flex justify-between text-xs">
              <span className="text-[var(--color-text-secondary)]">Flows Ingested</span>
              <span className="font-mono text-[var(--color-text-primary)]">1,247,832</span>
            </div>
            <div className="flex justify-between text-xs">
              <span className="text-[var(--color-text-secondary)]">Packets Observed</span>
              <span className="font-mono text-[var(--color-text-primary)]">8,234,567</span>
            </div>
            <div className="flex justify-between text-xs">
              <span className="text-[var(--color-text-secondary)]">Last Update</span>
              <span className="font-mono text-[var(--color-text-primary)]">2s ago</span>
            </div>
          </div>
        </div>

        {/* Throughput Capacity */}
        <div className="space-y-2">
          <h4 className="text-xs font-medium text-[var(--color-text-muted)] uppercase tracking-wider">Throughput Capacity (Tested)</h4>
          <div className="bg-[#1a1d26]/50 rounded-[6px] p-3 space-y-2">
            <div className="flex justify-between text-xs">
              <span className="text-[var(--color-text-secondary)]">Sustained</span>
              <span className="font-mono text-[var(--color-success)]">125.3 Mbps</span>
            </div>
            <div className="flex justify-between text-xs">
              <span className="text-[var(--color-text-secondary)]">Peak</span>
              <span className="font-mono text-[var(--color-accent-cyan)]">234.7 Mbps</span>
            </div>
            <div className="flex justify-between text-xs">
              <span className="text-[var(--color-text-secondary)]">Flows / Sec</span>
              <span className="font-mono text-[var(--color-text-primary)]">88.6</span>
            </div>
            <div className="flex justify-between text-xs">
              <span className="text-[var(--color-text-secondary)]">Packet Capture</span>
              <span className="font-mono text-[var(--color-text-primary)]">10 Gbps</span>
            </div>
          </div>
        </div>

        {/* System Resources */}
        <div className="space-y-2">
          <h4 className="text-xs font-medium text-[var(--color-text-muted)] uppercase tracking-wider">System Resources</h4>
          <div className="bg-[#1a1d26]/50 rounded-[6px] p-3 space-y-3">
            <div className="space-y-1">
              <div className="flex justify-between text-xs">
                <span className="text-[var(--color-text-secondary)] flex items-center gap-1">
                  <Cpu className="w-3 h-3" /> CPU
                </span>
                <span className="font-mono text-[var(--color-text-primary)]">{resources.cpu.toFixed(1)}%</span>
              </div>
              <div className="h-1.5 bg-[#090a0f] rounded-full overflow-hidden">
                <div 
                  className="h-full bg-[var(--color-accent-cyan)] transition-all duration-500"
                  style={{ width: `${resources.cpu}%` }}
                />
              </div>
            </div>
            <div className="space-y-1">
              <div className="flex justify-between text-xs">
                <span className="text-[var(--color-text-secondary)] flex items-center gap-1">
                  <Server className="w-3 h-3" /> RAM
                </span>
                <span className="font-mono text-[var(--color-text-primary)]">{resources.ram.toFixed(1)}%</span>
              </div>
              <div className="h-1.5 bg-[#090a0f] rounded-full overflow-hidden">
                <div 
                  className="h-full bg-[var(--color-success)] transition-all duration-500"
                  style={{ width: `${resources.ram}%` }}
                />
              </div>
            </div>
            <div className="space-y-1">
              <div className="flex justify-between text-xs">
                <span className="text-[var(--color-text-secondary)] flex items-center gap-1">
                  <HardDrive className="w-3 h-3" /> Disk
                </span>
                <span className="font-mono text-[var(--color-text-primary)]">{resources.disk.toFixed(1)}%</span>
              </div>
              <div className="h-1.5 bg-[#090a0f] rounded-full overflow-hidden">
                <div 
                  className="h-full bg-[var(--color-warning)] transition-all duration-500"
                  style={{ width: `${resources.disk}%` }}
                />
              </div>
            </div>
          </div>
        </div>

        {/* Streaming Engine Status */}
        <div className="space-y-2">
          <h4 className="text-xs font-medium text-[var(--color-text-muted)] uppercase tracking-wider">Streaming Engine Status</h4>
          <div className="bg-[#1a1d26]/50 rounded-[6px] p-3">
            <div className="flex items-center gap-2 mb-2">
              <div className="w-2 h-2 rounded-full bg-[var(--color-success)] animate-pulse" />
              <span className="text-sm font-medium text-[var(--color-success)]">STREAMING ENGINE ACTIVE</span>
            </div>
            <div className="h-8">
              <svg viewBox="0 0 100 30" className="w-full h-full">
                <path
                  d="M0,15 Q25,5 50,15 T100,15"
                  fill="none"
                  stroke="var(--color-accent-cyan)"
                  strokeWidth="2"
                  strokeLinecap="round"
                />
              </svg>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}