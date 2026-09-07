import { useState, useEffect, useRef, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { Search, ArrowRight, Globe, Shield, Hash, Fingerprint, AlertTriangle } from "lucide-react";
import { searchIndex } from "../services/searchIndex";
import { liveSimulation } from "../services/liveSimulation";
import type { SearchResult } from "../services/api";

const ICON_MAP: Record<SearchResult["type"], typeof Search> = {
  threat: AlertTriangle,
  alert: Shield,
  ip: Globe,
  domain: Globe,
  fingerprint: Fingerprint,
};

const TYPE_LABELS: Record<SearchResult["type"], string> = {
  threat: "Threat",
  alert: "Alert",
  ip: "IP Address",
  domain: "Domain",
  fingerprint: "Fingerprint",
};

export function GlobalSearch({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<SearchResult[]>([]);
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();

  useEffect(() => {
    if (open) {
      setQuery("");
      setResults([]);
      setSelectedIndex(0);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [open]);

  useEffect(() => {
    searchIndex.build(liveSimulation.getAlerts());
  }, []);

  useEffect(() => {
    if (!query.trim()) {
      setResults([]);
      setSelectedIndex(0);
      return;
    }
    const timer = setTimeout(() => {
      const searchResults = searchIndex.search(query);
      setResults(searchResults);
      setSelectedIndex(0);
    }, 50);
    return () => clearTimeout(timer);
  }, [query]);

  const handleSelect = useCallback((result: SearchResult) => {
    navigate(result.href);
    onClose();
  }, [navigate, onClose]);

  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setSelectedIndex(prev => Math.min(prev + 1, results.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setSelectedIndex(prev => Math.max(prev - 1, 0));
    } else if (e.key === "Enter" && results[selectedIndex]) {
      handleSelect(results[selectedIndex]);
    } else if (e.key === "Escape") {
      onClose();
    }
  }, [results, selectedIndex, handleSelect, onClose]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-[100] flex items-start justify-center pt-[15vh]" onClick={onClose}>
      <div className="fixed inset-0 bg-black/60 backdrop-blur-sm" />
      <div
        className="relative w-full max-w-xl bg-[var(--color-bg-elevated-1)] border border-[var(--color-border-card)] rounded-[8px] shadow-2xl animate-fade-in overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center gap-3 px-4 py-3 border-b border-[var(--color-border-card)]">
          <Search className="w-5 h-5 text-[var(--color-text-muted)] flex-shrink-0" />
          <input
            ref={inputRef}
            type="text"
            placeholder="Search threats, IPs, domains, fingerprints, severity, status..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            className="flex-1 bg-transparent text-[var(--color-text-primary)] placeholder-[var(--color-text-muted)] outline-none text-sm"
            aria-label="Global search"
          />
          <kbd className="hidden sm:inline-flex items-center px-2 py-0.5 rounded-[4px] bg-[var(--color-bg-elevated-2)] border border-[var(--color-border-card)] text-[10px] font-mono text-[var(--color-text-muted)]">
            ESC
          </kbd>
        </div>

        {results.length > 0 && (
          <div className="max-h-[400px] overflow-y-auto py-2">
            {results.map((result, i) => {
              const Icon = ICON_MAP[result.type];
              return (
                <button
                  key={`${result.type}-${result.id}-${i}`}
                  onClick={() => handleSelect(result)}
                  onMouseEnter={() => setSelectedIndex(i)}
                  className={`w-full flex items-center gap-3 px-4 py-2.5 text-left transition-colors ${
                    i === selectedIndex
                      ? "bg-[var(--color-accent-cyan-dim)]"
                      : "hover:bg-[var(--color-bg-elevated-2)]"
                  }`}
                >
                  <div className={`w-8 h-8 rounded-[6px] flex items-center justify-center flex-shrink-0 ${
                    i === selectedIndex ? "bg-[var(--color-accent-cyan)]" : "bg-[var(--color-bg-elevated-2)]"
                  }`}>
                    <Icon className={`w-4 h-4 ${i === selectedIndex ? "text-[var(--color-bg-deep)]" : "text-[var(--color-text-muted)]"}`} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium text-[var(--color-text-primary)] truncate">{result.title}</span>
                      <span className="text-[10px] font-mono text-[var(--color-text-muted)] uppercase">{TYPE_LABELS[result.type]}</span>
                    </div>
                    <p className="text-xs text-[var(--color-text-muted)] truncate mt-0.5">{result.subtitle}</p>
                  </div>
                  <ArrowRight className={`w-4 h-4 flex-shrink-0 transition-opacity ${i === selectedIndex ? "opacity-100 text-[var(--color-accent-cyan)]" : "opacity-0"}`} />
                </button>
              );
            })}
          </div>
        )}

        {query.trim() && results.length === 0 && (
          <div className="px-4 py-8 text-center">
            <p className="text-sm text-[var(--color-text-muted)]">No results found for "{query}"</p>
            <p className="text-xs text-[var(--color-text-muted)] mt-1">Try searching by IP, domain, threat class, severity, or fingerprint</p>
          </div>
        )}

        {!query.trim() && (
          <div className="px-4 py-6 text-center">
            <p className="text-sm text-[var(--color-text-muted)]">Type to search across threats, alerts, IPs, and more</p>
            <div className="flex items-center justify-center gap-4 mt-3 text-[10px] text-[var(--color-text-muted)]">
              <span>IPs</span>
              <span>Domains</span>
              <span>JA3/JA4</span>
              <span>Threat Classes</span>
              <span>Severity</span>
              <span>Status</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
