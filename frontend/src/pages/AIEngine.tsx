import { useEffect, useState } from 'react';
import { Cpu, Zap, AlertTriangle } from 'lucide-react';
import { CLASS_COLORS } from '../lib/utils';
import { fetchModelMetrics, type ThroughputTelemetry } from '../lib/api';
import { useLiveData } from '../hooks/useLiveData';

/**
 * Model metrics come from /api/v1/models, which serves the file produced by
 * scripts/regenerate_evaluation.py.
 *
 * This page previously rendered a hardcoded MODELS array in lib/utils.ts that
 * still claimed DGA test AUC 1.0 and "1000 Tranco benign + 5000 DGArchive
 * malicious". Both were superseded: the team's own audit showed that corpus was
 * separable by domain length alone, and the model was retrained on 142,582 real
 * domains for a CV AUC of 0.9966. The dashboard was therefore contradicting the
 * submission deck. Nothing on this page is hardcoded any more.
 */

type DgaBlock = {
  model?: string; cv_auc?: number; cv_sd?: number; test_auc?: number;
  full_model_cv_auc?: number; length_only_baseline_cv_auc?: number;
  tpr?: number; fpr?: number;
  deployed_features?: string[];
  corpus?: Record<string, unknown>;
  confusion?: Record<string, number>;
  available?: boolean; reason?: string; regenerate_with?: string;
};

type AblationBlock = {
  measured_at?: string;
  two_sided_features_removed?: string[];
  one_sided_substitutes?: string[];
  per_class?: Record<string, {
    bidirectional_f1: number | null;
    unidirectional_f1: number | null;
    with_substitutes_f1: number | null;
  }>;
  available?: boolean; reason?: string; regenerate_with?: string;
};

type Evaluation = {
  generated_at?: string; seed?: number;
  detectors?: { dga?: DgaBlock; unidirectional_ablation?: AblationBlock };
  throughput?: Record<string, unknown>;
};

const Metric = ({ label, value, color }: { label: string; value: string; color?: string }) => (
  <div className="glass glow-card metric-card">
    <div className="label">{label}</div>
    <div className="value" style={{ fontSize: 22, color: color ? `var(--color-${color})` : undefined }}>{value}</div>
  </div>
);

export default function AIEngine() {
  const { telemetry, backendUp } = useLiveData();
  const [evalData, setEvalData] = useState<Evaluation | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    fetchModelMetrics()
      .then(d => { setEvalData(d as Evaluation); setErr(null); })
      .catch(e => setErr((e as Error).message));
  }, []);

  const dga = evalData?.detectors?.dga;
  const abl = evalData?.detectors?.unidirectional_ablation;
  const t: ThroughputTelemetry | null = telemetry;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div>
        <h2 style={{ fontSize: 20, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 8 }}>
          <Cpu size={20} style={{ color: 'var(--color-violet)' }} /> AI Detection Engine
        </h2>
        <p style={{ fontSize: 13, color: 'var(--color-text-dim)', marginTop: 4 }}>
          6 detectors · streaming inference · no decryption · no return path
        </p>
      </div>

      {err && (
        <div className="glass" style={{ padding: '12px 16px', borderLeft: '3px solid var(--color-red)', fontSize: 12, color: 'var(--color-red)' }}>
          Could not load model metrics: {err}
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(180px,1fr))', gap: 14 }}>
        <Metric label="Detectors Active" value={t?.detection_active ? '6' : '0'} color={t?.detection_active ? 'teal' : 'red'} />
        <Metric label="Alerts Generated" value={t ? t.alerts_generated.toLocaleString() : '—'} />
        <Metric label="DGA CV AUC" value={dga?.cv_auc != null ? dga.cv_auc.toFixed(4) : '—'} color="green" />
        <Metric label="p50 Latency" value={t ? `${t.latency.p50_ms.toFixed(2)} ms` : '—'} />
      </div>

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
        {['Streaming inference', 'No payload decryption', 'Read-only ingest', 'No return path', 'Bounded latency'].map(l => (
          <span key={l} className="constraint">
            <span style={{ width: 5, height: 5, borderRadius: '50%', background: 'var(--color-green)' }} />{l}
          </span>
        ))}
      </div>

      {/* DGA — the only detector with a full published evaluation */}
      <div className="glass glow-card">
        <div className="panel-head">
          <h3>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: CLASS_COLORS['DGA'] || '#8060f0', display: 'inline-block', marginRight: 8 }} />
            DGA Classifier — LightGBM
          </h3>
          <span className="sub">seed {evalData?.seed ?? 42}</span>
        </div>
        <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {dga?.available === false ? (
            <div style={{ fontSize: 12, color: 'var(--color-amber)', display: 'flex', gap: 8, alignItems: 'center' }}>
              <AlertTriangle size={14} /> {dga.reason}. Regenerate with <code>{dga.regenerate_with}</code>
            </div>
          ) : (
            <>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(130px,1fr))', gap: 12 }}>
                {[
                  ['CV AUC (deployed)', dga?.cv_auc != null ? `${dga.cv_auc.toFixed(4)}${dga.cv_sd != null ? ` ± ${dga.cv_sd.toFixed(4)}` : ''}` : '—', 'green'],
                  ['Length-only baseline', dga?.length_only_baseline_cv_auc?.toFixed(4) ?? '—', 'amber'],
                  ['TPR', dga?.tpr != null ? `${(dga.tpr * 100).toFixed(1)}%` : '—', ''],
                  ['FPR', dga?.fpr != null ? `${(dga.fpr * 100).toFixed(1)}%` : '—', ''],
                ].map(([k, v, c]) => (
                  <div key={k as string}>
                    <div style={{ fontSize: 9, color: 'var(--color-text-muted)', textTransform: 'uppercase' }}>{k}</div>
                    <div className="num" style={{ fontSize: 15, marginTop: 3, color: c ? `var(--color-${c})` : undefined }}>{v}</div>
                  </div>
                ))}
              </div>
              {/* The baseline is displayed beside the model score on purpose: if
                  the two ever converge, the corpus is length-confounded again. */}
              <div style={{ padding: '10px 12px', borderRadius: 8, background: 'var(--color-surface-hi)', border: '1px solid var(--color-border)', fontSize: 11, color: 'var(--color-text-dim)', lineHeight: 1.6 }}>
                The length-only baseline is shown next to every model score deliberately. An earlier
                corpus scored AUC 1.0 because domain length alone separated the classes; the deployed
                model excludes <code>domain_length</code> entirely.
                {dga?.corpus ? ` Corpus: ${String(dga.corpus.benign_n ?? '?')} benign, ${String(dga.corpus.dga_n ?? '?')} DGA.` : ''}
              </div>
              {dga?.deployed_features?.length ? (
                <div>
                  <div style={{ fontSize: 10, color: 'var(--color-text-muted)', textTransform: 'uppercase', marginBottom: 6 }}>Deployed features</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                    {dga.deployed_features.map(f => (
                      <span key={f} className="num" style={{ fontSize: 10, padding: '2px 8px', borderRadius: 100, background: 'var(--color-surface-hi)', border: '1px solid var(--color-border)', color: 'var(--color-text-dim)' }}>{f}</span>
                    ))}
                  </div>
                </div>
              ) : null}
            </>
          )}
        </div>
      </div>

      {/* Unidirectional ablation */}
      <div className="glass glow-card">
        <div className="panel-head">
          <h3>Unidirectional Ablation</h3>
          <span className="sub">{abl?.measured_at ? new Date(abl.measured_at).toLocaleDateString() : 'not run'}</span>
        </div>
        <div className="panel-body">
          {abl?.available === false || !abl?.per_class ? (
            <div style={{ fontSize: 12, color: 'var(--color-amber)', display: 'flex', gap: 8, alignItems: 'center' }}>
              <AlertTriangle size={14} /> {abl?.reason ?? 'No ablation results available'}
            </div>
          ) : (
            <table style={{ width: '100%', fontSize: 12, borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ color: 'var(--color-text-muted)', textAlign: 'left' }}>
                  <th style={{ padding: '6px 0', fontWeight: 500 }}>Class</th>
                  <th style={{ fontWeight: 500 }}>Bidirectional F1</th>
                  <th style={{ fontWeight: 500 }}>Unidirectional F1</th>
                  <th style={{ fontWeight: 500 }}>+ Substitutes</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(abl.per_class).map(([cls, v]) => (
                  <tr key={cls} style={{ borderTop: '1px solid var(--color-border)' }}>
                    <td style={{ padding: '6px 0' }}>{cls}</td>
                    <td className="num">{v.bidirectional_f1?.toFixed(3) ?? '—'}</td>
                    <td className="num">{v.unidirectional_f1?.toFixed(3) ?? '—'}</td>
                    <td className="num" style={{ color: 'var(--color-green)' }}>{v.with_substitutes_f1?.toFixed(3) ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Live throughput — measured in this process, not a stored constant */}
      <div className="glass glow-card">
        <div className="panel-head">
          <h3><Zap size={14} style={{ color: 'var(--color-amber)' }} /> Live Throughput</h3>
          <span className="sub">{t ? `${t.total_flows.toLocaleString()} flows since boot` : backendUp ? 'loading…' : 'backend unreachable'}</span>
        </div>
        <div className="panel-body" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(150px,1fr))', gap: 16 }}>
          {(t ? [
            ['Current Rate', `${t.flows_per_sec.toFixed(1)} flows/sec`],
            ['Peak Observed', `${t.peak_flows_per_sec.toFixed(1)} flows/sec`],
            ['p50 Latency', `${t.latency.p50_ms.toFixed(2)} ms`],
            ['p95 Latency', `${t.latency.p95_ms.toFixed(2)} ms`],
            ['p99 Latency', `${t.latency.p99_ms.toFixed(2)} ms`],
            ['Zero Drops', t.queue.dropped_flows === 0 ? 'YES' : `NO (${t.queue.dropped_flows})`],
            ['Return Path', t.return_path],
          ] : [['Status', backendUp ? 'Loading…' : 'Backend unreachable']]).map(([k, v]) => (
            <div key={k as string}>
              <div style={{ fontSize: 10, color: 'var(--color-text-muted)', textTransform: 'uppercase' }}>{k}</div>
              <div className="num" style={{ fontSize: 16, marginTop: 4, color: (v as string) === 'YES' || (v as string) === 'NONE' ? 'var(--color-green)' : 'var(--color-text)' }}>{v}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
