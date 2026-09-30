import { Server, Shield, CheckCircle2, XCircle, Database } from 'lucide-react';
import { useLiveData } from '../hooks/useLiveData';
import { formatUptime } from '../lib/utils';
export default function System(){
  const {metrics,telemetry,backendUp,detectionActive,error}=useLiveData();
  const constraints=[
    {label:'Read-Only Ingest',ok:true,desc:'Input strictly read-only. No write-back capability.'},
    {label:'Return Path',ok:true,desc:'No physical or protocol-level return path exists.',inv:true},
    {label:'Payload Decryption',ok:true,desc:'TLS/QUIC analyzed from metadata only — never decrypted.',inv:true},
    {label:'Inline Blocking',ok:true,desc:'No inline blocking — intelligence output only.',inv:true},
    {label:'Streaming Engine',ok:true,desc:telemetry?`Traffic processed incrementally with bounded latency (measured p50: ${telemetry.latency.p50_ms.toFixed(2)}ms, p95: ${telemetry.latency.p95_ms.toFixed(2)}ms).`:'Traffic processed incrementally. Awaiting live latency measurement.'},
    {label:'Ledger Anchoring',ok:true,desc:'Every alert hashed for tamper-evident chain of custody.'},
  ];
  return (
    <div style={{display:'flex',flexDirection:'column',gap:20}}>
      <div><h2 style={{fontSize:20,fontWeight:600,display:'flex',alignItems:'center',gap:8}}><Server size={20}/> System Status</h2></div>
      {error && (
        <div className="glass" style={{padding:'12px 16px',borderLeft:'3px solid var(--color-red)',fontSize:12,color:'var(--color-red)'}}>
          {error}
        </div>
      )}
      <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(200px,1fr))',gap:14}}>
        <div className="glass glow-card metric-card"><div className="label">Detection Engine</div><div className="value" style={{fontSize:20,color:detectionActive?'var(--color-green)':'var(--color-red)'}}>{detectionActive?'ACTIVE':'UNAVAILABLE'}</div></div>
        <div className="glass glow-card metric-card"><div className="label">Queue Depth</div><div className="value" style={{fontSize:20}}>{telemetry?telemetry.queue.depth:'—'}</div></div>
        <div className="glass glow-card metric-card"><div className="label">Dropped Flows</div><div className="value" style={{fontSize:20,color:telemetry&&telemetry.queue.dropped_flows>0?'var(--color-amber)':'var(--color-green)'}}>{telemetry?telemetry.queue.dropped_flows:'—'}</div></div>
        <div className="glass glow-card metric-card"><div className="label">Memory (RSS)</div><div className="value" style={{fontSize:20}}>{telemetry?.resources.available?`${telemetry.resources.memory_rss_mb?.toFixed(0)} MB`:'n/a'}</div></div>
      </div>
      <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(200px,1fr))',gap:14}}>
        <div className="glass glow-card metric-card"><div className="label">Backend</div><div className="value" style={{fontSize:20,color:backendUp?'var(--color-green)':'var(--color-amber)'}}>{backendUp?'Connected':'Offline'}</div></div>
        <div className="glass glow-card metric-card"><div className="label">Uptime</div><div className="value" style={{fontSize:20}}>{formatUptime(metrics.uptime_seconds)}</div></div>
        <div className="glass glow-card metric-card"><div className="label">Throughput</div><div className="value" style={{fontSize:20}}>{telemetry?telemetry.flows_per_sec.toFixed(1):'—'}<span> fps</span></div></div>
        <div className="glass glow-card metric-card"><div className="label">Diode</div><div className="value" style={{fontSize:20,color:'var(--color-teal)'}}>PASS-THRU</div></div>
      </div>
      {(()=>{const p=telemetry?.pipeline;const multi=p?.mode==='multi_core';
        const loss=p?.loss?(p.loss.exporter_seq_gap_records+p.loss.queue_drops_messages):null;
        return(<div style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(200px,1fr))',gap:14}}>
        <div className="glass glow-card metric-card"><div className="label">Pipeline</div><div className="value" style={{fontSize:20}}>{p?(multi?`${p.workers} workers`:'single process'):'—'}</div></div>
        <div className="glass glow-card metric-card" title={p?.latency_basis}><div className="label">Latency p95 ({multi?'receipt→detection':'inference'})</div><div className="value" style={{fontSize:20}}>{telemetry?telemetry.latency.p95_ms.toFixed(1):'—'}<span> ms</span></div></div>
        <div className="glass glow-card metric-card" title="Exporter sequence gaps + receiver queue drops"><div className="label">Flow-record loss</div><div className="value" style={{fontSize:20,color:loss?'var(--color-amber)':'var(--color-green)'}}>{multi?loss:'n/a'}</div></div>
        <div className="glass glow-card metric-card" title="New alerts pushed live / held back by the 200/s cap (all are stored)"><div className="label">Live push / held</div><div className="value" style={{fontSize:20}}>{multi?`${p?.alerts?.pushed??0} / ${p?.alerts?.push_suppressed??0}`:'—'}</div></div>
      </div>);})()}
      <div className="glass glow-card"><div className="panel-head"><h3><Shield size={14} style={{color:'var(--color-green)'}}/> Architecture Constraints</h3><span style={{fontSize:11,color:'var(--color-green)',fontWeight:500}}>All satisfied ✓</span></div>
        <div>{constraints.map(c=>(<div key={c.label} style={{display:'flex',alignItems:'center',gap:16,padding:'14px 20px',borderBottom:'1px solid var(--color-border)'}}>
          {c.inv?<div style={{width:32,height:32,borderRadius:8,background:'var(--color-surface-hi)',display:'flex',alignItems:'center',justifyContent:'center'}}><XCircle size={16} style={{color:'var(--color-text-muted)'}}/></div>
            :<div style={{width:32,height:32,borderRadius:8,background:'rgba(32,192,112,.08)',display:'flex',alignItems:'center',justifyContent:'center'}}><CheckCircle2 size={16} style={{color:'var(--color-green)'}}/></div>}
          <div style={{flex:1}}><div style={{fontSize:13,fontWeight:500}}>{c.label}</div><div style={{fontSize:11,color:'var(--color-text-dim)',marginTop:2}}>{c.desc}</div></div>
          <span className="num" style={{fontSize:11,fontWeight:500,color:c.inv?'var(--color-text-muted)':'var(--color-green)'}}>{c.inv?'DISABLED':'ACTIVE'}</span>
        </div>))}</div></div>
      <div className="glass glow-card"><div className="panel-head"><h3><Database size={14}/> Services</h3></div><div className="panel-body" style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:8}}>
        {/* Only components this app actually runs: alerts are stored in SQLite
            (not Redis/Postgres, which the old panel showed as "up"). */}
        {[{n:'threx-backend',p:':8000',up:backendUp},{n:'threx-frontend',p:':5173',up:true},{n:'alert-store (SQLite)',p:'data/alerts.db',up:backendUp},{n:'flow-collector (IPFIX/NetFlow)',p:telemetry?.pipeline?.mode==='multi_core'?`${telemetry.pipeline.workers} workers`:'udp',up:telemetry?.data_source==='FLOW_RECORDS'}].map(s=>(
          <div key={s.n} style={{display:'flex',alignItems:'center',justifyContent:'space-between',padding:'8px 12px',borderRadius:8,background:'var(--color-surface-hi)',border:'1px solid var(--color-border)'}}>
            <span style={{display:'flex',alignItems:'center',gap:8,fontSize:12}}><span className="dot" style={{background:s.up?'var(--color-green)':'var(--color-text-muted)'}}/>{s.n}</span>
            <span className="num" style={{fontSize:11,color:'var(--color-text-muted)'}}>{s.p}</span></div>))}
      </div></div>
    </div>
  );
}
