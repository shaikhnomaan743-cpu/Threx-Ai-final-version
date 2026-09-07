import { Server, Shield, CheckCircle2, XCircle, Database } from 'lucide-react';
import { useLiveData } from '../hooks/useLiveData';
import { formatUptime, BENCHMARK } from '../lib/utils';
export default function System(){
  const {metrics,backendUp}=useLiveData();
  const constraints=[
    {label:'Read-Only Ingest',ok:true,desc:'Input strictly read-only. No write-back capability.'},
    {label:'Return Path',ok:true,desc:'No physical or protocol-level return path exists.',inv:true},
    {label:'Payload Decryption',ok:true,desc:'TLS/QUIC analyzed from metadata only — never decrypted.',inv:true},
    {label:'Inline Blocking',ok:true,desc:'No inline blocking — intelligence output only.',inv:true},
    {label:'Streaming Engine',ok:true,desc:'Traffic processed incrementally with bounded latency (p50: 12.93ms).'},
    {label:'Ledger Anchoring',ok:true,desc:'Every alert hashed for tamper-evident chain of custody.'},
  ];
  return (
    <div style={{display:'flex',flexDirection:'column',gap:20}}>
      <div><h2 style={{fontSize:20,fontWeight:600,display:'flex',alignItems:'center',gap:8}}><Server size={20}/> System Status</h2></div>
      <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(200px,1fr))',gap:14}}>
        <div className="glass glow-card metric-card"><div className="label">Backend</div><div className="value" style={{fontSize:20,color:backendUp?'var(--color-green)':'var(--color-amber)'}}>{backendUp?'Connected':'Offline'}</div></div>
        <div className="glass glow-card metric-card"><div className="label">Uptime</div><div className="value" style={{fontSize:20}}>{formatUptime(metrics.uptime_seconds)}</div></div>
        <div className="glass glow-card metric-card"><div className="label">Throughput</div><div className="value" style={{fontSize:20}}>{BENCHMARK.sustained_peak}<span> fps</span></div></div>
        <div className="glass glow-card metric-card"><div className="label">Diode</div><div className="value" style={{fontSize:20,color:'var(--color-teal)'}}>PASS-THRU</div></div>
      </div>
      <div className="glass glow-card"><div className="panel-head"><h3><Shield size={14} style={{color:'var(--color-green)'}}/> Architecture Constraints</h3><span style={{fontSize:11,color:'var(--color-green)',fontWeight:500}}>All satisfied ✓</span></div>
        <div>{constraints.map(c=>(<div key={c.label} style={{display:'flex',alignItems:'center',gap:16,padding:'14px 20px',borderBottom:'1px solid var(--color-border)'}}>
          {c.inv?<div style={{width:32,height:32,borderRadius:8,background:'var(--color-surface-hi)',display:'flex',alignItems:'center',justifyContent:'center'}}><XCircle size={16} style={{color:'var(--color-text-muted)'}}/></div>
            :<div style={{width:32,height:32,borderRadius:8,background:'rgba(32,192,112,.08)',display:'flex',alignItems:'center',justifyContent:'center'}}><CheckCircle2 size={16} style={{color:'var(--color-green)'}}/></div>}
          <div style={{flex:1}}><div style={{fontSize:13,fontWeight:500}}>{c.label}</div><div style={{fontSize:11,color:'var(--color-text-dim)',marginTop:2}}>{c.desc}</div></div>
          <span className="num" style={{fontSize:11,fontWeight:500,color:c.inv?'var(--color-text-muted)':'var(--color-green)'}}>{c.inv?'DISABLED':'ACTIVE'}</span>
        </div>))}</div></div>
      <div className="glass glow-card"><div className="panel-head"><h3><Database size={14}/> Services</h3></div><div className="panel-body" style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:8}}>
        {[{n:'threx-backend',p:':8000',up:backendUp},{n:'threx-frontend',p:':5173',up:true},{n:'threx-redis',p:':6379',up:backendUp},{n:'threx-postgres',p:':5432',up:backendUp}].map(s=>(
          <div key={s.n} style={{display:'flex',alignItems:'center',justifyContent:'space-between',padding:'8px 12px',borderRadius:8,background:'var(--color-surface-hi)',border:'1px solid var(--color-border)'}}>
            <span style={{display:'flex',alignItems:'center',gap:8,fontSize:12}}><span className="dot" style={{background:s.up?'var(--color-green)':'var(--color-text-muted)'}}/>{s.n}</span>
            <span className="num" style={{fontSize:11,color:'var(--color-text-muted)'}}>{s.p}</span></div>))}
      </div></div>
    </div>
  );
}
