import { useState, useEffect } from 'react';
import { Search, Crosshair } from 'lucide-react';
import { fetchRecon } from '../lib/api';
export default function Recon(){
  const [d,setD]=useState<any>(null);
  useEffect(()=>{fetchRecon().then(setD)},[]);
  if(!d) return <div style={{display:'flex',alignItems:'center',justifyContent:'center',height:260,color:'var(--color-text-muted)'}}>Loading…</div>;
  return (
    <div style={{display:'flex',flexDirection:'column',gap:20}}>
      <div><h2 style={{fontSize:20,fontWeight:600,display:'flex',alignItems:'center',gap:8}}><Search size={20}/> Reconnaissance Detection</h2>
      <p style={{fontSize:13,color:'var(--color-text-dim)',marginTop:4}}>Fan-out patterns — single source across many destination ports or hosts</p></div>
      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:14}}>
        <div className="glass glow-card metric-card"><div className="label">Total Scans</div><div className="value" style={{fontSize:22}}>{d.total}</div></div>
        <div className="glass glow-card metric-card"><div className="label">Active Scanners</div><div className="value" style={{fontSize:22,color:'var(--color-amber)'}}>{d.active}</div></div>
      </div>
      <div className="glass glow-card"><div className="panel-head"><h3><Crosshair size={14} style={{color:'var(--color-amber)'}}/> Detected Scans</h3></div>
        <div style={{overflowX:'auto'}}><table className="tbl"><thead><tr><th>Source</th><th>Unique Ports</th><th>Unique Hosts</th><th>Duration</th><th>Technique</th></tr></thead><tbody>
          {d.scans.map((s:any,i:number)=>(<tr key={i}><td className="num" style={{fontSize:12,color:'var(--color-amber)'}}>{s.src}</td><td className="num" style={{fontSize:12}}>{s.ports.toLocaleString()}</td><td className="num" style={{fontSize:12}}>{s.hosts}</td><td className="num" style={{fontSize:12,color:'var(--color-text-dim)'}}>{s.dur}s</td><td style={{fontSize:12,color:'var(--color-text-dim)'}}>{s.tech}</td></tr>))}
        </tbody></table></div></div>
      <div className="glass glow-card"><div className="panel-head"><h3>Detection Thresholds</h3></div><div className="panel-body" style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:'0 24px'}}>
        {[['Port scan threshold','> 20 unique ports'],['Host sweep threshold','> 15 unique hosts'],['SYN/ACK ratio flag','> 5:1'],['Model type','Rule-based statistical']].map(([k,v])=>(
          <div key={k} style={{display:'flex',justifyContent:'space-between',padding:'8px 0',borderBottom:'1px solid var(--color-border)',fontSize:12}}><span style={{color:'var(--color-text-dim)'}}>{k}</span><span className="num" style={{color:'var(--color-amber)'}}>{v}</span></div>))}
      </div></div>
    </div>
  );
}
