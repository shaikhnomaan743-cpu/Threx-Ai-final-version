import { useState, useEffect } from 'react';
import { Globe, AlertTriangle } from 'lucide-react';
import { fetchDNS } from '../lib/api';
export default function DNS(){
  const [d,setD]=useState<any>(null);
  useEffect(()=>{fetchDNS().then(setD)},[]);
  if(!d) return <div style={{display:'flex',alignItems:'center',justifyContent:'center',height:260,color:'var(--color-text-muted)'}}>Loading…</div>;
  return (
    <div style={{display:'flex',flexDirection:'column',gap:20}}>
      <div><h2 style={{fontSize:20,fontWeight:600,display:'flex',alignItems:'center',gap:8}}><Globe size={20} style={{color:'var(--color-violet)'}}/> DNS Analytics</h2>
      <p style={{fontSize:13,color:'var(--color-text-dim)',marginTop:4}}>DGA detection via entropy/n-gram · DNS tunnelling via query-length and record-type anomalies</p></div>
      <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(160px,1fr))',gap:14}}>
        {[['Total Queries',d.total.toLocaleString(),false],['DGA Detected',d.dga,true],['Tunnelling',d.tunnel,true],['Avg Entropy',d.entropy.toFixed(2),false]].map(([l,v,a])=>(
          <div key={l as string} className={`glass glow-card metric-card ${a?'alert':''}`}><div className="label">{l}</div><div className="value" style={{fontSize:22,...(a?{color:'var(--color-red)'}:{})}}>{v as any}</div></div>
        ))}
      </div>
      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16}}>
        <div className="glass glow-card"><div className="panel-head"><h3>DGA Families Detected</h3></div><div className="panel-body">
          {d.families.map((f:string)=>(<div key={f} style={{display:'flex',justifyContent:'space-between',padding:'10px 0',borderBottom:'1px solid var(--color-border)',fontSize:13}}>
            <span style={{display:'flex',alignItems:'center',gap:6}}><AlertTriangle size={12} style={{color:'var(--color-amber)'}}/>{f}</span>
            <span className="num" style={{fontSize:12,color:'var(--color-text-dim)'}}>{Math.round(Math.random()*30+5)} domains</span></div>))}
        </div></div>
        <div className="glass glow-card"><div className="panel-head"><h3>Flagged Domains</h3></div><div style={{overflowX:'auto'}}>
          <table className="tbl"><thead><tr><th>Domain</th><th>Entropy</th><th>Family</th><th>Confidence</th></tr></thead><tbody>
            {d.samples.map((s:any,i:number)=>(<tr key={i}><td className="num" style={{fontSize:11,color:'var(--color-red)'}}>{s.domain}</td><td className="num" style={{fontSize:12}}>{s.entropy}</td><td style={{fontSize:12,color:'var(--color-text-dim)'}}>{s.family}</td><td><span className="conf"><span className="num" style={{fontSize:12}}>{s.confidence}%</span><span className="confbar"><i className="fill-teal" style={{width:`${s.confidence}%`}}/></span></span></td></tr>))}
          </tbody></table></div></div>
      </div>
    </div>
  );
}
