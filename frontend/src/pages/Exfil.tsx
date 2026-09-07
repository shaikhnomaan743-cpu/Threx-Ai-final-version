import { useState, useEffect } from 'react';
import { ArrowUpFromLine } from 'lucide-react';
import { fetchExfil } from '../lib/api';
import { formatBytes } from '../lib/utils';
export default function Exfil(){
  const [d,setD]=useState<any>(null);
  useEffect(()=>{fetchExfil().then(setD)},[]);
  if(!d) return <div style={{display:'flex',alignItems:'center',justifyContent:'center',height:260,color:'var(--color-text-muted)'}}>Loading…</div>;
  const mx=Math.max(1,...(d.items||[]).map((a:any)=>a.out));
  return (
    <div style={{display:'flex',flexDirection:'column',gap:20}}>
      <div><h2 style={{fontSize:20,fontWeight:600,display:'flex',alignItems:'center',gap:8}}><ArrowUpFromLine size={20} style={{color:'var(--color-green)'}}/> Data Exfiltration</h2>
      <p style={{fontSize:13,color:'var(--color-text-dim)',marginTop:4}}>Asymmetric flow-volume anomalies and unusual outbound-to-inbound byte ratios</p></div>
      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:14}}>
        <div className="glass glow-card metric-card alert"><div className="label">Anomalies</div><div className="value" style={{fontSize:22,color:'var(--color-red)'}}>{d.total}</div></div>
        <div className="glass glow-card metric-card"><div className="label">Total Exfil Volume</div><div className="value" style={{fontSize:22}}>{formatBytes(d.bytes)}</div></div>
      </div>
      <div className="glass glow-card"><div className="panel-head"><h3>Anomalous Transfers</h3></div><div className="panel-body">
        {d.items.map((a:any,i:number)=>(<div key={i} style={{padding:'12px 0',borderTop:i?'1px solid var(--color-border)':'none'}}>
          <div style={{display:'flex',justifyContent:'space-between',alignItems:'baseline'}}><span className="num" style={{fontSize:13,color:'var(--color-red)'}}>{a.src}</span><span className="num" style={{fontSize:13,color:'var(--color-text-dim)'}}>→ {a.dst}</span></div>
          <div style={{display:'flex',gap:16,marginTop:4,fontSize:11,color:'var(--color-text-muted)'}}>
            <span>Out: <span className="num" style={{color:'var(--color-red)'}}>{formatBytes(a.out)}</span></span>
            <span>Ratio: <span className="num">{a.ratio}:1</span></span><span>Conf: <span className="num">{a.conf}%</span></span>
          </div>
          <div style={{height:3,background:'rgba(14,230,200,.06)',borderRadius:3,marginTop:8,overflow:'hidden'}}><div style={{height:'100%',borderRadius:3,background:'var(--color-red)',opacity:.7,width:`${(a.out/mx)*100}%`}}/></div>
        </div>))}
      </div></div>
    </div>
  );
}
