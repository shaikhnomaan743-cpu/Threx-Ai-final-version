import { useState, useEffect } from 'react';
import { Lock, ShieldX } from 'lucide-react';
import { fetchTLS } from '../lib/api';
export default function TLS(){
  const [d,setD]=useState<any>(null);
  useEffect(()=>{fetchTLS().then(setD)},[]);
  if(!d) return <div style={{display:'flex',alignItems:'center',justifyContent:'center',height:260,color:'var(--color-text-muted)'}}>Loading…</div>;
  return (
    <div style={{display:'flex',flexDirection:'column',gap:20}}>
      <div><h2 style={{fontSize:20,fontWeight:600,display:'flex',alignItems:'center',gap:8}}><Lock size={20} style={{color:'var(--color-cyan)'}}/> TLS/QUIC Analytics</h2>
      <p style={{fontSize:13,color:'var(--color-text-dim)',marginTop:4}}>Malware detection from JA3/JA4 fingerprints and packet-size sequences</p></div>
      <div style={{display:'flex',alignItems:'center',gap:10,padding:'10px 16px',borderRadius:12,background:'rgba(14,230,200,.04)',border:'1px solid rgba(14,230,200,.1)',fontSize:12,color:'var(--color-teal)'}}><Lock size={14}/> No payload decryption — all analysis from TLS/QUIC metadata only (extensions, ciphers, curves, record sizes)</div>
      <div style={{display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:14}}>
        {[['TLS Sessions',d.sessions,false],['Malware Flagged',d.malware,true],['Unique JA3',d.ja3,false]].map(([l,v,a])=>(
          <div key={l as string} className={`glass glow-card metric-card ${a?'alert':''}`}><div className="label">{l}</div><div className="value" style={{fontSize:22,...(a?{color:'var(--color-red)'}:{})}}>{v as any}</div></div>
        ))}
      </div>
      <div className="glass glow-card"><div className="panel-head"><h3><ShieldX size={14} style={{color:'var(--color-red)'}}/> Suspicious JA3 Fingerprints</h3></div>
        <div style={{overflowX:'auto'}}><table className="tbl"><thead><tr><th>JA3 Hash</th><th>Extensions</th><th>Ciphers</th><th>Verdict</th><th>Confidence</th></tr></thead><tbody>
          {d.prints.map((f:any,i:number)=>(<tr key={i}><td className="num" style={{fontSize:11,color:'var(--color-text-dim)',maxWidth:180,overflow:'hidden',textOverflow:'ellipsis'}}>{f.hash}</td><td className="num" style={{fontSize:12}}>{f.ext}</td><td className="num" style={{fontSize:12}}>{f.ciphers}</td><td style={{fontSize:12,fontWeight:500,color:f.verdict==='Malware'?'var(--color-red)':'var(--color-amber)'}}>{f.verdict}</td><td><span className="conf"><span className="num" style={{fontSize:12}}>{f.conf}%</span><span className="confbar"><i className="fill-teal" style={{width:`${f.conf}%`}}/></span></span></td></tr>))}
        </tbody></table></div></div>
    </div>
  );
}
