import { useState } from 'react';
import { FileText, Download } from 'lucide-react';
const CLS=['All','DDoS','C2 Beaconing','DGA','TLS Malware','Recon','Exfiltration'];
export default function Reports(){
  const [fmt,setFmt]=useState('JSON');
  const [cls,setCls]=useState('All');
  const [sev,setSev]=useState('All');
  const [lim,setLim]=useState(100);
  const [gen,setGen]=useState(false);
  const [done,setDone]=useState(false);
  const go=()=>{setGen(true);setDone(false);setTimeout(()=>{setGen(false);setDone(true)},1500)};
  return (
    <div style={{display:'flex',flexDirection:'column',gap:20}}>
      <div><h2 style={{fontSize:20,fontWeight:600,display:'flex',alignItems:'center',gap:8}}><FileText size={20}/> Report Generator</h2>
      <p style={{fontSize:13,color:'var(--color-text-dim)',marginTop:4}}>Export threat reports in standardized alert schema format</p></div>
      <div className="glass glow-card" style={{maxWidth:520,padding:24,display:'flex',flexDirection:'column',gap:18}}>
        <div><div style={{fontSize:11,color:'var(--color-text-dim)',textTransform:'uppercase',letterSpacing:'.04em',marginBottom:8}}>Format</div>
          <div style={{display:'flex',gap:6}}>{['JSON','CSV'].map(f=>(<button key={f} className={`filter-chip ${fmt===f?'active':''}`} onClick={()=>setFmt(f)}>{f}</button>))}</div></div>
        <div><div style={{fontSize:11,color:'var(--color-text-dim)',textTransform:'uppercase',letterSpacing:'.04em',marginBottom:8}}>Threat Class</div>
          <div style={{display:'flex',flexWrap:'wrap',gap:6}}>{CLS.map(c=>(<button key={c} className={`filter-chip ${cls===c?'active':''}`} onClick={()=>setCls(c)}>{c}</button>))}</div></div>
        <div><div style={{fontSize:11,color:'var(--color-text-dim)',textTransform:'uppercase',letterSpacing:'.04em',marginBottom:8}}>Severity</div>
          <div style={{display:'flex',gap:6}}>{['All','Critical','High','Medium'].map(s=>(<button key={s} className={`filter-chip ${sev===s?'active':''}`} onClick={()=>setSev(s)}>{s}</button>))}</div></div>
        <div><div style={{fontSize:11,color:'var(--color-text-dim)',textTransform:'uppercase',letterSpacing:'.04em',marginBottom:8}}>Limit</div>
          <input type="number" value={lim} onChange={e=>setLim(+e.target.value)} style={{height:32,padding:'0 12px',borderRadius:8,background:'var(--color-surface-hi)',border:'1px solid var(--color-border)',color:'var(--color-text)',fontSize:13,width:80,outline:'none'}}/></div>
        <div style={{fontSize:11,color:'var(--color-text-dim)',padding:'8px 12px',borderRadius:8,background:'var(--color-surface-hi)',border:'1px solid var(--color-border)'}}>
          Export includes: timestamp, flow_id, threat_class, confidence, evidence
        </div>
        <button onClick={go} disabled={gen} className="btn btn-primary" style={{alignSelf:'flex-start',display:'flex',alignItems:'center',gap:6,opacity:gen?.6:1}}>
          {gen?'Generating…':<><Download size={14}/> Generate report</>}</button>
        {done&&<div className="fade-in" style={{fontSize:12,color:'var(--color-green)'}}>✓ Report ready — {fmt} · {cls} · {sev} · {lim} records</div>}
      </div>
    </div>
  );
}
