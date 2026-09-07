import { useState } from 'react';
import { Bell } from 'lucide-react';
import { Link } from 'react-router-dom';
import { useLiveData } from '../hooks/useLiveData';
import { Eye } from 'lucide-react';
export default function Alerts(){
  const {alerts}=useLiveData();
  const [co,setCo]=useState(false);
  const f=co?alerts.filter(a=>a.severity==='critical'):alerts;
  return (
    <div style={{display:'flex',flexDirection:'column',gap:20}}>
      <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-end',flexWrap:'wrap',gap:16}}>
        <div><h2 style={{fontSize:20,fontWeight:600,display:'flex',alignItems:'center',gap:8}}><Bell size={20} style={{color:'var(--color-amber)'}}/> Alert Center</h2>
        <p style={{fontSize:13,color:'var(--color-text-dim)',marginTop:4}}>Live feed — {f.length} alerts{co?' (critical)':''}</p></div>
        <button className={`filter-chip ${co?'active':''}`} onClick={()=>setCo(!co)}>{co?'Show all':'Critical only'}</button>
      </div>
      <div className="glass glow-card"><div style={{overflowX:'auto'}}>
        <table className="tbl"><thead><tr><th>Time</th><th>Severity</th><th>Class</th><th>Flow ID</th><th>Confidence</th><th>Evidence</th><th></th></tr></thead><tbody>
          {f.map((a,i)=>(<tr key={a.id} className={i===0?'slide-in':''}>
            <td className="num" style={{fontSize:12,color:'var(--color-text-dim)'}}>{a.timestamp}</td>
            <td><span style={{fontSize:11,fontWeight:600,padding:'2px 8px',borderRadius:4,background:a.severity==='critical'?'rgba(240,64,80,.15)':'rgba(232,160,32,.15)',color:a.severity==='critical'?'var(--color-red)':'var(--color-amber)',textTransform:'uppercase'}}>{a.severity}</span></td>
            <td style={{fontSize:12}}>{a.threat_class}</td>
            <td className="num" style={{fontSize:11}}>{a.flow_id}</td>
            <td><span className="conf"><span className="num" style={{fontSize:12}}>{a.confidence}%</span><span className="confbar"><i className="fill-teal" style={{width:`${a.confidence}%`}}/></span></span></td>
            <td style={{fontSize:10,color:'var(--color-text-dim)'}}>{(a.evidence||[]).slice(0,2).map(e=>e.label).join(', ')}</td>
            <td><Link to={`/threats/${a.id}`} style={{color:'var(--color-teal)'}}><Eye size={14}/></Link></td>
          </tr>))}
        </tbody></table></div></div>
      <div className="glass glow-card"><div className="panel-head"><h3>Standardized Alert Schema</h3><span style={{fontSize:11,color:'var(--color-green)'}}>✓ All 5 required fields</span></div><div className="panel-body" style={{display:'flex',flexWrap:'wrap',gap:6}}>
        {['timestamp','flow_id','threat_class','confidence','evidence'].map(f=>(
          <span key={f} style={{display:'flex',alignItems:'center',gap:6,height:26,padding:'0 10px',borderRadius:100,background:'var(--color-surface-hi)',border:'1px solid var(--color-border)',fontSize:11}}><span style={{width:4,height:4,borderRadius:'50%',background:'var(--color-teal)'}}/><span className="num" style={{color:'var(--color-text-dim)'}}>{f}</span></span>
        ))}
      </div></div>
    </div>
  );
}
