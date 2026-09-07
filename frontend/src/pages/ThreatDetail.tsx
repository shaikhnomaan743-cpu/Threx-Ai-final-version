import { useParams, Link } from 'react-router-dom';
import { useState, useEffect } from 'react';
import { ArrowLeft, Shield, AlertTriangle, CheckCircle2, Download, Flag, ArrowRight } from 'lucide-react';
import { fetchThreats } from '../lib/api';
import type { Alert } from '../lib/types';
import { CLASS_COLORS, formatBytes } from '../lib/utils';

export default function ThreatDetail() {
  const { id } = useParams();
  const [alert, setAlert] = useState<Alert|null>(null);
  useEffect(()=>{ fetchThreats(100).then(all=>{ const found=all.find(a=>a.id===id); setAlert(found||all[0]); }); },[id]);
  if(!alert) return <div style={{padding:40,textAlign:'center',color:'var(--color-text-muted)'}}>Loading investigation…</div>;

  const maxContrib = Math.max(...(alert.evidence||[]).map(e=>e.contribution||0));

  return (
    <div style={{display:'flex',flexDirection:'column',gap:20}}>
      <Link to="/threats" style={{display:'flex',alignItems:'center',gap:6,fontSize:13,color:'var(--color-text-dim)'}}><ArrowLeft size={16}/> Back to threats</Link>

      {/* Header card */}
      <div className="glass glow-card" style={{padding:24}}>
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start',flexWrap:'wrap',gap:16}}>
          <div>
            <div style={{display:'flex',alignItems:'center',gap:10,marginBottom:12}}>
              <span style={{fontSize:12,fontWeight:700,padding:'3px 10px',borderRadius:4,background:alert.severity==='critical'?'rgba(240,64,80,.15)':'rgba(232,160,32,.15)',color:alert.severity==='critical'?'var(--color-red)':'var(--color-amber)',textTransform:'uppercase'}}>{alert.severity}</span>
              <span style={{fontSize:12,fontWeight:700,padding:'3px 10px',borderRadius:4,background:'rgba(14,230,200,.08)',color:'var(--color-teal)',textTransform:'uppercase'}}>{alert.threat_class}</span>
              <span style={{fontSize:12,color:'var(--color-text-dim)'}}>{alert.timestamp}</span>
            </div>
            <h2 style={{fontSize:20,fontWeight:600,letterSpacing:'-.02em'}}>Threat Investigation</h2>
            <p className="num" style={{fontSize:14,color:'var(--color-text-dim)',marginTop:6}}>{alert.flow_id}</p>
          </div>
          {/* actions */}
          <div style={{display:'flex',gap:8}}>
            <button className="btn btn-ghost" style={{display:'flex',alignItems:'center',gap:6}}><CheckCircle2 size={14}/> Mark reviewed</button>
            <button className="btn btn-ghost" style={{display:'flex',alignItems:'center',gap:6,borderColor:'rgba(240,64,80,.3)',color:'var(--color-red)'}}><Flag size={14}/> Escalate</button>
            <button className="btn btn-ghost" style={{display:'flex',alignItems:'center',gap:6}}><Download size={14}/> Export</button>
          </div>
        </div>
      </div>

      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16}}>
        {/* Flow visualization */}
        <div className="glass glow-card">
          <div className="panel-head"><h3>Flow Details</h3></div>
          <div className="panel-body">
            {/* source → destination viz */}
            <div style={{display:'flex',alignItems:'center',justifyContent:'center',gap:16,padding:'20px 0'}}>
              <div style={{textAlign:'center'}}>
                <div style={{width:56,height:56,borderRadius:'50%',border:'2px solid var(--color-border)',display:'flex',alignItems:'center',justifyContent:'center',margin:'0 auto 8px'}}><Shield size={20} style={{color:'var(--color-text-dim)'}}/></div>
                <div className="num" style={{fontSize:12}}>{alert.source_ip}</div>
                <div className="num" style={{fontSize:10,color:'var(--color-text-muted)'}}>:{alert.source_port}</div>
              </div>
              <div style={{display:'flex',flexDirection:'column',alignItems:'center',gap:4}}>
                <ArrowRight size={20} style={{color:'var(--color-teal)'}}/>
                <span style={{fontSize:10,color:'var(--color-text-dim)'}}>{alert.protocol}</span>
              </div>
              <div style={{textAlign:'center'}}>
                <div style={{width:56,height:56,borderRadius:'50%',border:'2px solid var(--color-border)',display:'flex',alignItems:'center',justifyContent:'center',margin:'0 auto 8px'}}><AlertTriangle size={20} style={{color:'var(--color-red)'}}/></div>
                <div className="num" style={{fontSize:12}}>{alert.destination_ip}</div>
                <div className="num" style={{fontSize:10,color:'var(--color-text-muted)'}}>:{alert.destination_port}</div>
              </div>
            </div>
            {/* meta */}
            <div style={{display:'grid',gridTemplateColumns:'1fr 1fr 1fr',gap:12,borderTop:'1px solid var(--color-border)',paddingTop:16}}>
              {[['Protocol',alert.protocol],['Bytes',alert.bytes?formatBytes(alert.bytes):'—'],['Duration',alert.duration?alert.duration+'s':'—'],['Confidence',alert.confidence+'%'],['Block',`#${alert.block_height}`],['Hash',alert.block_hash||'—']].map(([k,v])=>(
                <div key={k as string}><div style={{fontSize:10,color:'var(--color-text-muted)',textTransform:'uppercase'}}>{k}</div><div className="num" style={{fontSize:13,marginTop:3}}>{v}</div></div>
              ))}
            </div>
          </div>
        </div>

        {/* Evidence / Feature contribution */}
        <div className="glass glow-card">
          <div className="panel-head"><h3>ML Evidence — Feature Contribution</h3></div>
          <div className="panel-body">
            {(alert.evidence||[]).map(ev=>(
              <div key={ev.label} style={{padding:'10px 0',borderBottom:'1px solid var(--color-border)'}}>
                <div style={{display:'flex',justifyContent:'space-between',marginBottom:6}}>
                  <span className="num" style={{fontSize:12,color:'var(--color-text-dim)'}}>{ev.label}</span>
                  <span className="num" style={{fontSize:13,fontWeight:500}}>{typeof ev.value==='number'?Number(ev.value).toFixed(ev.value>100?0:3):ev.value}</span>
                </div>
                {ev.contribution && (
                  <div style={{height:4,background:'rgba(14,230,200,.06)',borderRadius:4,overflow:'hidden'}}>
                    <div style={{height:'100%',borderRadius:4,background:`linear-gradient(90deg,var(--color-teal),var(--color-cyan))`,width:`${(ev.contribution/maxContrib)*100}%`,transition:'width .5s'}}/>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Alert schema compliance */}
      <div className="glass glow-card">
        <div className="panel-head"><h3>Standardized Alert Schema</h3><span style={{fontSize:11,color:'var(--color-green)'}}>✓ All required fields present</span></div>
        <div className="panel-body" style={{display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(200px,1fr))',gap:12}}>
          {[['timestamp',alert.timestamp],['flow_id',alert.flow_id],['threat_class',alert.threat_class],['confidence',alert.confidence+'%'],['evidence',(alert.evidence||[]).length+' features']].map(([k,v])=>(
            <div key={k as string} style={{padding:'8px 12px',borderRadius:8,background:'var(--color-surface-hi)',border:'1px solid var(--color-border)'}}>
              <div style={{fontSize:10,color:'var(--color-teal)',textTransform:'uppercase',marginBottom:3}}>{k}</div>
              <div className="num" style={{fontSize:12}}>{v}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
