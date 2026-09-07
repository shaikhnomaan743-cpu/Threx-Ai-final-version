import { useState, useEffect } from 'react';
import { ShieldAlert, Search, Eye } from 'lucide-react';
import { Link, useSearchParams } from 'react-router-dom';
import { fetchThreats } from '../lib/api';
import type { Alert, Severity, ThreatClass } from '../lib/types';
import { CLASS_COLORS } from '../lib/utils';

const SEVS: Severity[] = ['critical','high','medium'];
const CLS: ThreatClass[] = ['DDoS','C2 Beaconing','DGA','TLS Malware','Recon','Exfiltration'];

export default function Threats() {
  const [data, setData] = useState<Alert[]>([]);
  const [sf, setSf] = useState<Severity|'all'>('all');
  const [cf, setCf] = useState<ThreatClass|'all'>('all');
  const [sp] = useSearchParams();
  const [q, setQ] = useState(sp.get('q')||'');
  useEffect(()=>{fetchThreats(100).then(setData)},[]);

  const filtered = data.filter(t=>{
    if(sf!=='all'&&t.severity!==sf) return false;
    if(cf!=='all'&&t.threat_class!==cf) return false;
    if(q&&!(t.source_ip||"").includes(q)&&!(t.destination_ip||"").includes(q)&&!(t.threat_class||"").toLowerCase().includes(q.toLowerCase())&&!(t.flow_id||"").toLowerCase().includes(q.toLowerCase())) return false;
    return true;
  });

  return (
    <div style={{display:'flex',flexDirection:'column',gap:20}}>
      <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-end',flexWrap:'wrap',gap:16}}>
        <div>
          <h2 style={{fontSize:20,fontWeight:600,display:'flex',alignItems:'center',gap:8}}><ShieldAlert size={20} style={{color:'var(--color-red)'}}/> All threats</h2>
          <p style={{fontSize:13,color:'var(--color-text-dim)',marginTop:4}}>{filtered.length} detections across {CLS.length} classes</p>
        </div>
        <div style={{position:'relative'}}>
          <Search size={14} style={{position:'absolute',left:10,top:'50%',transform:'translateY(-50%)',color:'var(--color-text-muted)'}}/>
          <input value={q} onChange={e=>setQ(e.target.value)} placeholder="Search IPs, class, flow..."
            style={{height:32,paddingLeft:32,paddingRight:12,borderRadius:100,background:'var(--color-surface-hi)',border:'1px solid var(--color-border)',color:'var(--color-text)',fontSize:12,width:220,outline:'none'}}/>
        </div>
      </div>
      <div style={{display:'flex',flexWrap:'wrap',gap:6}}>
        <button className={`filter-chip ${sf==='all'?'active':''}`} onClick={()=>setSf('all')}>All</button>
        {SEVS.map(s=><button key={s} className={`filter-chip ${sf===s?'active':''}`} onClick={()=>setSf(s)}>{s.charAt(0).toUpperCase()+s.slice(1)}</button>)}
        <span style={{width:1,height:24,background:'var(--color-border)',alignSelf:'center',margin:'0 4px'}}/>
        {CLS.map(c=><button key={c} className={`filter-chip ${cf===c?'active':''}`} onClick={()=>setCf(c)}>{c}</button>)}
      </div>
      <div className="glass glow-card" style={{overflow:'hidden'}}>
        <div style={{overflowX:'auto'}}>
          <table className="tbl">
            <thead><tr><th style={{width:90}}>Time</th><th style={{width:90}}>Severity</th><th>Class</th><th>Flow ID</th><th>Protocol</th><th style={{width:100}}>Confidence</th><th style={{width:60}}>Block</th><th style={{width:50}}></th></tr></thead>
            <tbody>
              {filtered.map((a,i)=>(
                <tr key={a.id} className={i<3?'slide-in':''}>
                  <td className="num" style={{fontSize:12,color:'var(--color-text-dim)'}}>{a.timestamp}</td>
                  <td><span style={{fontSize:11,fontWeight:600,padding:'2px 8px',borderRadius:4,background:a.severity==='critical'?'rgba(240,64,80,.15)':'rgba(232,160,32,.15)',color:a.severity==='critical'?'var(--color-red)':'var(--color-amber)',textTransform:'uppercase'}}>{a.severity}</span></td>
                  <td><span style={{display:'flex',alignItems:'center',gap:6,fontSize:12}}><span style={{width:6,height:6,borderRadius:'50%',background:CLASS_COLORS[a.threat_class]||'#6a7a8c'}}/>{a.threat_class}</span></td>
                  <td className="num" style={{fontSize:11.5}}>{a.flow_id}</td>
                  <td style={{fontSize:12,color:'var(--color-text-dim)'}}>{a.protocol}</td>
                  <td><span className="conf"><span className="num" style={{fontSize:12}}>{a.confidence}%</span><span className="confbar"><i className="fill-teal" style={{width:`${a.confidence}%`}}/></span></span></td>
                  <td className="num" style={{fontSize:11,color:'var(--color-green)'}}>#{a.block_height?.toLocaleString()}</td>
                  <td><Link to={`/threats/${a.id}`} style={{color:'var(--color-teal)',display:'flex',alignItems:'center'}}><Eye size={15}/></Link></td>
                </tr>
              ))}
              {filtered.length===0&&<tr><td colSpan={8} style={{textAlign:'center',color:'var(--color-text-muted)',padding:48}}>No threats match</td></tr>}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
