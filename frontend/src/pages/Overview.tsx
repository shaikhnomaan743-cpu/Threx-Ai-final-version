import { useMemo } from 'react';
import { LineChart, Line, XAxis, YAxis, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { Activity, ShieldAlert, Clock, Link2, BarChart3, Zap, Eye, ArrowRight } from 'lucide-react';
import { Link } from 'react-router-dom';
import PipelineViz from '../components/PipelineViz';
import { useLiveData } from '../hooks/useLiveData';
import { DETECTION_MIX, TOP_TALKERS } from '../lib/api';
import { CLASS_COLORS, BENCHMARK } from '../lib/utils';

export default function Overview() {
  const { metrics, alerts, paused } = useLiveData();
  const totalDet = DETECTION_MIX.reduce((a,b)=>a+b.count,0);
  const maxB = Math.max(...TOP_TALKERS.map(t=>t.bytes));
  const pieData = DETECTION_MIX.map(d=>({name:d.cls,value:d.count,color:d.color}));

  return (
    <div style={{display:'flex',flexDirection:'column',gap:20}}>

      {/* ── STATUS LINE ── */}
      <div style={{display:'flex',justifyContent:'space-between',alignItems:'center'}}>
        <h2 style={{fontSize:18,fontWeight:600,letterSpacing:'-.02em'}}>Command Center</h2>
        <div style={{display:'flex',alignItems:'center',gap:16,fontSize:12,color:'var(--color-text-dim)'}}>
          <span>Processing <span className="num" style={{color:'var(--color-teal)'}}>{Math.round(metrics.flows_per_second)}</span> flows/sec</span>
          <span>·</span>
          <span><span className="num" style={{color:'var(--color-teal)'}}>6</span> detectors active</span>
          <span>·</span>
          <span>Chain <span className="num" style={{color:'var(--color-green)'}}>#{metrics.chain_height.toLocaleString()}</span></span>
        </div>
      </div>

      {/* ── 3D HERO (smaller) ── */}
      <div className="well" style={{height:'clamp(260px,32vh,340px)'}}>
        <PipelineViz paused={paused} flowRate={metrics.flows_per_second}/>
        <div style={{position:'absolute',inset:0,zIndex:2,display:'flex',flexDirection:'column',justifyContent:'space-between',padding:'clamp(20px,3vw,32px)',pointerEvents:'none'}}>
          <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start'}}>
            <h1 style={{fontSize:'clamp(24px,3.5vw,42px)',fontWeight:700,lineHeight:.9,letterSpacing:'-.04em',textTransform:'uppercase'}}>
              Observe<br/><span style={{color:'var(--color-text-muted)'}}>Analyze</span><br/><span style={{color:'var(--color-teal)'}}>Detect</span>
            </h1>
            <div style={{display:'flex',flexDirection:'column',gap:6}}>
              {['DDoS','C2','DGA','TLS','RECON','EXFIL'].map(l=>(
                <div key={l} style={{display:'flex',alignItems:'center',gap:6,fontSize:10,letterSpacing:'.1em',color:'var(--color-text-muted)'}}>{l}<span style={{width:5,height:5,borderRadius:'50%',background:'rgba(14,230,200,.4)'}}/></div>
              ))}
            </div>
          </div>
          <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-end',fontSize:11,color:'var(--color-text-muted)'}}>
            <div style={{display:'flex',alignItems:'center',gap:6}}>
              Mirror port <span style={{width:16,height:1,background:'var(--color-text-muted)'}}/> <span style={{color:'var(--color-teal)'}}>Diode</span> <span style={{width:16,height:1,background:'var(--color-teal)'}}/> <span style={{color:'var(--color-violet)'}}>AI Pipeline</span> <span style={{width:16,height:1,background:'var(--color-violet)'}}/> <span style={{color:'var(--color-green)'}}>Ledger</span>
            </div>
          </div>
        </div>
      </div>

      {/* ── METRICS + BENCHMARK ── */}
      <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(180px,1fr))',gap:12}}>
        <MC label="Active Threats" value={metrics.active_threats.toString()} icon="⚠" alert/>
        <MC label="Flows / sec" value={BENCHMARK.sustained_peak.toString()} sub="88.6 fps lab benchmark"/>
        <MC label="Inference Latency" value={`~${metrics.detection_latency_ms.toFixed(0)}`} unit="ms" sub="p50 · streaming pipeline"/>
        <MC label="Total Detections" value={metrics.total_detections.toString()} sub={`${metrics.total_detections} in last hour`}/>
        <MC label="Diode Status" value="PASS-THRU" sub="Passive · read-only ingest" teal/>
      </div>

      {/* ── LIVE THREAT FEED + RIGHT PANEL ── */}
      <div style={{display:'grid',gridTemplateColumns:'1fr 360px',gap:16,alignItems:'start'}}>

        {/* LEFT: Threat cards with evidence */}
        <div className="glass glow-card">
          <div className="panel-head">
            <h3 style={{display:'flex',alignItems:'center',gap:8}}><ShieldAlert size={15} style={{color:'var(--color-red)'}}/> LIVE THREAT FEED <span style={{background:'var(--color-teal)',color:'var(--color-void)',fontSize:10,fontWeight:700,padding:'2px 8px',borderRadius:100,marginLeft:4}}>{alerts.length}</span></h3>
            <Link to="/threats" style={{fontSize:11.5,color:'var(--color-text-dim)'}}>All threats →</Link>
          </div>
          <div style={{maxHeight:520,overflowY:'auto'}}>
            {alerts.slice(0,8).map((a,i)=>(
              <div key={a.id} className={i===0?'slide-in':''} style={{padding:'14px 20px',borderBottom:'1px solid var(--color-border)',transition:'background .15s',cursor:'pointer'}}
                onMouseEnter={e=>(e.currentTarget.style.background='var(--color-glass)')} onMouseLeave={e=>(e.currentTarget.style.background='transparent')}>
                {/* severity + class badges */}
                <div style={{display:'flex',alignItems:'center',gap:8,marginBottom:8}}>
                  <span style={{fontSize:11,fontWeight:600,padding:'2px 8px',borderRadius:4,background:a.severity==='critical'?'rgba(240,64,80,.15)':'rgba(232,160,32,.15)',color:a.severity==='critical'?'var(--color-red)':'var(--color-amber)',textTransform:'uppercase'}}>{a.severity}</span>
                  <span style={{fontSize:11,fontWeight:600,padding:'2px 8px',borderRadius:4,background:'rgba(14,230,200,.08)',color:'var(--color-teal)',textTransform:'uppercase'}}>{a.threat_class}</span>
                  <span style={{marginLeft:'auto',fontSize:11,color:'var(--color-text-dim)'}}>{a.timestamp}</span>
                  <span className="num" style={{fontSize:11,color:'var(--color-teal)'}}>{a.confidence}%</span>
                </div>
                {/* flow ID */}
                <div className="num" style={{fontSize:13,marginBottom:6}}>{a.flow_id} <span style={{color:'var(--color-text-dim)',fontSize:11}}>{a.protocol} · {a.bytes?Math.round(a.bytes/1024)+' KB':''}</span></div>
                {/* evidence features */}
                <div style={{display:'flex',flexWrap:'wrap',gap:6}}>
                  {(a.evidence||[]).slice(0,4).map(ev=>(
                    <span key={ev.label} style={{fontSize:10,padding:'2px 8px',borderRadius:4,background:'var(--color-surface-hi)',border:'1px solid var(--color-border)',color:'var(--color-text-dim)'}}>
                      <span className="num">{ev.label}:</span> <span className="num" style={{color:'var(--color-text)'}}>{typeof ev.value==='number'?Number(ev.value).toFixed(ev.value>100?0:2):ev.value}</span>
                      {ev.contribution && <span style={{color:'var(--color-text-muted)',marginLeft:4}}>({ev.contribution}%)</span>}
                    </span>
                  ))}
                  {(a.evidence||[]).length>4 && <span style={{fontSize:10,color:'var(--color-text-muted)',padding:'2px 4px'}}>+{a.evidence.length-4} more</span>}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* RIGHT: Distribution + Top IPs + Alert Rate */}
        <div style={{display:'flex',flexDirection:'column',gap:16}}>
          {/* Threat distribution donut */}
          <div className="glass glow-card">
            <div className="panel-head"><h3>THREAT DISTRIBUTION</h3></div>
            <div className="panel-body" style={{display:'flex',alignItems:'center',gap:16}}>
              <div style={{width:100,height:100,flexShrink:0}}>
                <ResponsiveContainer><PieChart><Pie data={pieData} cx="50%" cy="50%" innerRadius={28} outerRadius={46} dataKey="value" stroke="none">{pieData.map((d,i)=><Cell key={i} fill={d.color}/>)}</Pie></PieChart></ResponsiveContainer>
              </div>
              <div style={{flex:1}}>
                {DETECTION_MIX.map(d=>(
                  <div key={d.cls} style={{display:'flex',justifyContent:'space-between',alignItems:'center',padding:'4px 0',fontSize:12}}>
                    <span style={{display:'flex',alignItems:'center',gap:6}}><span style={{width:6,height:6,borderRadius:'50%',background:d.color}}/>{d.cls}</span>
                    <span className="num" style={{color:d.color,fontWeight:600}}>{d.count}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Top source IPs */}
          <div className="glass glow-card">
            <div className="panel-head"><h3>TOP SOURCE IPs</h3><span className="sub">Traffic →</span></div>
            <div className="panel-body">
              {TOP_TALKERS.slice(0,4).map(t=>(
                <div key={t.ip} style={{display:'flex',alignItems:'center',justifyContent:'space-between',padding:'6px 0',borderBottom:'1px solid var(--color-border)',fontSize:12}}>
                  <span className="num" style={{color:t.flagged?'var(--color-red)':'var(--color-text)'}}>{t.ip}</span>
                  <div style={{display:'flex',alignItems:'center',gap:8}}>
                    <span className="num" style={{color:'var(--color-text-dim)'}}>{t.flows}</span>
                    <div style={{width:60,height:3,background:'rgba(14,230,200,.08)',borderRadius:3,overflow:'hidden'}}>
                      <div style={{height:'100%',borderRadius:3,background:t.flagged?'var(--color-red)':'var(--color-teal)',width:`${(t.bytes/maxB)*100}%`}}/>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Throughput benchmark */}
          <div className="glass glow-card">
            <div className="panel-head"><h3><Zap size={14} style={{color:'var(--color-amber)'}}/> BENCHMARK</h3></div>
            <div className="panel-body" style={{fontSize:12}}>
              {[
                ['Sustained peak',`${BENCHMARK.sustained_peak} flows/sec`],
                ['p50 latency',`${BENCHMARK.p50_ms} ms`],
                ['p99 latency',`${BENCHMARK.p99_ms} ms`],
                ['Zero drops',BENCHMARK.zero_drops?'YES':'NO'],
                ['Return path',BENCHMARK.return_path],
              ].map(([k,v])=>(
                <div key={k as string} style={{display:'flex',justifyContent:'space-between',padding:'5px 0',borderBottom:'1px solid var(--color-border)'}}>
                  <span style={{color:'var(--color-text-dim)'}}>{k}</span>
                  <span className="num" style={{fontWeight:500,color:(v as string)==='YES'||(v as string)==='NONE'?'var(--color-green)':'var(--color-text)'}}>{v}</span>
                </div>
              ))}
              <div style={{fontSize:10,color:'var(--color-text-muted)',marginTop:8}}>Tested on {BENCHMARK.total_flows} lab flows · mixed threat classes</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function MC({label,value,unit,sub,icon,alert,teal}:{label:string;value:string;unit?:string;sub?:string;icon?:string;alert?:boolean;teal?:boolean}) {
  return (
    <div className="glass glow-card metric-card" style={alert?{borderColor:'rgba(240,64,80,.2)'}:{}}>
      <div className="label" style={{display:'flex',alignItems:'center',justifyContent:'space-between'}}>
        {label} {icon&&<span>{icon}</span>}
      </div>
      <div className="value" style={{fontSize:28,...(alert?{color:'var(--color-red)'}:teal?{color:'var(--color-teal)'}:{})}}>
        {value}{unit&&<span>{unit}</span>}
      </div>
      {sub&&<div style={{fontSize:11,color:'var(--color-text-dim)',marginTop:6,position:'relative'}}>{sub}</div>}
    </div>
  );
}
