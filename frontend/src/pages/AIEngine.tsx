import { Cpu, Zap } from 'lucide-react';
import { MODELS, BENCHMARK, CLASS_COLORS } from '../lib/utils';
export default function AIEngine(){
  const total=MODELS.reduce((a,b)=>a+b.caught,0);
  return (
    <div style={{display:'flex',flexDirection:'column',gap:20}}>
      <div><h2 style={{fontSize:20,fontWeight:600,display:'flex',alignItems:'center',gap:8}}><Cpu size={20} style={{color:'var(--color-violet)'}}/> AI Detection Engine</h2>
      <p style={{fontSize:13,color:'var(--color-text-dim)',marginTop:4}}>6 ML detectors · streaming inference · no decryption · no return path</p></div>
      <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(180px,1fr))',gap:14}}>
        {[['Detectors Active','6','teal'],['Total Caught',total.toString(),'text'],['Avg AUC',(MODELS.reduce((a,b)=>a+b.auc,0)/6).toFixed(4),'green'],['p50 Latency',BENCHMARK.p50_ms+' ms','text']].map(([l,v,c])=>(
          <div key={l as string} className="glass glow-card metric-card"><div className="label">{l}</div><div className="value" style={{fontSize:22,color:`var(--color-${c})`}}>{v}</div></div>
        ))}
      </div>
      <div style={{display:'flex',flexWrap:'wrap',gap:8}}>
        {['Streaming inference','No payload decryption','Read-only ingest','No return path','Bounded latency'].map(l=>(<span key={l} className="constraint"><span style={{width:5,height:5,borderRadius:'50%',background:'var(--color-green)'}}/>{l}</span>))}
      </div>
      <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(380px,1fr))',gap:16}}>
        {MODELS.map(m=>(
          <div key={m.name} className="glass glow-card" style={{overflow:'hidden'}}>
            <div style={{padding:'16px 20px',borderBottom:'1px solid var(--color-border)'}}>
              <div style={{display:'flex',alignItems:'center',gap:8}}><span style={{width:8,height:8,borderRadius:'50%',background:CLASS_COLORS[m.name]||'#6a7a8c'}}/><span style={{fontSize:14,fontWeight:600}}>{m.name}</span></div>
              <div style={{fontSize:11,color:'var(--color-text-muted)',marginTop:2}}>{m.detector} · {m.type}</div>
            </div>
            <div style={{padding:20,display:'flex',flexDirection:'column',gap:14}}>
              <p style={{fontSize:12,color:'var(--color-text-dim)',lineHeight:1.6}}>{m.desc}</p>
              {/* metrics */}
              <div style={{display:'grid',gridTemplateColumns:'1fr 1fr 1fr 1fr',gap:10}}>
                <div><div style={{fontSize:9,color:'var(--color-text-muted)',textTransform:'uppercase'}}>Test AUC</div><div className="num" style={{fontSize:14,color:'var(--color-green)',marginTop:3}}>{m.testAuc.toFixed(4)}</div></div>
                <div><div style={{fontSize:9,color:'var(--color-text-muted)',textTransform:'uppercase'}}>Accuracy</div><div className="num" style={{fontSize:14,marginTop:3}}>{(m.acc*100).toFixed(1)}%</div></div>
                <div><div style={{fontSize:9,color:'var(--color-text-muted)',textTransform:'uppercase'}}>Caught</div><div className="num" style={{fontSize:14,color:'var(--color-teal)',marginTop:3}}>{m.caught}</div></div>
                <div><div style={{fontSize:9,color:'var(--color-text-muted)',textTransform:'uppercase'}}>Seed</div><div className="num" style={{fontSize:14,marginTop:3}}>42</div></div>
              </div>
              {/* training data */}
              <div style={{padding:'10px 12px',borderRadius:8,background:'var(--color-surface-hi)',border:'1px solid var(--color-border)',fontSize:11}}>
                <div style={{color:'var(--color-text-muted)',marginBottom:4}}>Training data</div>
                <div style={{color:'var(--color-text-dim)'}}>{m.dataset}</div>
                <div style={{color:'var(--color-text-muted)',marginTop:4}}>Split: {m.split}</div>
              </div>
              {/* features */}
              <div><div style={{fontSize:10,color:'var(--color-text-muted)',textTransform:'uppercase',marginBottom:6}}>Features</div>
                <div style={{display:'flex',flexWrap:'wrap',gap:4}}>{m.features.map(f=>(<span key={f} className="num" style={{fontSize:10,padding:'2px 8px',borderRadius:100,background:'var(--color-surface-hi)',border:'1px solid var(--color-border)',color:'var(--color-text-dim)'}}>{f}</span>))}</div>
              </div>
            </div>
          </div>
        ))}
      </div>
      {/* throughput benchmark */}
      <div className="glass glow-card"><div className="panel-head"><h3><Zap size={14} style={{color:'var(--color-amber)'}}/> Measured Throughput</h3><span className="sub">Lab benchmark · {BENCHMARK.total_flows} flows</span></div>
        <div className="panel-body" style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(150px,1fr))',gap:16}}>
          {[['Sustained Peak',`${BENCHMARK.sustained_peak} flows/sec`],['p50 Latency',`${BENCHMARK.p50_ms} ms`],['p95 Latency',`${BENCHMARK.p95_ms} ms`],['p99 Latency',`${BENCHMARK.p99_ms} ms`],['Zero Drops',BENCHMARK.zero_drops?'YES':'NO'],['Return Path',BENCHMARK.return_path]].map(([k,v])=>(
            <div key={k as string}><div style={{fontSize:10,color:'var(--color-text-muted)',textTransform:'uppercase'}}>{k}</div><div className="num" style={{fontSize:16,marginTop:4,color:(v as string)==='YES'||(v as string)==='NONE'?'var(--color-green)':'var(--color-text)'}}>{v}</div></div>
          ))}
        </div></div>
    </div>
  );
}
