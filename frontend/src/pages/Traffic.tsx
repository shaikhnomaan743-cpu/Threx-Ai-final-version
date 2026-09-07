import { useState, useEffect } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip } from 'recharts';
import { Activity } from 'lucide-react';
import { fetchTraffic } from '../lib/api';
const COLORS=['#0ee6c8','#8060f0','#20c070','#e8a020','#f04050'];
export default function Traffic(){
  const [s,setS]=useState<any>(null);
  useEffect(()=>{fetchTraffic().then(setS)},[]);
  if(!s) return <div style={{display:'flex',alignItems:'center',justifyContent:'center',height:260,color:'var(--color-text-muted)'}}>Loading…</div>;
  const pd=Object.entries(s.protocols).map(([n,v])=>({name:n,value:v as number}));
  return (
    <div style={{display:'flex',flexDirection:'column',gap:20}}>
      <div><h2 style={{fontSize:20,fontWeight:600,display:'flex',alignItems:'center',gap:8}}><Activity size={20} style={{color:'var(--color-teal)'}}/> Traffic Analytics</h2>
      <p style={{fontSize:13,color:'var(--color-text-dim)',marginTop:4}}>Protocol distribution and flow statistics — passive feed only</p></div>
      <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(180px,1fr))',gap:14}}>
        {[['Total flows',s.flows.toLocaleString()],['Total bytes',(s.bytes/1e9).toFixed(2)+' GB'],['Avg flow duration',s.avg_dur.toFixed(1)+'s'],['Protocols',Object.keys(s.protocols).length]].map(([l,v])=>(
          <div key={l as string} className="glass glow-card metric-card"><div className="label">{l}</div><div className="value" style={{fontSize:22}}>{v}</div></div>
        ))}
      </div>
      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16}}>
        <div className="glass glow-card"><div className="panel-head"><h3>Protocol Distribution</h3></div>
          <div className="panel-body" style={{display:'flex',alignItems:'center',gap:24}}>
            <div style={{width:150,height:150}}><ResponsiveContainer><PieChart><Pie data={pd} cx="50%" cy="50%" innerRadius={38} outerRadius={65} dataKey="value" stroke="none">{pd.map((_,i)=><Cell key={i} fill={COLORS[i%COLORS.length]}/>)}</Pie></PieChart></ResponsiveContainer></div>
            <div style={{display:'flex',flexDirection:'column',gap:6}}>{pd.map((p,i)=>(
              <div key={p.name} style={{display:'flex',alignItems:'center',gap:8,fontSize:13}}><span style={{width:8,height:8,borderRadius:'50%',background:COLORS[i%COLORS.length]}}/><span style={{color:'var(--color-text-dim)',width:36}}>{p.name}</span><span className="num">{p.value}%</span></div>
            ))}</div>
          </div>
        </div>
        <div className="glass glow-card"><div className="panel-head"><h3>Protocol Volume</h3></div>
          <div className="panel-body" style={{height:180}}><ResponsiveContainer><BarChart data={pd}><XAxis dataKey="name" tick={{fill:'#6a7a8c',fontSize:11}} axisLine={false} tickLine={false}/><YAxis hide/><Tooltip contentStyle={{background:'#141b22',border:'1px solid rgba(14,230,200,.1)',borderRadius:8,fontSize:12,color:'#d4dce6'}}/><Bar dataKey="value" radius={[6,6,0,0]}>{pd.map((_,i)=><Cell key={i} fill={COLORS[i%COLORS.length]}/>)}</Bar></BarChart></ResponsiveContainer></div>
        </div>
      </div>
    </div>
  );
}
