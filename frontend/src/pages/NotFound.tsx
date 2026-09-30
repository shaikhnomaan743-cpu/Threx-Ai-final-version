import { Link } from 'react-router-dom';
import { Shield } from 'lucide-react';
export default function NotFound(){
  return (
    <div style={{display:'flex',flexDirection:'column',alignItems:'center',justifyContent:'center',height:'60vh',textAlign:'center'}}>
      <Shield size={48} style={{color:'var(--color-text-muted)',marginBottom:16}}/>
      <h2 style={{fontSize:24,fontWeight:600}}>404 — Sector not found</h2>
      <p style={{fontSize:13,color:'var(--color-text-dim)',marginTop:8}}>This route doesn't exist in the THREX AI perimeter.</p>
      <Link to="/" className="btn btn-primary" style={{marginTop:24,display:'inline-flex',alignItems:'center'}}>Return to Overview</Link>
    </div>
  );
}
