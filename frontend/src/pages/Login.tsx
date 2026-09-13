import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, ArrowRight, Eye, EyeOff, AlertTriangle } from 'lucide-react';

// Credentials: analyst@threx.ai / ThrexAI@2026
const VALID_EMAIL = 'analyst@threx.ai';
const VALID_PASS = 'ThrexAI@2026';

export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPw, setShowPw] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const nav = useNavigate();

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !password) { setError('Please enter your credentials'); return; }
    setLoading(true); setError('');
    setTimeout(() => {
      if (email === VALID_EMAIL && password === VALID_PASS) {
        localStorage.setItem('threx_auth', 'true');
        localStorage.setItem('threx_user', JSON.stringify({ name: 'Analyst', email: VALID_EMAIL, role: 'SOC Analyst' }));
        nav('/');
      } else {
        setError('Invalid credentials. Access denied.');
        setLoading(false);
      }
    }, 1000);
  };

  return (
    <div style={{minHeight:'100vh',display:'flex',position:'relative',overflow:'hidden',background:'var(--color-void)'}}>
      {/* ambient */}
      <div style={{position:'absolute',inset:0,background:'radial-gradient(ellipse 60% 50% at 50% 40%,rgba(14,230,200,.025) 0%,transparent 70%)',pointerEvents:'none'}}/>

      {/* Left panel - branding */}
      <div style={{flex:1,display:'flex',flexDirection:'column',justifyContent:'center',alignItems:'center',padding:48,position:'relative',zIndex:1}}>
        <div style={{maxWidth:400}}>
          <div style={{display:'flex',alignItems:'center',gap:14,marginBottom:32}}>
            <div style={{width:48,height:48,borderRadius:14,background:'linear-gradient(135deg,var(--color-teal),var(--color-cyan))',display:'flex',alignItems:'center',justifyContent:'center',boxShadow:'0 0 32px rgba(14,230,200,.2)'}}>
              <Shield size={24} color="#080c10" strokeWidth={2.5}/>
            </div>
            <div>
              <div style={{fontSize:22,fontWeight:700,letterSpacing:'-.03em'}}>THREX AI</div>
              <div style={{fontSize:10,color:'var(--color-teal)',letterSpacing:'.12em'}}>OBSERVE · ANALYZE · DETECT</div>
            </div>
          </div>
          <h2 style={{fontSize:28,fontWeight:700,letterSpacing:'-.03em',lineHeight:1.2}}>Secure access to<br/><span style={{color:'var(--color-teal)'}}>Threat Intelligence</span></h2>
          <p style={{fontSize:13,color:'var(--color-text-dim)',lineHeight:1.7,marginTop:16}}>
            AI-powered passive threat detection for critical infrastructure networks.
            Unidirectional monitoring — the network cannot see the sensor.
          </p>

          {/* constraint badges */}
          <div style={{display:'flex',flexWrap:'wrap',gap:8,marginTop:24}}>
            {['Passive','Read-only','No decryption','Streaming','Tamper-evident'].map(c=>(
              <span key={c} style={{fontSize:10,padding:'4px 10px',borderRadius:100,border:'1px solid var(--color-border)',color:'var(--color-text-dim)'}}>{c}</span>
            ))}
          </div>
        </div>
      </div>

      {/* Right panel - form */}
      <div style={{width:440,display:'flex',alignItems:'center',justifyContent:'center',padding:48,borderLeft:'1px solid var(--color-border)',background:'linear-gradient(180deg,rgba(13,17,23,.95),rgba(10,15,20,.98))',position:'relative',zIndex:1}}>
        <div style={{width:'100%',maxWidth:340}}>
          <h3 style={{fontSize:18,fontWeight:600,marginBottom:8}}>Sign in</h3>
          <p style={{fontSize:12,color:'var(--color-text-dim)',marginBottom:28}}>Enter your credentials to access the command center</p>

          <form onSubmit={submit} style={{display:'flex',flexDirection:'column',gap:20}}>
            <div>
              <label style={{fontSize:11,color:'var(--color-text-dim)',textTransform:'uppercase',letterSpacing:'.04em',display:'block',marginBottom:6}}>Email address</label>
              <input type="email" value={email} onChange={e=>setEmail(e.target.value)} placeholder="analyst@threx.ai"
                style={{width:'100%',height:42,padding:'0 14px',borderRadius:10,background:'var(--color-surface-hi)',border:'1px solid var(--color-border)',color:'var(--color-text)',fontSize:13,outline:'none',boxSizing:'border-box',transition:'border-color .2s'}}
                onFocus={e=>e.target.style.borderColor='rgba(14,230,200,.3)'} onBlur={e=>e.target.style.borderColor='var(--color-border)'}/>
            </div>
            <div>
              <label style={{fontSize:11,color:'var(--color-text-dim)',textTransform:'uppercase',letterSpacing:'.04em',display:'block',marginBottom:6}}>Password</label>
              <div style={{position:'relative'}}>
                <input type={showPw?'text':'password'} value={password} onChange={e=>setPassword(e.target.value)} placeholder="••••••••"
                  style={{width:'100%',height:42,padding:'0 42px 0 14px',borderRadius:10,background:'var(--color-surface-hi)',border:'1px solid var(--color-border)',color:'var(--color-text)',fontSize:13,outline:'none',boxSizing:'border-box',transition:'border-color .2s'}}
                  onFocus={e=>e.target.style.borderColor='rgba(14,230,200,.3)'} onBlur={e=>e.target.style.borderColor='var(--color-border)'}/>
                <button type="button" onClick={()=>setShowPw(!showPw)} style={{position:'absolute',right:12,top:'50%',transform:'translateY(-50%)',color:'var(--color-text-muted)'}}>
                  {showPw?<EyeOff size={16}/>:<Eye size={16}/>}
                </button>
              </div>
            </div>

            {error && <div style={{display:'flex',alignItems:'center',gap:8,fontSize:12,color:'var(--color-red)',padding:'8px 12px',borderRadius:8,background:'rgba(240,64,80,.06)',border:'1px solid rgba(240,64,80,.15)'}}><AlertTriangle size={14}/>{error}</div>}

            <button type="submit" disabled={loading} className="btn btn-primary" style={{width:'100%',height:44,display:'flex',alignItems:'center',justifyContent:'center',gap:8,fontSize:14,borderRadius:10,opacity:loading?.6:1}}>
              {loading ? 'Authenticating...' : <><span>Sign in</span><ArrowRight size={16}/></>}
            </button>
          </form>

          <div style={{marginTop:24,padding:'12px 14px',borderRadius:10,background:'var(--color-surface-hi)',border:'1px solid var(--color-border)',fontSize:11,color:'var(--color-text-muted)'}}>
            <div style={{color:'var(--color-text-dim)',marginBottom:4,fontWeight:500}}>Authorized personnel only</div>
            All sessions are logged. Unauthorized access attempts are recorded and reported.
          </div>
        </div>
      </div>
    </div>
  );
}
