import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Login from './pages/Login';
import Overview from './pages/Overview';
import Threats from './pages/Threats';
import ThreatDetail from './pages/ThreatDetail';
import Traffic from './pages/Traffic';
import DNS from './pages/DNS';
import TLS from './pages/TLS';
import Recon from './pages/Recon';
import Exfil from './pages/Exfil';
import Alerts from './pages/Alerts';
import Reports from './pages/Reports';
import AIEngine from './pages/AIEngine';
import System from './pages/System';
import NotFound from './pages/NotFound';

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login/>}/>
        <Route element={<Layout/>}>
          <Route index element={<Overview/>}/>
          <Route path="overview" element={<Overview/>}/>
          <Route path="threats" element={<Threats/>}/>
          <Route path="threats/:id" element={<ThreatDetail/>}/>
          <Route path="traffic" element={<Traffic/>}/>
          <Route path="dns" element={<DNS/>}/>
          <Route path="tls" element={<TLS/>}/>
          <Route path="recon" element={<Recon/>}/>
          <Route path="exfil" element={<Exfil/>}/>
          <Route path="alerts" element={<Alerts/>}/>
          <Route path="reports" element={<Reports/>}/>
          <Route path="ai-engine" element={<AIEngine/>}/>
          <Route path="system" element={<System/>}/>
          <Route path="*" element={<NotFound/>}/>
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
