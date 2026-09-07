import React, { useState } from 'react';
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom';
import {
  LayoutDashboard,
  ShieldAlert,
  Activity,
  Globe,
  Lock,
  Search,
  ArrowUpFromLine,
  Bell,
  Cpu,
  FileText,
  Server,
  Menu,
  Shield,
  User,
  LogOut,
  ChevronLeft,
  ChevronRight
} from 'lucide-react';
import { useLiveData } from '../hooks/useLiveData';

const MONITORING = [
  { to: '/', label: 'Overview', icon: LayoutDashboard },
  { to: '/traffic', label: 'Traffic Analytics', icon: Activity },
  { to: '/dns', label: 'DNS Analytics', icon: Globe },
  { to: '/tls', label: 'TLS/QUIC Analytics', icon: Lock },
];

const DETECTION = [
  { to: '/threats', label: 'Threats & Alerts', icon: ShieldAlert },
  { to: '/recon', label: 'Reconnaissance', icon: Search },
  { to: '/exfil', label: 'Exfiltration', icon: ArrowUpFromLine },
  { to: '/alerts', label: 'Alert Center', icon: Bell },
];

const SYSTEM_NAV = [
  { to: '/ai-engine', label: 'AI Detection Engine', icon: Cpu },
  { to: '/reports', label: 'Reports', icon: FileText },
  { to: '/system', label: 'System', icon: Server },
];

const CONSTRAINTS = [
  { label: 'Read-Only Ingest', ok: true, val: 'ENABLED' },
  { label: 'Payload Decryption', ok: false, val: 'DISABLED' },
  { label: 'Return Path', ok: false, val: 'NONE' },
  { label: 'Inline Blocking', ok: false, val: 'DISABLED' },
  { label: 'Streaming Engine', ok: true, val: 'ACTIVE' },
  { label: 'Data Retention', ok: true, val: 'ACTIVE' },
];

export default function Layout() {
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  
  const nav = useNavigate();
  const { paused, togglePause, backendUp } = useLiveData();

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchQuery.trim()) {
      nav(`/threats?q=${encodeURIComponent(searchQuery.trim())}`);
    }
  };

  return (
    <>
      {/* ── SIDEBAR DRAWER ── */}
      <aside
        className={`sidebar ${collapsed ? 'collapsed' : ''} ${mobileOpen ? 'open' : ''}`}
        style={{
          width: collapsed ? 64 : 240,
          transition: 'width .3s cubic-bezier(.2,.8,.3,1)',
        }}
      >
        {/* Toggle Collapse Button */}
        <button
          className="sidebar-toggle"
          onClick={() => setCollapsed(!collapsed)}
          style={{
            position: 'absolute',
            right: -14,
            top: 28,
            width: 28,
            height: 28,
            borderRadius: '50%',
            background: 'var(--color-surface)',
            border: '1px solid var(--color-border)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            cursor: 'pointer',
            zIndex: 51,
            boxShadow: '0 4px 12px rgba(0,0,0,.4)',
            transition: 'all .2s',
          }}
        >
          {collapsed ? (
            <ChevronRight size={14} style={{ color: 'var(--color-text-dim)' }} />
          ) : (
            <ChevronLeft size={14} style={{ color: 'var(--color-text-dim)' }} />
          )}
        </button>

        {/* Brand */}
        <div
          className="sidebar-brand"
          style={{
            justifyContent: collapsed ? 'center' : 'flex-start',
            padding: collapsed ? '20px 10px 24px' : '20px 20px 24px',
          }}
        >
          <div className="sidebar-logo">
            <Shield size={20} color="#080c10" strokeWidth={2.5} />
          </div>
          {!collapsed && (
            <div>
              <div className="sidebar-title">THREX AI</div>
              <div
                style={{
                  fontSize: 9,
                  color: 'var(--color-teal)',
                  letterSpacing: '.1em',
                  marginTop: 1,
                }}
              >
                OBSERVE · ANALYZE · DETECT
              </div>
            </div>
          )}
        </div>

        {/* Navigation Items */}
        <nav className="sidebar-nav">
          {!collapsed && <div className="sidebar-section">MONITORING</div>}
          {MONITORING.map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              end={n.to === '/'}
              onClick={() => setMobileOpen(false)}
              className={({ isActive }) => (isActive ? 'active' : '')}
              title={collapsed ? n.label : undefined}
              style={{
                justifyContent: collapsed ? 'center' : 'flex-start',
                padding: collapsed ? '10px' : '10px 14px',
              }}
            >
              <n.icon />
              {!collapsed && <span>{n.label}</span>}
            </NavLink>
          ))}

          {!collapsed && (
            <div className="sidebar-section" style={{ marginTop: 20 }}>
              DETECTION
            </div>
          )}
          {collapsed && (
            <div style={{ height: 1, background: 'var(--color-border)', margin: '10px 8px' }} />
          )}
          {DETECTION.map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              onClick={() => setMobileOpen(false)}
              className={({ isActive }) => (isActive ? 'active' : '')}
              title={collapsed ? n.label : undefined}
              style={{
                justifyContent: collapsed ? 'center' : 'flex-start',
                padding: collapsed ? '10px' : '10px 14px',
              }}
            >
              <n.icon />
              {!collapsed && <span>{n.label}</span>}
            </NavLink>
          ))}

          {!collapsed && (
            <div className="sidebar-section" style={{ marginTop: 20 }}>
              SYSTEM
            </div>
          )}
          {collapsed && (
            <div style={{ height: 1, background: 'var(--color-border)', margin: '10px 8px' }} />
          )}
          {SYSTEM_NAV.map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              onClick={() => setMobileOpen(false)}
              className={({ isActive }) => (isActive ? 'active' : '')}
              title={collapsed ? n.label : undefined}
              style={{
                justifyContent: collapsed ? 'center' : 'flex-start',
                padding: collapsed ? '10px' : '10px 14px',
              }}
            >
              <n.icon />
              {!collapsed && <span>{n.label}</span>}
            </NavLink>
          ))}
        </nav>

        {/* Architecture Constraints Status (Visible only when expanded) */}
        {!collapsed && (
          <div className="sidebar-constraints" style={{ marginTop: 'auto', padding: '16px 20px' }}>
            <div className="sidebar-section">ARCHITECTURE STATUS</div>
            {CONSTRAINTS.map((c) => (
              <div key={c.label} className="constraint-row">
                <span className="constraint-label">{c.label}</span>
                <span className={`constraint-val ${c.ok ? 'on' : 'off'}`}>{c.val}</span>
              </div>
            ))}
          </div>
        )}

        {/* Connection Status Footer */}
        <div className="sidebar-foot">
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              justifyContent: collapsed ? 'center' : 'flex-start',
            }}
          >
            <span
              className="dot"
              style={{
                background: backendUp ? 'var(--color-green)' : 'var(--color-text-muted)',
                width: 8,
                height: 8,
                flexShrink: 0,
              }}
            />
            {!collapsed && (
              <span>{backendUp ? 'BACKEND CONNECTED' : 'OFFLINE · backend unreachable'}</span>
            )}
          </div>
          {!collapsed && (
            <div style={{ marginTop: 4, color: 'var(--color-text-muted)', fontSize: 10 }}>
              Data Diode: Connected · Return Path: None
            </div>
          )}
        </div>
      </aside>

      {/* Mobile Drawer Overlay */}
      {mobileOpen && (
        <div
          style={{ position: 'fixed', inset: 0, zIndex: 40, background: 'rgba(0,0,0,.6)' }}
          onClick={() => setMobileOpen(false)}
        />
      )}

      {/* ── MAIN CONTENT AREA ── */}
      <div
        className="main-area"
        style={{
          marginLeft: collapsed ? 64 : 240,
          transition: 'margin-left .3s cubic-bezier(.2,.8,.3,1)',
        }}
      >
        <header className="topbar">
          <div className="topbar-left">
            <button
              className="mobile-toggle"
              style={{ display: 'none' }}
              onClick={() => setMobileOpen(true)}
            >
              <Menu size={20} />
            </button>
          </div>

          {/* Search Bar */}
          <form onSubmit={handleSearch} className="topbar-search">
            <Search size={14} style={{ color: 'var(--color-text-muted)', flexShrink: 0 }} />
            <input
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search anything..."
              style={{
                background: 'transparent',
                border: 'none',
                outline: 'none',
                color: 'var(--color-text)',
                fontSize: 13,
                flex: 1,
              }}
            />
            <span
              style={{
                fontSize: 10,
                color: 'var(--color-text-muted)',
                border: '1px solid var(--color-border)',
                borderRadius: 4,
                padding: '1px 6px',
              }}
            >
              ⌘ K
            </span>
          </form>

          {/* Topbar Right Actions */}
          <div className="topbar-right">
            <button className="btn btn-ghost" onClick={togglePause} style={{ fontSize: 12 }}>
              {paused ? '▶ Resume' : '⏸ Pause'}
            </button>
            <span style={{ fontSize: 11, color: 'var(--color-text-dim)' }}>Last Hour</span>

            {/* User Profile */}
            <div style={{ position: 'relative' }}>
              <button
                onClick={() => setProfileOpen(!profileOpen)}
                style={{
                  width: 34,
                  height: 34,
                  borderRadius: '50%',
                  background: 'linear-gradient(135deg,var(--color-teal),var(--color-cyan))',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: 13,
                  fontWeight: 600,
                  color: 'var(--color-void)',
                }}
              >
                AN
              </button>
              {profileOpen && (
                <div className="profile-dropdown">
                  <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--color-border)' }}>
                    <div style={{ fontWeight: 600, fontSize: 13 }}>Analyst</div>
                    <div style={{ fontSize: 11, color: 'var(--color-text-dim)', marginTop: 2 }}>
                      analyst@threx.ai
                    </div>
                  </div>
                  <button className="profile-item">
                    <User size={14} /> Profile
                  </button>
                  <button
                    className="profile-item"
                    onClick={() => {
                      setProfileOpen(false);
                      nav('/login');
                    }}
                  >
                    <LogOut size={14} /> Sign out
                  </button>
                </div>
              )}
            </div>
          </div>
        </header>

        <div className="main-shell" style={{ padding: '24px 28px 40px' }}>
          <Outlet />
        </div>
      </div>
    </>
  );
}