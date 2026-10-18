import { BrowserRouter as Router, Routes, Route, NavLink, useLocation } from 'react-router-dom';
import { Shield, LayoutDashboard, Search, FileText, Lock, Info } from 'lucide-react';
import Dashboard from './pages/Dashboard';
import Analyze from './pages/Analyze';
import AppDetail from './pages/AppDetail';
import Policies from './pages/Policies';
import Privacy from './pages/Privacy';
import NotFound from './pages/NotFound';
import './index.css';

function Sidebar() {
  const location = useLocation();
  const isActive = (path: string) => location.pathname === path || (path !== '/' && location.pathname.startsWith(path));
  
  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <Shield size={28} style={{ color: '#8b5cf6' }} />
          <div>
            <h1>Permission Sentinel</h1>
            <p>Android Permission Auditor</p>
          </div>
        </div>
      </div>
      <nav className="sidebar-nav">
        <NavLink to="/" className={`nav-link ${location.pathname === '/' ? 'active' : ''}`}>
          <LayoutDashboard size={18} />
          Dashboard
        </NavLink>
        <NavLink to="/analyze" className={`nav-link ${isActive('/analyze') ? 'active' : ''}`}>
          <Search size={18} />
          Analyze App
        </NavLink>
        <NavLink to="/policies" className={`nav-link ${isActive('/policies') ? 'active' : ''}`}>
          <FileText size={18} />
          Policies
        </NavLink>
        <NavLink to="/privacy" className={`nav-link ${isActive('/privacy') ? 'active' : ''}`}>
          <Lock size={18} />
          Privacy & Info
        </NavLink>
      </nav>
      <div style={{ padding: '16px', borderTop: '1px solid var(--border-color)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
          <Info size={14} />
          <span>v1.0.0 · KB v1.0.0</span>
        </div>
      </div>
    </aside>
  );
}

export default function App() {
  return (
    <Router>
      <div className="app-layout">
        <Sidebar />
        <main className="main-content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/analyze" element={<Analyze />} />
            <Route path="/app/:id" element={<AppDetail />} />
            <Route path="/policies" element={<Policies />} />
            <Route path="/privacy" element={<Privacy />} />
            <Route path="*" element={<NotFound />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
}
