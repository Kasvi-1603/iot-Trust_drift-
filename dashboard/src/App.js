import React from 'react';
import { BrowserRouter as Router, Routes, Route, NavLink, useNavigate, useLocation } from 'react-router-dom';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Analytics from './pages/Analytics';
import Network from './pages/Network';
import Alerts from './pages/Alerts';
import Security from './pages/Security';
import Devices from './pages/Devices';
import DeviceDetail from './pages/DeviceDetail';

/* SVG Icons as components */
const IconDashboard = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="3" y="3" width="7" height="7" /><rect x="14" y="3" width="7" height="7" />
    <rect x="3" y="14" width="7" height="7" /><rect x="14" y="14" width="7" height="7" />
  </svg>
);

const IconAnalytics = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <line x1="18" y1="20" x2="18" y2="10" /><line x1="12" y1="20" x2="12" y2="4" /><line x1="6" y1="20" x2="6" y2="14" />
  </svg>
);

const IconNetwork = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="5" r="3" /><circle cx="5" cy="19" r="3" /><circle cx="19" cy="19" r="3" />
    <line x1="12" y1="8" x2="5" y2="16" /><line x1="12" y1="8" x2="19" y2="16" />
  </svg>
);

const IconAlerts = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" /><path d="M13.73 21a2 2 0 0 1-3.46 0" />
  </svg>
);

const IconSecurity = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
  </svg>
);

const IconDevices = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="2" y="3" width="20" height="14" rx="2" ry="2" /><line x1="8" y1="21" x2="16" y2="21" /><line x1="12" y1="17" x2="12" y2="21" />
  </svg>
);

const IconLogout = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" /><polyline points="16 17 21 12 16 7" /><line x1="21" y1="12" x2="9" y2="12" />
  </svg>
);

function Sidebar() {
  const navigate = useNavigate();

  const links = [
    { to: '/', label: 'Dashboard', icon: <IconDashboard /> },
    { to: '/devices', label: 'Devices', icon: <IconDevices /> },
    { to: '/analytics', label: 'Analytics', icon: <IconAnalytics /> },
    { to: '/network', label: 'Network', icon: <IconNetwork /> },
    { to: '/alerts', label: 'Alerts', icon: <IconAlerts /> },
    { to: '/security', label: 'Security', icon: <IconSecurity /> },
  ];

  return (
    <aside className="app-sidebar">
      <div className="sidebar-logo" onClick={() => navigate('/')}>
        <div className="sidebar-logo-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
        </div>
        <div className="sidebar-logo-text">
          <h2>TrustGuard</h2>
          <p>IoT SOC</p>
        </div>
      </div>

      <nav className="sidebar-nav">
        <div className="sidebar-section-label">Monitor</div>
        {links.slice(0, 4).map(link => (
          <NavLink
            key={link.to}
            to={link.to}
            end={link.to === '/'}
            className={({ isActive }) => `sidebar-link ${isActive ? 'active' : ''}`}
          >
            {link.icon}
            <span>{link.label}</span>
          </NavLink>
        ))}

        <div className="sidebar-section-label" style={{ marginTop: 8 }}>Respond</div>
        {links.slice(4).map(link => (
          <NavLink
            key={link.to}
            to={link.to}
            className={({ isActive }) => `sidebar-link ${isActive ? 'active' : ''}`}
          >
            {link.icon}
            <span>{link.label}</span>
          </NavLink>
        ))}
      </nav>

      <div className="sidebar-bottom">
        <div className="sidebar-status">
          <span className="sidebar-status-dot" />
          <span>System Online</span>
        </div>
        <button className="sidebar-logout" onClick={() => navigate('/login')}>
          <IconLogout />
          <span>Sign Out</span>
        </button>
      </div>
    </aside>
  );
}

function AppLayout({ children }) {
  const location = useLocation();
  const isLogin = location.pathname === '/login';

  if (isLogin) return <>{children}</>;

  return (
    <div className="app-layout">
      <Sidebar />
      <main className="app-main">
        <div className="app-content">
          {children}
        </div>
      </main>
    </div>
  );
}

function App() {
  return (
    <Router>
      <AppLayout>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/" element={<Dashboard />} />
          <Route path="/devices" element={<Devices />} />
          <Route path="/analytics" element={<Analytics />} />
          <Route path="/network" element={<Network />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/security" element={<Security />} />
          <Route path="/device/:deviceId" element={<DeviceDetail />} />
        </Routes>
      </AppLayout>
    </Router>
  );
}

export default App;
