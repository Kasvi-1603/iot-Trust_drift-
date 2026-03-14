import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, ReferenceLine, Legend,
} from 'recharts';

const API = 'http://localhost:8002/api';

const DEVICE_COLORS = {
  CCTV_01: '#3b82f6',
  Router_01: '#f59e0b',
  Access_01: '#22c55e',
};

const ATTACK_ICONS = {
  exfiltration: '📤',
  c2: '🎯',
  lateral_scan: '🔍',
  dns_tunnel: '🌐',
  credential_stuffing: '🔑',
};

function severityClass(severity) {
  return (severity || 'low').toLowerCase();
}

function formatTime(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  const mon = d.toLocaleString('en-US', { month: 'short' });
  const day = d.getDate();
  const h = d.getHours().toString().padStart(2, '0');
  const m = d.getMinutes().toString().padStart(2, '0');
  return `${mon} ${day}, ${h}:${m}`;
}

/* ── Device Card with Attack Injection ── */
function DeviceCard({ device, catalog, activeInjections, onInject, onNavigate, injecting }) {
  const [selectedAttack, setSelectedAttack] = useState('');
  const [isInjecting, setIsInjecting] = useState(false);
  const sev = severityClass(device.severity);

  // Get device type for catalog lookup
  function deviceType(id) {
    if (id.startsWith('CCTV')) return 'CCTV';
    if (id.startsWith('Router')) return 'Router';
    if (id.startsWith('Access')) return 'AccessController';
    return '';
  }

  const attacks = catalog[deviceType(device.device_id)] || [];
  const activeAttack = activeInjections[device.device_id];

  const handleInject = async () => {
    if (!selectedAttack || isInjecting) return;
    setIsInjecting(true);
    await onInject(device.device_id, selectedAttack);
    setIsInjecting(false);
    setSelectedAttack('');
  };

  return (
    <div className={`device-card severity-${sev} ${activeAttack ? 'device-card-attacked' : ''}`}>
      {/* Active attack indicator */}
      {activeAttack && (
        <div className="device-attack-active-banner">
          <span className="attack-pulse-dot" />
          <span>UNDER ATTACK</span>
        </div>
      )}

      <div className="device-card-header" onClick={onNavigate}>
        <div>
          <div className="device-card-name">{device.device_id}</div>
          <div className="device-card-type">{device.description || device.device_type}</div>
        </div>
        <span className={`severity-badge ${sev}`}>{device.severity}</span>
      </div>
      <div className="device-card-score" onClick={onNavigate}>
        <div className="device-card-score-label">Trust Score</div>
        <div className={`device-card-score-value ${sev}`}>{device.trust_score}</div>
      </div>
      <div className="trust-bar-container" onClick={onNavigate}>
        <div className={`trust-bar-fill ${sev}`} style={{ width: `${device.trust_score}%` }} />
      </div>

      {/* Active Attack Info */}
      {activeAttack && (
        <div className="device-attack-info">
          <div className="device-attack-info-icon">{ATTACK_ICONS[activeAttack.attack_type] || '⚠️'}</div>
          <div className="device-attack-info-text">
            <div className="device-attack-info-name">{activeAttack.attack_name}</div>
            <div className="device-attack-info-mitre">{activeAttack.mitre}</div>
          </div>
          <div className="device-attack-info-flows">{activeAttack.attack_flows} flows</div>
        </div>
      )}

      {/* Attack Injection Dropdown */}
      {attacks.length > 0 && !activeAttack && (
        <div className="device-inject-section">
          <div className="device-inject-label">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>
            </svg>
            Simulate Attack
          </div>
          <div className="device-inject-row">
            <select
              className="device-inject-select"
              value={selectedAttack}
              onChange={e => setSelectedAttack(e.target.value)}
              disabled={isInjecting || injecting}
            >
              <option value="">Choose attack type...</option>
              {attacks.map(a => (
                <option key={a.id} value={a.id}>
                  {ATTACK_ICONS[a.id] || '⚡'} {a.name}
                </option>
              ))}
            </select>
            <button
              className="device-inject-btn"
              disabled={!selectedAttack || isInjecting || injecting}
              onClick={handleInject}
            >
              {isInjecting ? (
                <span className="device-inject-btn-loading">
                  <span className="mini-spinner" />
                </span>
              ) : (
                <>
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                    <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>
                  </svg>
                  Inject
                </>
              )}
            </button>
          </div>
          {selectedAttack && (
            <div className="device-inject-desc">
              {attacks.find(a => a.id === selectedAttack)?.description}
              <div className="device-inject-mitre">
                {attacks.find(a => a.id === selectedAttack)?.mitre}
              </div>
            </div>
          )}
        </div>
      )}

      <span className="device-card-action" onClick={onNavigate}>
        View Details
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M5 12h14M12 5l7 7-7 7" />
        </svg>
      </span>
    </div>
  );
}

function ChartTooltip({ active, payload, label }) {
  if (!active || !payload || !payload.length) return null;
  return (
    <div style={{
      background: '#fff', border: '1px solid #e2e8f0', borderRadius: 8,
      padding: '12px 16px', boxShadow: '0 4px 12px rgba(0,0,0,0.08)', fontSize: 13,
    }}>
      <div style={{ color: '#64748b', marginBottom: 6, fontSize: 12 }}>{label}</div>
      {payload.map((p, i) => (
        <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 2 }}>
          <span style={{ width: 10, height: 10, borderRadius: '50%', background: p.color, display: 'inline-block' }} />
          <span style={{ fontWeight: 500 }}>{p.name}:</span>
          <span>{p.value}</span>
        </div>
      ))}
    </div>
  );
}

function Dashboard() {
  const [devices, setDevices] = useState([]);
  const [timeline, setTimeline] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  /* ── System status + detection metrics ── */
  const [systemStatus, setSystemStatus] = useState(null);
  const [detectionMetrics, setDetectionMetrics] = useState(null);

  /* ── Attack injection state ── */
  const [catalog, setCatalog] = useState({});
  const [activeInjections, setActiveInjections] = useState({});
  const [injecting, setInjecting] = useState(false);
  const [lastInjection, setLastInjection] = useState(null);

  const navigate = useNavigate();

  const fetchDashboardData = useCallback(async () => {
    // Use allSettled so one slow/failing endpoint never blocks the whole dashboard
    const safe = (promise) => promise.catch(() => ({ data: null }));
    try {
      const [devRes, tlRes, alRes, stRes, catRes, injRes, sysRes, dtRes] = await Promise.all([
        safe(axios.get(`${API}/devices`)),
        safe(axios.get(`${API}/trust-timeline`)),
        safe(axios.get(`${API}/alerts`)),
        safe(axios.get(`${API}/stats`)),
        safe(axios.get(`${API}/attack-catalog`)),
        safe(axios.get(`${API}/injection-status`)),
        safe(axios.get(`${API}/system-status`)),
        safe(axios.get(`${API}/detection-metrics`)),
      ]);

      if (!devRes.data && !stRes.data) {
        // Core endpoints both failed — backend is down
        setError('Failed to connect to API. Make sure the FastAPI server is running on port 8002.');
        setLoading(false);
        return;
      }

      if (devRes.data)  setDevices(devRes.data);
      if (stRes.data)   setStats(stRes.data);
      if (catRes.data)  setCatalog(catRes.data);
      if (injRes.data)  setActiveInjections(injRes.data.active_injections || {});
      if (sysRes.data)  setSystemStatus(sysRes.data);
      if (dtRes.data)   setDetectionMetrics(dtRes.data);

      if (tlRes.data) {
        const byWindow = {};
        tlRes.data.forEach((row) => {
          const t = formatTime(row.window);
          if (!byWindow[t]) byWindow[t] = { window: t };
          byWindow[t][row.device_id] = row.trust_score;
        });
        setTimeline(Object.values(byWindow));
      }
      if (alRes.data) setAlerts(alRes.data.slice(0, 15));
      setLoading(false);
    } catch (err) {
      console.error(err);
      setError('Failed to connect to API. Make sure the FastAPI server is running on port 8002.');
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchDashboardData();
  }, [fetchDashboardData]);

  async function handleInject(deviceId, attackType) {
    setInjecting(true);
    try {
      const res = await axios.post(`${API}/inject-attack`, {
        device_id: deviceId,
        attack_type: attackType,
      });
      setActiveInjections(res.data.active_injections || {});
      setLastInjection({
        device_id: deviceId,
        attack_name: res.data.attack_name,
        flows: res.data.flows_injected,
        time: new Date().toLocaleTimeString(),
      });
      await fetchDashboardData();
    } catch (err) {
      console.error('Inject failed:', err);
    }
    setInjecting(false);
  }

  async function handleReset() {
    setInjecting(true);
    try {
      await axios.post(`${API}/reset`);
      setActiveInjections({});
      setLastInjection(null);
      await fetchDashboardData();
    } catch (err) {
      console.error('Reset failed:', err);
    }
    setInjecting(false);
  }

  if (loading) {
    return <div className="loading-container"><div className="loading-spinner" /><div className="loading-text">Loading dashboard...</div></div>;
  }
  if (error) {
    return <div className="error-container"><div>{error}</div></div>;
  }

  const deviceIds = devices.map(d => d.device_id);
  const hasActiveAttack = Object.keys(activeInjections).length > 0;

  return (
    <>
      <div className="page-title-section">
        <h1 className="page-title">Security Overview</h1>
        <p className="page-subtitle">Real-time trust monitoring across all IoT devices</p>
      </div>

      {/* ── Attack Simulation Control Bar ── */}
      <div className={`sim-panel ${hasActiveAttack ? 'sim-panel-alert' : ''}`}>
        <div className="sim-panel-left">
          <div className="sim-panel-title">
            {hasActiveAttack ? '🔴 Attack Simulation Active' : '🛡️ Attack Injection Control'}
          </div>
          <div className="sim-panel-desc">
            {hasActiveAttack
              ? Object.entries(activeInjections).map(([devId, info]) =>
                  `${devId}: ${info.attack_name} (${info.mitre})`
                ).join(' | ')
              : 'No active attacks — Select an attack below any device to simulate'}
          </div>
        </div>

        <div className="sim-panel-right" style={{ flexWrap: 'wrap', gap: 8 }}>
          {hasActiveAttack && (
            <button
              className="sim-btn sim-btn-reset-glow"
              disabled={injecting}
              onClick={handleReset}
            >
              {injecting ? (
                <><span className="mini-spinner" /> Resetting...</>
              ) : (
                <>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/>
                    <path d="M3 3v5h5"/>
                  </svg>
                  Reset to Clean Baseline
                </>
              )}
            </button>
          )}
        </div>

        {injecting && (
          <div className="sim-loading">
            <div className="loading-spinner" style={{ width: 18, height: 18 }} />
            <span>Running ML pipeline... Anomaly detection → Drift analysis → Policy engine → Trust scoring → Evidence generation</span>
          </div>
        )}
      </div>

      {/* Active Attack Banner */}
      {hasActiveAttack && (
        <div className="attack-active-banner">
          <div className="attack-active-banner-pulse" />
          <div className="attack-active-banner-content">
            <span className="attack-active-banner-icon">⚠️</span>
            <div className="attack-active-banner-text">
              <span className="attack-active-banner-title">ATTACK SIMULATION IN PROGRESS</span>
              <span className="attack-active-banner-detail">
                {Object.entries(activeInjections).map(([devId, info]) =>
                  `${devId} → ${info.attack_name} (${info.attack_flows} malicious flows injected)`
                ).join(' | ')}
              </span>
            </div>
            <span className="attack-active-banner-badge">LIVE</span>
          </div>
        </div>
      )}

      {/* Last Injection Success Toast */}
      {lastInjection && !injecting && (
        <div className="inject-success-toast">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>
          </svg>
          <span>
            Attack injected on <strong>{lastInjection.device_id}</strong> — {lastInjection.attack_name} ({lastInjection.flows} flows)
            — Check <strong onClick={() => navigate('/alerts')} style={{cursor:'pointer', textDecoration:'underline'}}>Alerts tab</strong> for detections
          </span>
        </div>
      )}

      {/* ── Auto-Decision Banner ── */}
      {systemStatus && (
        <div style={{
          display: 'flex', gap: 12, marginBottom: 16, flexWrap: 'wrap',
        }}>
          {/* Overall system verdict */}
          <div style={{
            flex: '0 0 auto', display: 'flex', alignItems: 'center', gap: 12,
            padding: '14px 22px', borderRadius: 14, fontFamily: 'inherit',
            background: systemStatus.overall === 'UNSAFE' ? '#fef2f2'
                       : systemStatus.overall === 'WATCH'  ? '#fffbeb' : '#f0fdf4',
            border: `2px solid ${systemStatus.overall === 'UNSAFE' ? '#fca5a5'
                                : systemStatus.overall === 'WATCH'  ? '#fde68a' : '#86efac'}`,
          }}>
            <span style={{ fontSize: 28 }}>
              {systemStatus.overall === 'UNSAFE' ? '🔴' : systemStatus.overall === 'WATCH' ? '🟡' : '🟢'}
            </span>
            <div>
              <div style={{
                fontSize: 11, fontWeight: 700, letterSpacing: 1.2, textTransform: 'uppercase',
                color: systemStatus.overall === 'UNSAFE' ? '#dc2626'
                     : systemStatus.overall === 'WATCH'  ? '#d97706' : '#16a34a',
              }}>Network Status</div>
              <div style={{
                fontSize: 22, fontWeight: 800,
                color: systemStatus.overall === 'UNSAFE' ? '#dc2626'
                     : systemStatus.overall === 'WATCH'  ? '#d97706' : '#16a34a',
              }}>{systemStatus.overall}</div>
            </div>
          </div>

          {/* Per-device verdicts */}
          {systemStatus.devices.map(d => (
            <div key={d.device_id} style={{
              flex: '1 1 0', minWidth: 150,
              padding: '12px 16px', borderRadius: 14,
              background: d.status === 'UNSAFE' ? '#fef2f2' : d.status === 'WATCH' ? '#fffbeb' : '#f0fdf4',
              border: `1.5px solid ${d.status === 'UNSAFE' ? '#fca5a5' : d.status === 'WATCH' ? '#fde68a' : '#86efac'}`,
            }}>
              <div style={{ fontSize: 11, fontWeight: 600, color: '#94a3b8', marginBottom: 2 }}>{d.device_id}</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ fontSize: 16 }}>
                  {d.status === 'UNSAFE' ? '🔴' : d.status === 'WATCH' ? '🟡' : '🟢'}
                </span>
                <span style={{
                  fontSize: 15, fontWeight: 800,
                  color: d.status === 'UNSAFE' ? '#dc2626' : d.status === 'WATCH' ? '#d97706' : '#16a34a',
                }}>{d.status}</span>
              </div>
              <div style={{ fontSize: 10, color: '#64748b', marginTop: 4 }}>{d.reason}</div>
            </div>
          ))}

          {/* Time-to-detection */}
          {detectionMetrics && detectionMetrics.detection_time_mins != null && (
            <div style={{
              flex: '0 0 auto', padding: '12px 20px', borderRadius: 14,
              background: detectionMetrics.status === 'early' ? '#eff6ff' : '#fff7ed',
              border: `1.5px solid ${detectionMetrics.status === 'early' ? '#bfdbfe' : '#fed7aa'}`,
            }}>
              <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase', color: '#94a3b8', marginBottom: 4 }}>
                ⏱ Time-to-Detection
              </div>
              <div style={{
                fontSize: 26, fontWeight: 800,
                color: detectionMetrics.status === 'early' ? '#2563eb' : '#ea580c',
              }}>
                {detectionMetrics.detection_time_mins < 1
                  ? `<1 min`
                  : `${detectionMetrics.detection_time_mins} min`}
              </div>
              <div style={{
                fontSize: 10, fontWeight: 600, marginTop: 2,
                color: detectionMetrics.status === 'early' ? '#3b82f6' : '#f97316',
              }}>
                {detectionMetrics.status === 'early' ? '✓ Early detection' : '⚠ Delayed detection'}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Stats Bar */}
      {stats && (
        <div className="stats-bar">
          <div className="stat-card">
            <div className="stat-card-label">Avg Trust Score</div>
            <div className={`stat-card-value ${stats.avg_trust >= 70 ? 'green' : stats.avg_trust >= 40 ? 'yellow' : 'red'}`}>{stats.avg_trust}</div>
          </div>
          <div className="stat-card">
            <div className="stat-card-label">Devices Monitored</div>
            <div className="stat-card-value">{stats.total_devices}</div>
          </div>
          <div className="stat-card">
            <div className="stat-card-label">Compromised</div>
            <div className={`stat-card-value ${stats.compromised_devices > 0 ? 'red' : 'green'}`}>{stats.compromised_devices}</div>
          </div>
          <div className="stat-card">
            <div className="stat-card-label">Active Alerts</div>
            <div className={`stat-card-value ${stats.total_alerts > 0 ? 'yellow' : 'green'}`}>{stats.total_alerts}</div>
          </div>
          <div className="stat-card">
            <div className="stat-card-label">Policy Violations</div>
            <div className={`stat-card-value ${stats.policy_violations > 0 ? 'red' : 'green'}`}>{stats.policy_violations}</div>
          </div>
        </div>
      )}

      {/* Device Cards with Attack Dropdowns */}
      <div className="device-cards-grid">
        {devices.map((d) => (
          <DeviceCard
            key={d.device_id}
            device={d}
            catalog={catalog}
            activeInjections={activeInjections}
            onInject={handleInject}
            onNavigate={() => navigate(`/device/${d.device_id}`)}
            injecting={injecting}
          />
        ))}
      </div>

      {/* Trust Timeline */}
      <div className="panel">
        <div className="panel-header">
          <div>
            <div className="panel-title">Trust Score Timeline</div>
            <div className="panel-subtitle">All devices — hourly smoothed trust score {hasActiveAttack && <span style={{color:'#ef4444', fontWeight:600}}> (attack data included)</span>}</div>
          </div>
        </div>
        <div className="panel-body">
          <div className="chart-container">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={timeline} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
                <XAxis dataKey="window" tick={{ fontSize: 11, fill: '#94a3b8' }} interval={Math.max(Math.floor(timeline.length / 8), 1)} tickLine={false} axisLine={{ stroke: '#e2e8f0' }} />
                <YAxis domain={[0, 100]} tick={{ fontSize: 11, fill: '#94a3b8' }} tickLine={false} axisLine={{ stroke: '#e2e8f0' }} width={35} />
                <Tooltip content={<ChartTooltip />} />
                <Legend verticalAlign="top" height={36} iconType="circle" wrapperStyle={{ fontSize: 12 }} />
                <ReferenceLine y={30} stroke="#ef4444" strokeDasharray="4 4" strokeWidth={1} />
                <ReferenceLine y={60} stroke="#f59e0b" strokeDasharray="4 4" strokeWidth={1} />
                {deviceIds.map((id) => (
                  <Line key={id} type="monotone" dataKey={id} name={id} stroke={DEVICE_COLORS[id] || '#8884d8'} strokeWidth={2} dot={false} activeDot={{ r: 4, strokeWidth: 0 }} />
                ))}
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Recent Alerts */}
      <div className="panel">
        <div className="panel-header">
          <div>
            <div className="panel-title">Recent Alerts</div>
            <div className="panel-subtitle">Flagged windows — Medium, High, or Critical</div>
          </div>
          <button
            onClick={() => navigate('/alerts')}
            style={{
              padding: '6px 16px', borderRadius: 8, border: '1px solid #e2e8f0',
              background: 'white', color: '#3b82f6', fontSize: 13, fontWeight: 600,
              cursor: 'pointer', fontFamily: 'inherit',
            }}
          >
            View All Alerts →
          </button>
        </div>
        <div className="panel-body no-padding">
          {alerts.length === 0 ? (
            <div className="table-empty">No alerts — all devices operating normally.</div>
          ) : (
            <table className="alerts-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Device</th>
                  <th>Severity</th>
                  <th>Trust</th>
                  <th>Summary</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((a, i) => (
                  <tr key={i} onClick={() => navigate(`/device/${a.device_id}`)} style={{ cursor: 'pointer' }}
                    className={severityClass(a.severity) === 'critical' ? 'alert-row-critical' : severityClass(a.severity) === 'high' ? 'alert-row-high' : ''}
                  >
                    <td className="table-cell-time">{formatTime(a.window)}</td>
                    <td className="table-cell-device">{a.device_id}</td>
                    <td><span className={`severity-badge ${severityClass(a.severity)}`}>{a.severity}</span></td>
                    <td style={{ fontVariantNumeric: 'tabular-nums', fontWeight: 500 }}>{a.trust_score}</td>
                    <td className="table-cell-summary">{a.risk_summary}</td>
                    <td className="table-cell-action">{a.recommended_action}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </>
  );
}

export default Dashboard;
