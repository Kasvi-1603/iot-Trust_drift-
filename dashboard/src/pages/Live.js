import React, { useState, useEffect, useRef, useCallback } from 'react';
import axios from 'axios';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Legend, BarChart, Bar, Cell,
  AreaChart, Area, PieChart, Pie,
} from 'recharts';

const API = 'http://localhost:8002/api';
const WS_URL = 'ws://localhost:8002/ws/live';

const SEVERITY_COLORS = {
  Low: '#22c55e',
  Medium: '#f59e0b',
  High: '#f97316',
  Critical: '#ef4444',
};

const DEVICE_COLORS = {
  CCTV_01: '#3b82f6',
  Router_01: '#f59e0b',
  Access_01: '#22c55e',
};

/* ── Helpers ── */
function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(2) + ' MB';
}

function formatBps(bytes) {
  if (bytes < 1024) return bytes + ' B/s';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB/s';
  return (bytes / 1048576).toFixed(2) + ' MB/s';
}

function PulseDot({ color }) {
  return (
    <span style={{ position: 'relative', display: 'inline-block', width: 10, height: 10 }}>
      <span style={{ position: 'absolute', width: 10, height: 10, borderRadius: '50%', background: color, animation: 'pulse-ring 1.5s infinite' }} />
      <span style={{ position: 'absolute', width: 6, height: 6, borderRadius: '50%', background: color, top: 2, left: 2 }} />
    </span>
  );
}

function ChartTooltip({ active, payload, label }) {
  if (!active || !payload || !payload.length) return null;
  return (
    <div style={{ background: '#fff', border: '1px solid #e2e8f0', borderRadius: 8, padding: '10px 14px', boxShadow: '0 4px 12px rgba(0,0,0,0.08)', fontSize: 12 }}>
      <div style={{ color: '#64748b', marginBottom: 4 }}>{label}</div>
      {payload.map((p, i) => (
        <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 2 }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: p.color, display: 'inline-block' }} />
          <span style={{ fontWeight: 500 }}>{p.name}:</span>
          <span>{typeof p.value === 'number' ? (p.value > 1000 ? formatBytes(p.value) : p.value.toFixed(1)) : p.value}</span>
        </div>
      ))}
    </div>
  );
}

/* ══════════════════════════════════════════════
   LIVE PAGE COMPONENT
   ══════════════════════════════════════════════ */

function Live() {
  // ── Real Traffic State ──
  const [wsConnected, setWsConnected] = useState(false);
  const [captureStatus, setCaptureStatus] = useState(null);
  const [trafficHistory, setTrafficHistory] = useState([]);   // rolling 120s of bandwidth data
  const [latestSnapshot, setLatestSnapshot] = useState(null);
  const [latestScoring, setLatestScoring] = useState(null);
  const [trustHistory, setTrustHistory] = useState([]);        // rolling trust scores
  const [realAlerts, setRealAlerts] = useState([]);

  // ── Simulation State ──
  const [simRunning, setSimRunning] = useState(false);
  const [simStatus, setSimStatus] = useState(null);
  const [simTimeline, setSimTimeline] = useState([]);
  const [simAnomalies, setSimAnomalies] = useState([]);
  const [simViolations, setSimViolations] = useState([]);
  const [attackCatalog, setAttackCatalog] = useState({});
  const [selectedDevice, setSelectedDevice] = useState('');
  const [selectedAttack, setSelectedAttack] = useState('');
  const [injecting, setInjecting] = useState(false);
  const [message, setMessage] = useState('');

  // ── Tab State ──
  const [activeTab, setActiveTab] = useState('real');  // 'real' or 'sim'

  const wsRef = useRef(null);
  const reconnectTimer = useRef(null);
  const pollRef = useRef(null);
  const pingIntervalRef = useRef(null);

  // ── WebSocket Connection ──
  const connectWs = useCallback(() => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) return;

    const ws = new WebSocket(WS_URL);
    wsRef.current = ws;

    ws.onopen = () => {
      setWsConnected(true);
      console.log('[WS] Connected');
      // Send keep-alive ping every 30 seconds
      pingIntervalRef.current = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) {
          try {
            ws.send('ping');
          } catch (e) {
            console.error('[WS] Ping failed:', e);
          }
        }
      }, 30000);
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);

        if (data.real_traffic) {
          setLatestSnapshot(data.real_traffic);
          // Add to bandwidth history (keep last 120 points)
          setTrafficHistory(prev => {
            const next = [...prev, {
              tick: data.real_traffic.tick,
              sent: data.real_traffic.bytes_sent_per_sec,
              recv: data.real_traffic.bytes_recv_per_sec,
              connections: data.real_traffic.active_connections,
              ips: data.real_traffic.unique_remote_ips,
              external: data.real_traffic.external_connections,
            }];
            return next.slice(-120);
          });
        }

        if (data.scoring) {
          setLatestScoring(data.scoring);
          if (data.scoring.status === 'scoring') {
            setTrustHistory(prev => {
              const next = [...prev, {
                tick: data.scoring.tick,
                trust: data.scoring.trust_score,
                anomaly: data.scoring.anomaly_score,
                drift: data.scoring.drift_magnitude,
              }];
              return next.slice(-120);
            });
          }
        }

        if (data.capture_status) {
          setCaptureStatus(data.capture_status);
        }

        if (data.simulation) {
          setSimStatus(data.simulation);
          setSimRunning(data.simulation.running);
        }
      } catch (e) {
        console.error('[WS] Parse error:', e);
      }
    };

    ws.onclose = () => {
      setWsConnected(false);
      if (pingIntervalRef.current) {
        clearInterval(pingIntervalRef.current);
        pingIntervalRef.current = null;
      }
      // Reconnect after 2 seconds
      reconnectTimer.current = setTimeout(connectWs, 2000);
    };

    ws.onerror = (error) => {
      console.error('[WS] Error:', error);
      ws.close();
    };
  }, []);

  useEffect(() => {
    connectWs();
    // Fetch attack catalog once
    axios.get(`${API}/attack-catalog`).then(res => setAttackCatalog(res.data)).catch(() => {});
    return () => {
      if (wsRef.current) wsRef.current.close();
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
      if (pollRef.current) clearInterval(pollRef.current);
      if (pingIntervalRef.current) clearInterval(pingIntervalRef.current);
    };
  }, [connectWs]);

  // Poll simulation data every 3s (only when sim tab is active)
  useEffect(() => {
    if (activeTab !== 'sim') {
      if (pollRef.current) clearInterval(pollRef.current);
      return;
    }
    const fetchSim = async () => {
      try {
        const [timelineRes, anomRes, violRes] = await Promise.all([
          axios.get(`${API}/live/timeline?last_n=100`),
          axios.get(`${API}/live/anomalies?last_n=50`),
          axios.get(`${API}/live/violations?last_n=50`),
        ]);
        setSimTimeline(timelineRes.data);
        setSimAnomalies(anomRes.data);
        setSimViolations(violRes.data);
      } catch (err) { }
    };
    fetchSim();
    pollRef.current = setInterval(fetchSim, 3000);
    return () => clearInterval(pollRef.current);
  }, [activeTab, simRunning]);

  // Fetch real alerts periodically
  useEffect(() => {
    const fetchAlerts = () => {
      axios.get(`${API}/live/capture/alerts?last_n=30`).then(r => setRealAlerts(r.data)).catch(() => {});
    };
    fetchAlerts();
    const iv = setInterval(fetchAlerts, 5000);
    return () => clearInterval(iv);
  }, []);

  // ── Handlers ──
  async function handleCaptureReset() {
    try {
      await axios.post(`${API}/live/capture/reset`);
      setTrafficHistory([]);
      setTrustHistory([]);
      setRealAlerts([]);
      setMessage('Capture reset — re-learning baseline');
      setTimeout(() => setMessage(''), 3000);
    } catch (err) {
      setMessage('Failed to reset capture');
    }
  }

  async function handleSimStart() {
    try {
      await axios.post(`${API}/live/start?interval=10`);
      setSimRunning(true);
      setMessage('Simulation started');
      setTimeout(() => setMessage(''), 3000);
    } catch (err) { setMessage('Failed to start simulation'); }
  }

  async function handleSimStop() {
    try {
      await axios.post(`${API}/live/stop`);
      setSimRunning(false);
      setMessage('Simulation paused');
      setTimeout(() => setMessage(''), 3000);
    } catch (err) { setMessage('Failed to stop'); }
  }

  async function handleSimReset() {
    try {
      await axios.post(`${API}/live/reset`);
      setSimTimeline([]);
      setSimAnomalies([]);
      setSimViolations([]);
      setMessage('Simulation reset');
      setTimeout(() => setMessage(''), 3000);
    } catch (err) { setMessage('Failed to reset'); }
  }

  async function handleInject() {
    if (!selectedDevice || !selectedAttack) return;
    setInjecting(true);
    try {
      const res = await axios.post(`${API}/live/inject`, { device_id: selectedDevice, attack_type: selectedAttack });
      setMessage(`Attack "${res.data.attack_name}" injected on ${selectedDevice}`);
      setTimeout(() => setMessage(''), 4000);
    } catch (err) { setMessage('Injection failed'); }
    setInjecting(false);
  }

  async function handleClearAttack(deviceId) {
    try {
      await axios.post(`${API}/live/clear-attack?device_id=${deviceId}`);
      setMessage(`Attack cleared on ${deviceId}`);
      setTimeout(() => setMessage(''), 3000);
    } catch (err) { setMessage('Failed to clear attack'); }
  }

  // ── Derived data ──
  const isLearning = latestScoring?.status === 'learning';
  const learningProgress = latestScoring?.progress || 0;
  const trustScore = latestScoring?.trust_score ?? null;
  const severity = latestScoring?.severity ?? 'Low';
  const sevColor = SEVERITY_COLORS[severity] || '#94a3b8';

  // Sim chart data
  const simTrustChart = [];
  const simGrouped = {};
  simTimeline.forEach(w => {
    const key = w.tick;
    if (!simGrouped[key]) simGrouped[key] = { tick: key, label: `T+${key}` };
    simGrouped[key][w.device_id] = w.trust_score_smoothed;
  });
  Object.values(simGrouped).sort((a, b) => a.tick - b.tick).forEach(g => simTrustChart.push(g));

  const activeAttacks = simStatus?.active_attacks || {};
  const devices = ['CCTV_01', 'Router_01', 'Access_01'];
  const deviceTypeMap = { CCTV_01: 'CCTV', Router_01: 'Router', Access_01: 'AccessController' };

  // Protocol distribution from latest snapshot
  const protoData = latestSnapshot?.app_protocols
    ? Object.entries(latestSnapshot.app_protocols).map(([k, v]) => ({ name: k, value: v })).sort((a, b) => b.value - a.value).slice(0, 8)
    : [];

  return (
    <>
      {/* ── Page Title ── */}
      <div className="page-title-section">
        <h1 className="page-title">
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 10 }}>
            Live Monitoring
            {wsConnected && <PulseDot color="#22c55e" />}
            {!wsConnected && <span style={{ fontSize: 11, color: '#ef4444', fontWeight: 500 }}>DISCONNECTED</span>}
          </span>
        </h1>
        <p className="page-subtitle">
          Real-time network traffic capture — monitoring your WiFi every second
        </p>
      </div>

      {/* ── Tab Selector ── */}
      <div style={{ display: 'flex', gap: 0, marginBottom: 16 }}>
        <button
          className={`live-tab-btn ${activeTab === 'real' ? 'active' : ''}`}
          onClick={() => setActiveTab('real')}
        >
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="14" height="14"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
          Real Traffic
        </button>
        <button
          className={`live-tab-btn ${activeTab === 'sim' ? 'active' : ''}`}
          onClick={() => setActiveTab('sim')}
        >
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="14" height="14"><path d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
          IoT Simulation
        </button>
      </div>

      {/* ══════════════════════════════════════
          TAB 1: REAL TRAFFIC
         ══════════════════════════════════════ */}
      {activeTab === 'real' && (
        <>
          {/* ── Status Bar ── */}
          <div className="rt-status-bar">
            <div className="rt-status-item">
              <span className="rt-status-label">Interface</span>
              <span className="rt-status-value">{captureStatus?.interface || '—'}</span>
            </div>
            <div className="rt-status-item">
              <span className="rt-status-label">IP Address</span>
              <span className="rt-status-value" style={{ fontFamily: 'monospace' }}>{captureStatus?.interface_ip || '—'}</span>
            </div>
            <div className="rt-status-item">
              <span className="rt-status-label">Upload</span>
              <span className="rt-status-value rt-up">{latestSnapshot ? formatBps(latestSnapshot.bytes_sent_per_sec) : '—'}</span>
            </div>
            <div className="rt-status-item">
              <span className="rt-status-label">Download</span>
              <span className="rt-status-value rt-down">{latestSnapshot ? formatBps(latestSnapshot.bytes_recv_per_sec) : '—'}</span>
            </div>
            <div className="rt-status-item">
              <span className="rt-status-label">Connections</span>
              <span className="rt-status-value">{latestSnapshot?.active_connections ?? '—'}</span>
            </div>
            <div className="rt-status-item">
              <span className="rt-status-label">Remote IPs</span>
              <span className="rt-status-value">{latestSnapshot?.unique_remote_ips ?? '—'}</span>
            </div>
            <div style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
              <button className="live-btn live-btn-reset" onClick={handleCaptureReset}>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="13" height="13"><path d="M3 12a9 9 0 019-9 9.75 9.75 0 016.74 2.74L21 8" strokeLinecap="round" strokeLinejoin="round"/><path d="M21 3v5h-5" strokeLinecap="round" strokeLinejoin="round"/></svg>
                Reset Baseline
              </button>
            </div>
          </div>

          {/* ── Baseline Learning Progress ── */}
          {isLearning && (
            <div className="rt-learning-bar">
              <div className="rt-learning-icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="18" height="18"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg>
              </div>
              <div className="rt-learning-info">
                <div className="rt-learning-title">Learning Your Network Baseline...</div>
                <div className="rt-learning-sub">Capturing normal traffic pattern — {latestScoring?.seconds_remaining}s remaining</div>
              </div>
              <div className="rt-learning-progress">
                <div className="rt-learning-fill" style={{ width: `${learningProgress * 100}%` }} />
              </div>
              <span className="rt-learning-pct">{Math.round(learningProgress * 100)}%</span>
            </div>
          )}

          {/* ── Trust Score Card ── */}
          {!isLearning && trustScore !== null && (
            <div className="rt-trust-card" style={{ borderColor: sevColor }}>
              <div className="rt-trust-score" style={{ color: sevColor }}>{trustScore}</div>
              <div className="rt-trust-label">Trust Score</div>
              <div className="trust-bar-container" style={{ width: 200, margin: '8px auto 0' }}>
                <div className={`trust-bar-fill ${severity.toLowerCase()}`} style={{ width: `${trustScore}%` }} />
              </div>
              <span className={`severity-badge ${severity.toLowerCase()}`} style={{ marginTop: 8 }}>{severity}</span>
              <div style={{ display: 'flex', gap: 16, marginTop: 10, fontSize: 11, color: '#64748b' }}>
                <span>Anomaly: {latestScoring?.anomaly_score?.toFixed(3)}</span>
                <span>Drift: {latestScoring?.drift_magnitude?.toFixed(2)}</span>
                <span>{latestScoring?.drift_class?.replace('DRIFT_', '')}</span>
              </div>
            </div>
          )}

          {/* ── Charts Row 1: Bandwidth + Connections ── */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
            {/* Bandwidth Timeline */}
            <div className="panel">
              <div className="panel-header">
                <div>
                  <div className="panel-title">Live Bandwidth</div>
                  <div className="panel-subtitle">Bytes sent/received per second (real-time)</div>
                </div>
              </div>
              <div className="panel-body">
                <div className="chart-container">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={trafficHistory} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
                      <XAxis dataKey="tick" tick={{ fontSize: 10, fill: '#94a3b8' }} tickLine={false} />
                      <YAxis tick={{ fontSize: 10, fill: '#94a3b8' }} tickLine={false} width={60} tickFormatter={v => formatBytes(v)} />
                      <Tooltip content={<ChartTooltip />} />
                      <Legend verticalAlign="top" height={30} iconType="circle" wrapperStyle={{ fontSize: 11 }} />
                      <Area type="monotone" dataKey="sent" name="Upload" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.15} strokeWidth={2} dot={false} />
                      <Area type="monotone" dataKey="recv" name="Download" stroke="#22c55e" fill="#22c55e" fillOpacity={0.15} strokeWidth={2} dot={false} />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>

            {/* Connections + IPs */}
            <div className="panel">
              <div className="panel-header">
                <div>
                  <div className="panel-title">Active Connections</div>
                  <div className="panel-subtitle">Total connections, unique IPs, external connections</div>
                </div>
              </div>
              <div className="panel-body">
                <div className="chart-container">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={trafficHistory} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
                      <XAxis dataKey="tick" tick={{ fontSize: 10, fill: '#94a3b8' }} tickLine={false} />
                      <YAxis tick={{ fontSize: 10, fill: '#94a3b8' }} tickLine={false} width={30} />
                      <Tooltip content={<ChartTooltip />} />
                      <Legend verticalAlign="top" height={30} iconType="circle" wrapperStyle={{ fontSize: 11 }} />
                      <Line type="monotone" dataKey="connections" name="Connections" stroke="#3b82f6" strokeWidth={2} dot={false} />
                      <Line type="monotone" dataKey="ips" name="Unique IPs" stroke="#f59e0b" strokeWidth={2} dot={false} />
                      <Line type="monotone" dataKey="external" name="External" stroke="#ef4444" strokeWidth={2} dot={false} />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>
          </div>

          {/* ── Charts Row 2: Trust Timeline + Protocol Distribution ── */}
          <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 16, marginBottom: 16 }}>
            {/* Trust Score Timeline */}
            <div className="panel">
              <div className="panel-header">
                <div>
                  <div className="panel-title">Trust Score Timeline</div>
                  <div className="panel-subtitle">Self-learned anomaly detection on your real network traffic</div>
                </div>
              </div>
              <div className="panel-body">
                <div className="chart-container">
                  {trustHistory.length > 0 ? (
                    <ResponsiveContainer width="100%" height="100%">
                      <LineChart data={trustHistory} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
                        <XAxis dataKey="tick" tick={{ fontSize: 10, fill: '#94a3b8' }} tickLine={false} />
                        <YAxis domain={[0, 100]} tick={{ fontSize: 10, fill: '#94a3b8' }} tickLine={false} width={30} />
                        <Tooltip content={<ChartTooltip />} />
                        <Legend verticalAlign="top" height={30} iconType="circle" wrapperStyle={{ fontSize: 11 }} />
                        <Line type="monotone" dataKey="trust" name="Trust Score" stroke="#3b82f6" strokeWidth={2.5} dot={false} />
                        <Line type="monotone" dataKey="anomaly" name="Anomaly (×100)" stroke="#ef4444" strokeWidth={1.5} dot={false} strokeDasharray="4 4" />
                      </LineChart>
                    </ResponsiveContainer>
                  ) : (
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: '#94a3b8', fontSize: 13 }}>
                      {isLearning ? 'Learning baseline — chart will appear after baseline is complete' : 'Waiting for data...'}
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Protocol Distribution */}
            <div className="panel">
              <div className="panel-header">
                <div>
                  <div className="panel-title">Protocols</div>
                  <div className="panel-subtitle">Active application protocols</div>
                </div>
              </div>
              <div className="panel-body" style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: 220 }}>
                {protoData.length > 0 ? (
                  <ResponsiveContainer width="100%" height={220}>
                    <PieChart>
                      <Pie data={protoData} cx="50%" cy="50%" outerRadius={70} innerRadius={35} dataKey="value"
                        label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                        labelLine={{ stroke: '#94a3b8' }}
                      >
                        {protoData.map((_, i) => (
                          <Cell key={i} fill={['#3b82f6', '#22c55e', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899', '#06b6d4', '#84cc16'][i % 8]} />
                        ))}
                      </Pie>
                      <Tooltip />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <div style={{ color: '#94a3b8', fontSize: 13 }}>No connections yet</div>
                )}
              </div>
            </div>
          </div>

          {/* ── Active Connections Table + Alerts ── */}
          <div style={{ display: 'grid', gridTemplateColumns: '3fr 2fr', gap: 16, marginBottom: 16 }}>
            {/* Connections Table */}
            <div className="panel">
              <div className="panel-header">
                <div>
                  <div className="panel-title">Active Connections</div>
                  <div className="panel-subtitle">Real-time network connections from your machine</div>
                </div>
                <span className="live-badge">{latestSnapshot?.active_connections || 0} total</span>
              </div>
              <div className="panel-body no-padding" style={{ maxHeight: 320, overflowY: 'auto' }}>
                {latestSnapshot?.connections?.length > 0 ? (
                  <table className="alerts-table">
                    <thead>
                      <tr>
                        <th>Remote IP</th>
                        <th>Port</th>
                        <th>Protocol</th>
                        <th>Status</th>
                        <th>Type</th>
                      </tr>
                    </thead>
                    <tbody>
                      {latestSnapshot.connections.map((c, i) => (
                        <tr key={i}>
                          <td style={{ fontFamily: 'monospace', fontWeight: 500, color: c.is_external ? '#ef4444' : '#22c55e' }}>
                            {c.remote_ip}
                          </td>
                          <td style={{ fontVariantNumeric: 'tabular-nums' }}>{c.remote_port}</td>
                          <td>
                            <span style={{ fontSize: 10, background: '#f1f5f9', padding: '2px 6px', borderRadius: 4, fontWeight: 600 }}>
                              {c.app_protocol}
                            </span>
                          </td>
                          <td style={{ fontSize: 11, color: c.status === 'ESTABLISHED' ? '#22c55e' : '#94a3b8' }}>{c.status}</td>
                          <td>
                            <span style={{
                              fontSize: 10, fontWeight: 600, padding: '2px 6px', borderRadius: 4,
                              background: c.is_external ? '#fee2e2' : '#dcfce7',
                              color: c.is_external ? '#ef4444' : '#22c55e',
                            }}>
                              {c.is_external ? 'EXTERNAL' : 'INTERNAL'}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <div className="table-empty">No active connections</div>
                )}
              </div>
            </div>

            {/* Alerts Feed */}
            <div className="panel">
              <div className="panel-header">
                <div>
                  <div className="panel-title">Live Alerts</div>
                  <div className="panel-subtitle">Anomalies detected in real traffic</div>
                </div>
                {realAlerts.length > 0 && <span className="live-badge" style={{ background: '#fee2e2', color: '#ef4444' }}>{realAlerts.length}</span>}
              </div>
              <div className="panel-body no-padding" style={{ maxHeight: 320, overflowY: 'auto' }}>
                {realAlerts.length > 0 ? (
                  <table className="alerts-table">
                    <thead>
                      <tr>
                        <th>Time</th>
                        <th>Severity</th>
                        <th>Trust</th>
                        <th>Details</th>
                      </tr>
                    </thead>
                    <tbody>
                      {[...realAlerts].reverse().slice(0, 30).map((a, i) => (
                        <tr key={i}>
                          <td style={{ fontVariantNumeric: 'tabular-nums', fontSize: 11 }}>T+{a.tick}</td>
                          <td><span className={`severity-badge ${(a.severity || 'low').toLowerCase()}`}>{a.severity}</span></td>
                          <td style={{ fontWeight: 600, color: SEVERITY_COLORS[a.severity] }}>{a.trust_score}</td>
                          <td style={{ fontSize: 11, color: '#64748b', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.message}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <div className="table-empty">No anomalies detected — traffic is normal</div>
                )}
              </div>
            </div>
          </div>

          {/* ── Top Drifting Features ── */}
          {latestScoring?.top_drifters && latestScoring.top_drifters.length > 0 && !isLearning && (
            <div className="panel" style={{ marginBottom: 16 }}>
              <div className="panel-header">
                <div>
                  <div className="panel-title">Feature Drift Analysis</div>
                  <div className="panel-subtitle">Top features deviating from your baseline (Z-score)</div>
                </div>
              </div>
              <div className="panel-body">
                <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
                  {latestScoring.top_drifters.map(([feat, z], i) => (
                    <div key={i} style={{
                      flex: '1 1 200px', padding: '12px 16px', borderRadius: 8,
                      background: z > 3 ? '#fef2f2' : z > 1.5 ? '#fffbeb' : '#f0fdf4',
                      border: `1px solid ${z > 3 ? '#fecaca' : z > 1.5 ? '#fde68a' : '#bbf7d0'}`,
                    }}>
                      <div style={{ fontSize: 12, fontWeight: 600, color: '#334155', marginBottom: 4 }}>
                        {feat.replace(/_/g, ' ')}
                      </div>
                      <div style={{ fontSize: 20, fontWeight: 700, color: z > 3 ? '#ef4444' : z > 1.5 ? '#f59e0b' : '#22c55e' }}>
                        Z = {z.toFixed(2)}
                      </div>
                      <div style={{ fontSize: 11, color: '#94a3b8', marginTop: 2 }}>
                        {z < 1.5 ? 'Normal' : z < 3 ? 'Mild drift' : 'Strong drift'}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </>
      )}

      {/* ══════════════════════════════════════
          TAB 2: IoT SIMULATION
         ══════════════════════════════════════ */}
      {activeTab === 'sim' && (
        <>
          {/* ── Control Panel ── */}
          <div className="panel" style={{ marginBottom: 20 }}>
            <div className="panel-body" style={{ padding: '16px 20px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
                {!simRunning ? (
                  <button className="live-btn live-btn-start" onClick={handleSimStart}>
                    <svg viewBox="0 0 24 24" fill="currentColor" width="16" height="16"><polygon points="5 3 19 12 5 21 5 3" /></svg>
                    Start Simulation
                  </button>
                ) : (
                  <button className="live-btn live-btn-stop" onClick={handleSimStop}>
                    <svg viewBox="0 0 24 24" fill="currentColor" width="16" height="16"><rect x="6" y="4" width="4" height="16" /><rect x="14" y="4" width="4" height="16" /></svg>
                    Pause
                  </button>
                )}
                <button className="live-btn live-btn-reset" onClick={handleSimReset}>
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="14" height="14"><path d="M3 12a9 9 0 019-9 9.75 9.75 0 016.74 2.74L21 8" strokeLinecap="round" strokeLinejoin="round" /><path d="M21 3v5h-5" strokeLinecap="round" strokeLinejoin="round" /></svg>
                  Reset
                </button>

                <div style={{ width: 1, height: 28, background: '#e2e8f0', margin: '0 4px' }} />

                {/* Attack Injection */}
                <select className="live-select" value={selectedDevice} onChange={e => { setSelectedDevice(e.target.value); setSelectedAttack(''); }}>
                  <option value="">Select Device...</option>
                  {devices.map(d => <option key={d} value={d}>{d}</option>)}
                </select>
                <select className="live-select" value={selectedAttack} onChange={e => setSelectedAttack(e.target.value)} disabled={!selectedDevice}>
                  <option value="">Select Attack...</option>
                  {selectedDevice && (attackCatalog[deviceTypeMap[selectedDevice]] || []).map(a => (
                    <option key={a.id} value={a.id}>{a.name}</option>
                  ))}
                </select>
                <button className="live-btn live-btn-inject" onClick={handleInject} disabled={!selectedDevice || !selectedAttack || injecting}>
                  {injecting ? 'Injecting...' : (
                    <>
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="14" height="14"><path d="M13 10V3L4 14h7v7l9-11h-7z" strokeLinecap="round" strokeLinejoin="round" /></svg>
                      Inject Attack
                    </>
                  )}
                </button>

                <div style={{ marginLeft: 'auto', display: 'flex', gap: 12, alignItems: 'center' }}>
                  {simStatus && (
                    <>
                      <span className="live-badge">Tick: {simStatus.tick_count}</span>
                      <span className="live-badge">{simStatus.total_anomalous || 0} anomalies</span>
                    </>
                  )}
                </div>
              </div>

              {/* Active Attacks Row */}
              {Object.keys(activeAttacks).length > 0 && (
                <div style={{ marginTop: 10, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  {Object.entries(activeAttacks).map(([devId, info]) => (
                    <span key={devId} className="live-attack-tag">
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="12" height="12"><path d="M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" strokeLinecap="round" strokeLinejoin="round" /></svg>
                      {devId}: {info.attack_name}
                      <button className="live-attack-clear" onClick={() => handleClearAttack(devId)} title="Stop attack">&times;</button>
                    </span>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* ── Device Status Cards ── */}
          {simStatus?.devices?.length > 0 && (
            <div className="device-cards-grid" style={{ marginBottom: 20 }}>
              {simStatus.devices.map(d => {
                const sev = (d.severity || 'low').toLowerCase();
                const isAttacked = !!activeAttacks[d.device_id];
                return (
                  <div key={d.device_id} className={`device-card severity-${sev}`} style={isAttacked ? { borderColor: '#ef4444', boxShadow: '0 0 0 2px rgba(239,68,68,0.2)' } : {}}>
                    <div className="device-card-header">
                      <div>
                        <div className="device-card-name" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          {d.device_id}
                          {isAttacked && <span style={{ fontSize: 10, background: '#fee2e2', color: '#ef4444', padding: '1px 6px', borderRadius: 4, fontWeight: 600 }}>ATTACK</span>}
                        </div>
                        <div className="device-card-type">{d.device_type}</div>
                      </div>
                      <span className={`severity-badge ${sev}`}>{d.severity}</span>
                    </div>
                    <div className="device-card-score">
                      <div className="device-card-score-label">Trust Score</div>
                      <div className={`device-card-score-value ${sev}`}>{d.trust_score}</div>
                    </div>
                    <div className="trust-bar-container">
                      <div className={`trust-bar-fill ${sev}`} style={{ width: `${d.trust_score}%` }} />
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* ── Sim Trust Timeline ── */}
          {simTrustChart.length > 0 && (
            <div className="panel" style={{ marginBottom: 16 }}>
              <div className="panel-header">
                <div>
                  <div className="panel-title">Simulated Trust Scores</div>
                  <div className="panel-subtitle">Trust score per device per tick</div>
                </div>
              </div>
              <div className="panel-body">
                <div className="chart-container">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={simTrustChart} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
                      <XAxis dataKey="label" tick={{ fontSize: 10, fill: '#94a3b8' }} tickLine={false} />
                      <YAxis domain={[0, 100]} tick={{ fontSize: 10, fill: '#94a3b8' }} tickLine={false} width={30} />
                      <Tooltip content={<ChartTooltip />} />
                      <Legend verticalAlign="top" height={30} iconType="circle" wrapperStyle={{ fontSize: 11 }} />
                      {devices.map(id => (
                        <Line key={id} type="monotone" dataKey={id} name={id} stroke={DEVICE_COLORS[id]} strokeWidth={2} dot={false} activeDot={{ r: 3 }} />
                      ))}
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>
          )}

          {/* ── Sim Anomaly Feed + Violations ── */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
            <div className="panel">
              <div className="panel-header">
                <div>
                  <div className="panel-title">Anomaly Feed</div>
                  <div className="panel-subtitle">Anomalous windows from simulation</div>
                </div>
              </div>
              <div className="panel-body no-padding" style={{ maxHeight: 260, overflowY: 'auto' }}>
                {simAnomalies.length === 0 ? (
                  <div className="table-empty">No anomalies detected yet — start simulation</div>
                ) : (
                  <table className="alerts-table">
                    <thead><tr><th>Tick</th><th>Device</th><th>Trust</th><th>Severity</th></tr></thead>
                    <tbody>
                      {[...simAnomalies].reverse().slice(0, 20).map((a, i) => (
                        <tr key={i}>
                          <td>T+{a.tick}</td>
                          <td style={{ fontWeight: 500 }}>{a.device_id}</td>
                          <td style={{ fontWeight: 600, color: SEVERITY_COLORS[a.severity] }}>{a.trust_score}</td>
                          <td><span className={`severity-badge ${(a.severity || 'low').toLowerCase()}`}>{a.severity}</span></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </div>

            <div className="panel">
              <div className="panel-header">
                <div>
                  <div className="panel-title">Policy Violations</div>
                  <div className="panel-subtitle">Rule violations in simulated traffic</div>
                </div>
              </div>
              <div className="panel-body no-padding" style={{ maxHeight: 260, overflowY: 'auto' }}>
                {simViolations.length === 0 ? (
                  <div className="table-empty">No violations detected</div>
                ) : (
                  <table className="alerts-table">
                    <thead><tr><th>Tick</th><th>Device</th><th>Types</th><th>Details</th></tr></thead>
                    <tbody>
                      {[...simViolations].reverse().slice(0, 20).map((v, i) => (
                        <tr key={i}>
                          <td>T+{v.tick}</td>
                          <td style={{ fontWeight: 500 }}>{v.device_id}</td>
                          <td>
                            {(v.violation_types || []).map((t, j) => (
                              <span key={j} style={{ display: 'inline-block', fontSize: 10, background: '#fee2e2', color: '#dc2626', padding: '1px 6px', borderRadius: 4, marginRight: 4, fontWeight: 600 }}>
                                {t.replace('_violation', '')}
                              </span>
                            ))}
                          </td>
                          <td style={{ fontSize: 11, color: '#64748b', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {(v.violations || []).join('; ')}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </div>
          </div>
        </>
      )}

      {/* ── Message Toast ── */}
      {message && (
        <div style={{
          position: 'fixed', bottom: 24, right: 24, background: '#1e293b', color: '#fff',
          padding: '12px 20px', borderRadius: 10, fontSize: 13, fontWeight: 500,
          boxShadow: '0 8px 24px rgba(0,0,0,0.15)', zIndex: 9999,
          animation: 'fadeIn 0.3s ease',
        }}>
          {message}
        </div>
      )}
    </>
  );
}

export default Live;
