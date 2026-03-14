import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Legend,
} from 'recharts';

const API = 'http://localhost:8002/api';

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

const DEVICE_ICONS = {
  CCTV_01: '📷',
  Router_01: '🌐',
  Access_01: '🔑',
};

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
          <span>{typeof p.value === 'number' ? p.value.toFixed(1) : p.value}</span>
        </div>
      ))}
    </div>
  );
}

/* ══════════════════════════════════════════════
   LIVE IoT MONITOR
   ══════════════════════════════════════════════ */

function Live() {
  const [simRunning, setSimRunning]       = useState(false);
  const [simStatus, setSimStatus]         = useState(null);
  const [simTimeline, setSimTimeline]     = useState([]);
  const [simAnomalies, setSimAnomalies]   = useState([]);
  const [simViolations, setSimViolations] = useState([]);
  const [attackCatalog, setAttackCatalog] = useState({});
  const [selectedDevice, setSelectedDevice] = useState('');
  const [selectedAttack, setSelectedAttack] = useState('');
  const [injecting, setInjecting]         = useState(false);
  const [message, setMessage]             = useState('');

  const pollRef = useRef(null);

  useEffect(() => {
    axios.get(`${API}/attack-catalog`).then(r => setAttackCatalog(r.data)).catch(() => {});
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, []);

  // ── Poll ALL simulation data every 3s (no WebSocket dependency) ──
  useEffect(() => {
    const fetchSim = async () => {
      try {
        const [statusRes, tlRes, anomRes, violRes] = await Promise.all([
          axios.get(`${API}/live/status`),
          axios.get(`${API}/live/timeline?last_n=100`),
          axios.get(`${API}/live/anomalies?last_n=50`),
          axios.get(`${API}/live/violations?last_n=50`),
        ]);
        // Use HTTP status as primary source — no WebSocket needed
        setSimStatus(statusRes.data);
        setSimRunning(statusRes.data?.running === true);
        setSimTimeline(tlRes.data);
        setSimAnomalies(anomRes.data);
        setSimViolations(violRes.data);
      } catch {}
    };
    fetchSim();
    pollRef.current = setInterval(fetchSim, 3000);
    return () => clearInterval(pollRef.current);
  }, []);

  // ── Handlers ──
  async function handleStart() {
    try {
      await axios.post(`${API}/live/start?interval=10`);
      setSimRunning(true);
      setMessage('✅ Simulation started — first data in ~10 seconds');
      setTimeout(() => setMessage(''), 5000);
      // Immediately fetch status so UI updates without waiting for next poll
      const res = await axios.get(`${API}/live/status`);
      setSimStatus(res.data);
    } catch { setMessage('❌ Failed to start — is backend running?'); }
  }

  async function handleStop() {
    try {
      await axios.post(`${API}/live/stop`);
      setSimRunning(false);
      setMessage('Simulation paused');
      setTimeout(() => setMessage(''), 3000);
    } catch { setMessage('Failed to stop'); }
  }

  async function handleReset() {
    try {
      await axios.post(`${API}/live/reset`);
      setSimTimeline([]);
      setSimAnomalies([]);
      setSimViolations([]);
      setMessage('Simulation reset to clean baseline');
      setTimeout(() => setMessage(''), 3000);
    } catch { setMessage('Failed to reset'); }
  }

  async function handleInject() {
    if (!selectedDevice || !selectedAttack) return;
    setInjecting(true);
    try {
      const res = await axios.post(`${API}/live/inject`, {
        device_id: selectedDevice,
        attack_type: selectedAttack,
      });
      setMessage(`⚠ Attack "${res.data.attack_name}" injected on ${selectedDevice}`);
      setTimeout(() => setMessage(''), 5000);
    } catch { setMessage('Injection failed'); }
    setInjecting(false);
  }

  async function handleClearAttack(deviceId) {
    try {
      await axios.post(`${API}/live/clear-attack?device_id=${deviceId}`);
      setMessage(`Attack cleared on ${deviceId}`);
      setTimeout(() => setMessage(''), 3000);
    } catch { setMessage('Failed to clear'); }
  }

  // ── Derived ──
  const devices        = ['CCTV_01', 'Router_01', 'Access_01'];
  const deviceTypeMap  = { CCTV_01: 'CCTV', Router_01: 'Router', Access_01: 'AccessController' };
  const activeAttacks  = simStatus?.active_attacks || {};

  // Build trust chart data
  const simGrouped = {};
  simTimeline.forEach(w => {
    if (!simGrouped[w.tick]) simGrouped[w.tick] = { tick: w.tick, label: `T+${w.tick}` };
    simGrouped[w.tick][w.device_id] = w.trust_score_smoothed;
  });
  const simTrustChart = Object.values(simGrouped).sort((a, b) => a.tick - b.tick);

  return (
    <>
      {/* ── Page Title ── */}
      <div className="page-title-section">
        <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          Live IoT Monitor
          {simRunning
            ? <PulseDot color="#22c55e" />
            : <span style={{ fontSize: 11, color: '#94a3b8', fontWeight: 500 }}>IDLE</span>}
        </h1>
        <p className="page-subtitle">
          Real-time simulation of 3 IoT devices — inject attacks and watch trust scores respond
        </p>
      </div>

      {/* ── Sim Status Bar ── */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap',
        padding: '14px 20px', borderRadius: 12, marginBottom: 16,
        background: simRunning ? '#f0fdf4' : '#f8fafc',
        border: `1.5px solid ${simRunning ? '#86efac' : '#e2e8f0'}`,
      }}>
        {/* Run / Pause */}
        {!simRunning ? (
          <button className="live-btn live-btn-start" onClick={handleStart}>
            <svg viewBox="0 0 24 24" fill="currentColor" width="15" height="15"><polygon points="5 3 19 12 5 21 5 3" /></svg>
            Start Simulation
          </button>
        ) : (
          <button className="live-btn live-btn-stop" onClick={handleStop}>
            <svg viewBox="0 0 24 24" fill="currentColor" width="15" height="15"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg>
            Pause
          </button>
        )}

        <button className="live-btn live-btn-reset" onClick={handleReset}>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="13" height="13" strokeLinecap="round" strokeLinejoin="round">
            <path d="M3 12a9 9 0 019-9 9.75 9.75 0 016.74 2.74L21 8"/><path d="M21 3v5h-5"/>
          </svg>
          Reset
        </button>

        <div style={{ width: 1, height: 28, background: '#e2e8f0', margin: '0 4px' }} />

        {/* Attack injection */}
        <select className="live-select" value={selectedDevice}
          onChange={e => { setSelectedDevice(e.target.value); setSelectedAttack(''); }}>
          <option value="">Select Device...</option>
          {devices.map(d => <option key={d} value={d}>{DEVICE_ICONS[d]} {d}</option>)}
        </select>

        <select className="live-select" value={selectedAttack}
          onChange={e => setSelectedAttack(e.target.value)} disabled={!selectedDevice}>
          <option value="">Select Attack...</option>
          {selectedDevice && (attackCatalog[deviceTypeMap[selectedDevice]] || []).map(a => (
            <option key={a.id} value={a.id}>{a.name}</option>
          ))}
        </select>

        <button className="live-btn live-btn-inject"
          onClick={handleInject} disabled={!selectedDevice || !selectedAttack || injecting}>
          {injecting ? 'Injecting...' : (
            <>
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="13" height="13" strokeLinecap="round" strokeLinejoin="round">
                <path d="M13 10V3L4 14h7v7l9-11h-7z"/>
              </svg>
              Inject Attack
            </>
          )}
        </button>

        <div style={{ marginLeft: 'auto', display: 'flex', gap: 10, alignItems: 'center' }}>
          {simStatus && (
            <>
              <span className="live-badge" style={{ background: simRunning ? '#dcfce7' : '#f1f5f9', color: simRunning ? '#16a34a' : '#64748b' }}>
                {simRunning ? '● LIVE' : '◼ PAUSED'}
              </span>
              <span className="live-badge">Tick: {simStatus.tick_count || 0}</span>
              <span className="live-badge">{simStatus.total_anomalous || 0} anomalies</span>
            </>
          )}
        </div>
      </div>

      {/* Active attack tags */}
      {Object.keys(activeAttacks).length > 0 && (
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 16 }}>
          {Object.entries(activeAttacks).map(([devId, info]) => (
            <span key={devId} className="live-attack-tag">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="12" height="12">
                <path d="M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
              {devId}: {info.attack_name}
              <button className="live-attack-clear" onClick={() => handleClearAttack(devId)}>&times;</button>
            </span>
          ))}
        </div>
      )}

      {/* ── Device Status Cards ── */}
      {simStatus?.devices?.length > 0 && (
        <div className="device-cards-grid" style={{ marginBottom: 20 }}>
          {simStatus.devices.map(d => {
            const sev        = (d.severity || 'low').toLowerCase();
            const isAttacked = !!activeAttacks[d.device_id];
            return (
              <div key={d.device_id} className={`device-card severity-${sev}`}
                style={isAttacked ? { borderColor: '#ef4444', boxShadow: '0 0 0 3px rgba(239,68,68,0.15)' } : {}}>

                {isAttacked && (
                  <div style={{
                    background: '#ef4444', color: '#fff', fontSize: 10, fontWeight: 700,
                    textAlign: 'center', padding: '4px 0', letterSpacing: 1,
                    display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6,
                  }}>
                    <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#fff', animation: 'pulse-ring 1.2s infinite', display: 'inline-block' }} />
                    ATTACK ACTIVE
                  </div>
                )}

                <div className="device-card-header" style={{ padding: isAttacked ? '14px 16px 0' : undefined }}>
                  <div>
                    <div className="device-card-name" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span style={{ fontSize: 18 }}>{DEVICE_ICONS[d.device_id] || '📡'}</span>
                      {d.device_id}
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

                {/* Anomaly score if available */}
                {d.anomaly_score != null && (
                  <div style={{ padding: '8px 16px', fontSize: 11, color: '#64748b', display: 'flex', justifyContent: 'space-between' }}>
                    <span>Anomaly score</span>
                    <span style={{ fontWeight: 600, color: d.anomaly_score > 0.6 ? '#ef4444' : '#94a3b8' }}>
                      {d.anomaly_score.toFixed(3)}
                    </span>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Empty state before sim starts */}
      {!simStatus?.devices?.length && (
        <div style={{
          textAlign: 'center', padding: '48px 24px', borderRadius: 16,
          background: '#f8fafc', border: '2px dashed #e2e8f0', marginBottom: 20,
        }}>
          <div style={{ fontSize: 48, marginBottom: 12 }}>📡</div>
          <div style={{ fontSize: 16, fontWeight: 700, color: '#334155', marginBottom: 6 }}>
            No Live Data Yet
          </div>
          <div style={{ fontSize: 13, color: '#94a3b8', marginBottom: 20 }}>
            Press <strong>Start Simulation</strong> to begin generating IoT device traffic
          </div>
          <button className="live-btn live-btn-start" onClick={handleStart} style={{ margin: '0 auto' }}>
            <svg viewBox="0 0 24 24" fill="currentColor" width="15" height="15"><polygon points="5 3 19 12 5 21 5 3"/></svg>
            Start Simulation
          </button>
        </div>
      )}

      {/* ── Trust Score Timeline ── */}
      {simTrustChart.length > 0 && (
        <div className="panel" style={{ marginBottom: 16 }}>
          <div className="panel-header">
            <div>
              <div className="panel-title">Trust Score Timeline</div>
              <div className="panel-subtitle">
                Per-device smoothed trust score — drops indicate detected anomalies
                {Object.keys(activeAttacks).length > 0 &&
                  <span style={{ color: '#ef4444', fontWeight: 600 }}> ⚠ Attack active</span>}
              </div>
            </div>
            <span className="live-badge">
              {simTrustChart.length} ticks
            </span>
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
                    <Line key={id} type="monotone" dataKey={id} name={id}
                      stroke={DEVICE_COLORS[id]} strokeWidth={2.5} dot={false}
                      activeDot={{ r: 4, strokeWidth: 0 }} />
                  ))}
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      )}

      {/* ── Anomaly Feed + Policy Violations ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>

        {/* Anomaly Feed */}
        <div className="panel">
          <div className="panel-header">
            <div>
              <div className="panel-title">Anomaly Feed</div>
              <div className="panel-subtitle">Windows flagged by Isolation Forest</div>
            </div>
            {simAnomalies.length > 0 &&
              <span className="live-badge" style={{ background: '#fee2e2', color: '#ef4444' }}>
                {simAnomalies.length}
              </span>}
          </div>
          <div className="panel-body no-padding" style={{ maxHeight: 280, overflowY: 'auto' }}>
            {simAnomalies.length === 0 ? (
              <div className="table-empty">No anomalies yet — start simulation</div>
            ) : (
              <table className="alerts-table">
                <thead><tr><th>Tick</th><th>Device</th><th>Trust</th><th>Severity</th></tr></thead>
                <tbody>
                  {[...simAnomalies].reverse().slice(0, 25).map((a, i) => (
                    <tr key={i}>
                      <td style={{ color: '#64748b' }}>T+{a.tick}</td>
                      <td style={{ fontWeight: 600 }}>{a.device_id}</td>
                      <td style={{ fontWeight: 700, color: SEVERITY_COLORS[a.severity] }}>{a.trust_score}</td>
                      <td><span className={`severity-badge ${(a.severity || 'low').toLowerCase()}`}>{a.severity}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* Policy Violations */}
        <div className="panel">
          <div className="panel-header">
            <div>
              <div className="panel-title">Policy Violations</div>
              <div className="panel-subtitle">Rules broken by simulated traffic</div>
            </div>
            {simViolations.length > 0 &&
              <span className="live-badge" style={{ background: '#fff7ed', color: '#f97316' }}>
                {simViolations.length}
              </span>}
          </div>
          <div className="panel-body no-padding" style={{ maxHeight: 280, overflowY: 'auto' }}>
            {simViolations.length === 0 ? (
              <div className="table-empty">No violations detected</div>
            ) : (
              <table className="alerts-table">
                <thead><tr><th>Tick</th><th>Device</th><th>Violation</th></tr></thead>
                <tbody>
                  {[...simViolations].reverse().slice(0, 25).map((v, i) => (
                    <tr key={i}>
                      <td style={{ color: '#64748b' }}>T+{v.tick}</td>
                      <td style={{ fontWeight: 600 }}>{v.device_id}</td>
                      <td>
                        {(v.violation_types || []).map((t, j) => (
                          <span key={j} style={{
                            display: 'inline-block', fontSize: 10, fontWeight: 600,
                            background: '#fee2e2', color: '#dc2626',
                            padding: '2px 7px', borderRadius: 4, marginRight: 4,
                          }}>
                            {t.replace('_violation', '').toUpperCase()}
                          </span>
                        ))}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>

      {/* ── Toast ── */}
      {message && (
        <div style={{
          position: 'fixed', bottom: 24, right: 24,
          background: '#1e293b', color: '#fff',
          padding: '12px 20px', borderRadius: 10,
          fontSize: 13, fontWeight: 500,
          boxShadow: '0 8px 24px rgba(0,0,0,0.15)', zIndex: 9999,
        }}>
          {message}
        </div>
      )}
    </>
  );
}

export default Live;
