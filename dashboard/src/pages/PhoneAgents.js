import React, { useState, useEffect, useRef, useCallback } from 'react';
import axios from 'axios';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, ReferenceLine, AreaChart, Area, Legend,
} from 'recharts';

const API = 'http://localhost:8002/api';

// Colour per device
const DEVICE_COLORS = {
  CCTV_01:   '#3b82f6',
  Router_01: '#f59e0b',
  Access_01: '#22c55e',
};
const DEVICE_ICONS  = { CCTV_01: '📷', Router_01: '🌐', Access_01: '🔐' };

function trustColor(score) {
  if (score >= 70) return '#22c55e';
  if (score >= 40) return '#f59e0b';
  return '#ef4444';
}
function severityClass(s) {
  if (s === 'Critical') return 'critical';
  if (s === 'High')     return 'high';
  if (s === 'Medium')   return 'medium';
  return 'low';
}
function fmt(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  return `${d.getHours().toString().padStart(2,'0')}:${d.getMinutes().toString().padStart(2,'0')}:${d.getSeconds().toString().padStart(2,'0')}`;
}

// ── Radial trust gauge ────────────────────────────────────
function TrustGauge({ score }) {
  const r = 44, cx = 54, cy = 54;
  const circ = 2 * Math.PI * r;
  const pct  = Math.max(0, Math.min(100, score)) / 100;
  const dash = pct * circ;
  const color = trustColor(score);
  return (
    <svg width={108} height={108}>
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="#f1f5f9" strokeWidth={10} />
      <circle cx={cx} cy={cy} r={r} fill="none" stroke={color} strokeWidth={10}
        strokeDasharray={`${dash} ${circ - dash}`}
        strokeLinecap="round"
        transform={`rotate(-90 ${cx} ${cy})`}
        style={{ transition: 'stroke-dasharray 0.6s ease' }}
      />
      <text x={cx} y={cy - 4} textAnchor="middle" fontSize={18} fontWeight="700" fill={color}>{Math.round(score)}</text>
      <text x={cx} y={cy + 14} textAnchor="middle" fontSize={10} fill="#94a3b8">TRUST</text>
    </svg>
  );
}

// ── Pulse dot (live indicator) ────────────────────────────
function PulseDot({ active }) {
  return (
    <span style={{ display: 'inline-block', width: 10, height: 10, borderRadius: '50%',
      background: active ? '#22c55e' : '#94a3b8',
      boxShadow: active ? '0 0 0 3px #22c55e44' : 'none',
      animation: active ? 'pulse 1.5s infinite' : 'none',
      verticalAlign: 'middle', marginRight: 5 }} />
  );
}

// ═══════════════════════════════════════════════════════════
export default function PhoneAgents() {
  const [connInfo,  setConnInfo]  = useState(null);
  const [agents,    setAgents]    = useState([]);   // latest per-device records
  const [history,   setHistory]   = useState([]);   // all history
  const [selected,  setSelected]  = useState(null); // device_id for detail view
  const [lastSeen,  setLastSeen]  = useState({});   // device_id → Date
  const pollRef = useRef(null);

  // Fetch connection info once
  useEffect(() => {
    axios.get(`${API}/phone/connection-info`).then(r => setConnInfo(r.data)).catch(() => {});
  }, []);

  // Poll agents + history every 3 s
  const poll = useCallback(async () => {
    try {
      const [aRes, hRes] = await Promise.all([
        axios.get(`${API}/phone/devices`),
        axios.get(`${API}/phone/history?last_n=200`),
      ]);
      setAgents(aRes.data);
      setHistory(hRes.data);

      // Update last-seen timestamps
      const now = new Date();
      const seen = {};
      aRes.data.forEach(a => { seen[a.device_id] = now; });
      setLastSeen(prev => ({ ...prev, ...seen }));
    } catch (_) {}
  }, []);

  useEffect(() => {
    poll();
    pollRef.current = setInterval(poll, 3000);
    return () => clearInterval(pollRef.current);
  }, [poll]);

  // Is an agent "live" (seen within last 20 s)?
  function isLive(deviceId) {
    const t = lastSeen[deviceId];
    return t && (new Date() - t) < 20000;
  }

  // Per-device history for charts
  function deviceHistory(deviceId) {
    return history.filter(h => h.device_id === deviceId).slice(-50);
  }

  // Trust timeline merged (all devices on same axis)
  const trustTimeline = (() => {
    const byTime = {};
    history.forEach(h => {
      const k = h.received_at || h.window;
      if (!byTime[k]) byTime[k] = { time: k };
      byTime[k][h.device_id] = h.trust_score_smoothed;
      byTime[k][h.device_id + '_mode'] = h.mode;
    });
    return Object.values(byTime)
      .sort((a, b) => new Date(a.time) - new Date(b.time))
      .slice(-80);
  })();

  return (
    <>
      <style>{`
        @keyframes pulse { 0%,100%{box-shadow:0 0 0 3px #22c55e44} 50%{box-shadow:0 0 0 8px #22c55e11} }
        .phone-card { background:#fff; border-radius:14px; border:1px solid #e2e8f0; padding:20px; transition:box-shadow 0.2s; }
        .phone-card:hover { box-shadow:0 4px 20px #0001; }
        .phone-card.selected { border-color:#3b82f6; box-shadow:0 0 0 2px #3b82f644; }
        .mode-badge-normal   { background:#dcfce7; color:#15803d; border:1px solid #bbf7d0; }
        .mode-badge-malicious{ background:#fee2e2; color:#dc2626; border:1px solid #fecaca; }
      `}</style>

      <div className="page-title-section">
        <h1 className="page-title">📱 Phone Agent Nodes</h1>
        <p className="page-subtitle">Real phones acting as live IoT devices — normal or malicious mode</p>
      </div>

      {/* ── Connection Setup Banner ── */}
      <div style={{ background: 'linear-gradient(135deg, #0f172a 0%, #1e293b 100%)', borderRadius: 14,
        padding: '20px 24px', marginBottom: 20, border: '1px solid #334155' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 20, flexWrap: 'wrap' }}>
          <div>
            <div style={{ color: '#f1f5f9', fontWeight: 700, fontSize: 16, marginBottom: 4 }}>
              📡 Connect a Phone — Same WiFi Required
            </div>
            <div style={{ color: '#94a3b8', fontSize: 13, marginBottom: 14 }}>
              Install Python on Termux, then run the agent with your laptop's IP below.
            </div>

            {/* Install steps */}
            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
              {[
                { n: '1', cmd: 'pkg install python', label: 'Install Python (Termux)' },
                { n: '2', cmd: 'pip install requests', label: 'Install requests' },
                { n: '3', cmd: `python agent.py --role CCTV_01 --server ${connInfo?.server_url || 'http://LAPTOP_IP:8002'}`, label: 'Run agent (normal mode)' },
                { n: '4', cmd: `python agent.py --role CCTV_01 --mode malicious --server ${connInfo?.server_url || 'http://LAPTOP_IP:8002'}`, label: 'Run agent (malicious mode)' },
              ].map(s => (
                <div key={s.n} style={{ background: '#0f172a', borderRadius: 8, padding: '8px 12px', border: '1px solid #1e293b', minWidth: 200, flex: '1' }}>
                  <div style={{ fontSize: 10, color: '#64748b', marginBottom: 4 }}>Step {s.n} — {s.label}</div>
                  <code style={{ fontSize: 11, color: '#7dd3fc', fontFamily: 'monospace', wordBreak: 'break-all' }}>{s.cmd}</code>
                </div>
              ))}
            </div>
          </div>

          {/* Laptop IP big display */}
          <div style={{ textAlign: 'center', background: '#0f172a', borderRadius: 12, padding: '16px 24px', border: '1px solid #22c55e44', minWidth: 180 }}>
            <div style={{ color: '#64748b', fontSize: 11, marginBottom: 4 }}>Your Laptop IP</div>
            <div style={{ color: '#22c55e', fontSize: 26, fontWeight: 800, fontFamily: 'monospace', letterSpacing: 1 }}>
              {connInfo?.laptop_ip || '—'}
            </div>
            <div style={{ color: '#64748b', fontSize: 11, marginTop: 4 }}>port 8002</div>
            <div style={{ marginTop: 10, fontSize: 11, color: '#94a3b8' }}>
              {agents.length > 0
                ? <><PulseDot active />{agents.length} phone{agents.length !== 1 ? 's' : ''} connected</>
                : '⏳ Waiting for agents…'}
            </div>
          </div>
        </div>
      </div>

      {/* ── No agents yet ── */}
      {agents.length === 0 && (
        <div className="panel" style={{ textAlign: 'center', padding: 48 }}>
          <div style={{ fontSize: 56, marginBottom: 16 }}>📱</div>
          <div style={{ fontWeight: 700, fontSize: 18, color: '#1e293b', marginBottom: 8 }}>
            No phone agents connected yet
          </div>
          <div style={{ color: '#64748b', fontSize: 14, maxWidth: 480, margin: '0 auto' }}>
            Follow the setup steps above to connect a phone. Each phone will appear here as a live IoT device
            with real-time trust scoring.
          </div>
        </div>
      )}

      {/* ── Agent Cards ── */}
      {agents.length > 0 && (
        <>
          {/* Summary row */}
          <div className="stats-bar" style={{ marginBottom: 16 }}>
            {agents.map(a => (
              <div key={a.device_id} className={`phone-card${selected === a.device_id ? ' selected' : ''}`}
                style={{ cursor: 'pointer', flex: 1 }} onClick={() => setSelected(s => s === a.device_id ? null : a.device_id)}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  <TrustGauge score={a.trust_score_smoothed || 100} />
                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                      <PulseDot active={isLive(a.device_id)} />
                      <span style={{ fontWeight: 700, fontSize: 14 }}>{DEVICE_ICONS[a.device_id] || '📱'} {a.device_id}</span>
                    </div>
                    <div style={{ marginBottom: 6 }}>
                      <span className={`mode-badge-${a.mode || 'normal'}`}
                        style={{ fontSize: 11, padding: '2px 10px', borderRadius: 20, fontWeight: 700 }}>
                        {a.mode === 'malicious' ? '🔴 MALICIOUS' : '🟢 NORMAL'}
                      </span>
                    </div>
                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', fontSize: 11, color: '#64748b' }}>
                      <span>Anomaly: <strong style={{ color: a.is_anomaly ? '#ef4444' : '#22c55e' }}>{a.is_anomaly ? 'YES' : 'NO'}</strong></span>
                      <span>Drift: <strong>{a.drift_class || 'NONE'}</strong></span>
                      <span>Policy: <span className={`severity-badge ${a.policy_status === 'COMPLIANT' ? 'low' : a.policy_status === 'SOFT_DRIFT' ? 'medium' : 'high'}`}
                        style={{ fontSize: 10 }}>{a.policy_status}</span></span>
                    </div>
                    <div style={{ marginTop: 6, fontSize: 10, color: '#94a3b8' }}>
                      Last seen: {fmt(a.received_at)}
                    </div>
                  </div>
                </div>

                {/* Mini stats */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 6, marginTop: 14 }}>
                  {[
                    { label: 'Bytes Out', value: `${((a.total_bytes_out || 0) / 1024).toFixed(1)} KB` },
                    { label: 'Ext %',     value: `${((a.external_ratio || 0) * 100).toFixed(0)}%` },
                    { label: 'Flows',     value: a.num_flows || 0 },
                  ].map(m => (
                    <div key={m.label} style={{ background: '#f8fafc', borderRadius: 8, padding: '6px 10px', textAlign: 'center' }}>
                      <div style={{ fontSize: 13, fontWeight: 700, color: '#1e293b' }}>{m.value}</div>
                      <div style={{ fontSize: 10, color: '#94a3b8' }}>{m.label}</div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>

          {/* ── Detail Panel (expanded on click) ── */}
          {selected && (() => {
            const dh = deviceHistory(selected);
            const agent = agents.find(a => a.device_id === selected);
            if (!agent) return null;
            return (
              <div className="panel" style={{ marginBottom: 16, borderTop: `4px solid ${DEVICE_COLORS[selected] || '#3b82f6'}` }}>
                <div className="panel-header">
                  <div>
                    <div className="panel-title">{DEVICE_ICONS[selected]} {selected} — Live Detail</div>
                    <div className="panel-subtitle">Trust score + feature timeline (last {dh.length} readings)</div>
                  </div>
                  <button onClick={() => setSelected(null)}
                    style={{ background: '#f1f5f9', border: 'none', borderRadius: 8, padding: '6px 12px', cursor: 'pointer', fontSize: 12, color: '#64748b' }}>
                    ✕ Close
                  </button>
                </div>

                <div className="panel-body">
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                    {/* Trust over time */}
                    <div>
                      <div style={{ fontWeight: 600, fontSize: 13, color: '#334155', marginBottom: 8 }}>Trust Score Timeline</div>
                      <div style={{ height: 180 }}>
                        <ResponsiveContainer width="100%" height="100%">
                          <AreaChart data={dh} margin={{ top: 4, right: 8, left: 0, bottom: 0 }}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
                            <XAxis dataKey="received_at" tick={{ fontSize: 9, fill: '#94a3b8' }} tickFormatter={fmt} interval="preserveStartEnd" tickLine={false} />
                            <YAxis domain={[0, 100]} tick={{ fontSize: 9, fill: '#94a3b8' }} width={25} tickLine={false} />
                            <Tooltip contentStyle={{ fontSize: 11, borderRadius: 8 }} formatter={v => `${v?.toFixed(1)}%`} labelFormatter={fmt} />
                            <ReferenceLine y={60} stroke="#ef4444" strokeDasharray="4 3" />
                            <Area type="monotone" dataKey="trust_score_smoothed" name="Trust"
                              stroke={DEVICE_COLORS[selected] || '#3b82f6'} fill={DEVICE_COLORS[selected] || '#3b82f6'} fillOpacity={0.15} strokeWidth={2} dot={false} />
                          </AreaChart>
                        </ResponsiveContainer>
                      </div>
                    </div>

                    {/* External ratio over time */}
                    <div>
                      <div style={{ fontWeight: 600, fontSize: 13, color: '#334155', marginBottom: 8 }}>External Ratio & Bytes Out</div>
                      <div style={{ height: 180 }}>
                        <ResponsiveContainer width="100%" height="100%">
                          <LineChart data={dh} margin={{ top: 4, right: 8, left: 0, bottom: 0 }}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
                            <XAxis dataKey="received_at" tick={{ fontSize: 9, fill: '#94a3b8' }} tickFormatter={fmt} interval="preserveStartEnd" tickLine={false} />
                            <YAxis yAxisId="ext" domain={[0, 1]} tick={{ fontSize: 9, fill: '#94a3b8' }} width={25} tickLine={false} tickFormatter={v => `${(v * 100).toFixed(0)}%`} />
                            <YAxis yAxisId="bytes" orientation="right" tick={{ fontSize: 9, fill: '#94a3b8' }} width={40} tickLine={false} tickFormatter={v => `${(v / 1000).toFixed(0)}K`} />
                            <Tooltip contentStyle={{ fontSize: 11, borderRadius: 8 }} />
                            <ReferenceLine yAxisId="ext" y={0.5} stroke="#ef4444" strokeDasharray="4 3" />
                            <Line yAxisId="ext"   type="monotone" dataKey="external_ratio" name="Ext %" stroke="#ef4444" strokeWidth={2} dot={false} />
                            <Line yAxisId="bytes" type="monotone" dataKey="total_bytes_out" name="Bytes" stroke="#f59e0b" strokeWidth={1.5} dot={false} />
                            <Legend verticalAlign="top" height={24} wrapperStyle={{ fontSize: 10 }} />
                          </LineChart>
                        </ResponsiveContainer>
                      </div>
                    </div>
                  </div>

                  {/* Scoring detail strip */}
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 8, marginTop: 14 }}>
                    {[
                      { label: 'Anomaly Score',     value: ((agent.anomaly_score || 0) * 100).toFixed(1) + '%', color: agent.is_anomaly ? '#ef4444' : '#22c55e' },
                      { label: 'Anomaly Deduction', value: `-${(agent.anomaly_deduction || 0).toFixed(1)}`, color: '#f59e0b' },
                      { label: 'Drift Deduction',   value: `-${agent.drift_deduction || 0}`,               color: '#f59e0b' },
                      { label: 'Policy Deduction',  value: `-${agent.policy_deduction || 0}`,              color: '#f59e0b' },
                    ].map(m => (
                      <div key={m.label} style={{ background: '#f8fafc', borderRadius: 8, padding: '10px 12px', textAlign: 'center' }}>
                        <div style={{ fontSize: 15, fontWeight: 700, color: m.color }}>{m.value}</div>
                        <div style={{ fontSize: 10, color: '#94a3b8', marginTop: 2 }}>{m.label}</div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            );
          })()}

          {/* ── All-device trust timeline ── */}
          <div className="panel" style={{ marginBottom: 16 }}>
            <div className="panel-header">
              <div>
                <div className="panel-title">All Phone Agents — Trust Timeline</div>
                <div className="panel-subtitle">Red zones = malicious mode detected via ML</div>
              </div>
            </div>
            <div className="panel-body"><div className="chart-container">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={trustTimeline} margin={{ top: 8, right: 20, left: 0, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
                  <XAxis dataKey="time" tick={{ fontSize: 9, fill: '#94a3b8' }} tickFormatter={fmt} interval="preserveStartEnd" tickLine={false} />
                  <YAxis domain={[0, 100]} tick={{ fontSize: 10, fill: '#94a3b8' }} width={28} tickLine={false} />
                  <Tooltip contentStyle={{ fontSize: 11, borderRadius: 8 }} formatter={v => v != null ? `${v.toFixed(1)}` : 'N/A'} labelFormatter={fmt} />
                  <ReferenceLine y={60} stroke="#ef4444" strokeDasharray="4 3" label={{ value: 'Alert', position: 'insideTopRight', fontSize: 10, fill: '#ef4444' }} />
                  {agents.map(a => (
                    <Line key={a.device_id} type="monotone" dataKey={a.device_id} name={a.device_id}
                      stroke={DEVICE_COLORS[a.device_id] || '#94a3b8'} strokeWidth={2.5} dot={false} activeDot={{ r: 4 }} connectNulls />
                  ))}
                  <Legend verticalAlign="top" height={28} wrapperStyle={{ fontSize: 11 }} />
                </LineChart>
              </ResponsiveContainer>
            </div></div>
          </div>

          {/* ── Live feed table ── */}
          <div className="panel">
            <div className="panel-header">
              <div>
                <div className="panel-title">Live Feed</div>
                <div className="panel-subtitle">Most recent telemetry readings from all phone agents</div>
              </div>
              <span style={{ fontSize: 11, color: '#94a3b8' }}>Auto-refresh every 3s</span>
            </div>
            <div className="panel-body no-padding" style={{ maxHeight: 340, overflowY: 'auto' }}>
              <table className="alerts-table">
                <thead>
                  <tr>
                    <th>Time</th><th>Device</th><th>Mode</th><th>Trust</th>
                    <th>Anomaly</th><th>Drift</th><th>Policy</th>
                    <th>Bytes Out</th><th>Ext %</th><th>Flows</th>
                  </tr>
                </thead>
                <tbody>
                  {[...history].reverse().slice(0, 60).map((h, i) => (
                    <tr key={i} style={{ background: h.mode === 'malicious' ? '#fff5f5' : undefined }}>
                      <td style={{ fontSize: 10, fontFamily: 'monospace' }}>{fmt(h.received_at)}</td>
                      <td style={{ fontWeight: 600 }}>{DEVICE_ICONS[h.device_id]} {h.device_id}</td>
                      <td>
                        <span style={{ fontSize: 10, fontWeight: 700, padding: '2px 8px', borderRadius: 20,
                          ...(h.mode === 'malicious' ? { background: '#fee2e2', color: '#dc2626' } : { background: '#dcfce7', color: '#15803d' }) }}>
                          {h.mode === 'malicious' ? '🔴' : '🟢'} {h.mode}
                        </span>
                      </td>
                      <td style={{ fontWeight: 700, color: trustColor(h.trust_score_smoothed) }}>{(h.trust_score_smoothed || 0).toFixed(1)}</td>
                      <td style={{ color: h.is_anomaly ? '#ef4444' : '#22c55e', fontWeight: 600 }}>{h.is_anomaly ? '⚠ YES' : '✓ NO'}</td>
                      <td style={{ fontSize: 11 }}>{h.drift_class || '—'}</td>
                      <td><span className={`severity-badge ${h.policy_status === 'COMPLIANT' ? 'low' : h.policy_status === 'SOFT_DRIFT' ? 'medium' : 'high'}`}
                        style={{ fontSize: 9 }}>{h.policy_status}</span></td>
                      <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{((h.total_bytes_out || 0) / 1024).toFixed(1)}K</td>
                      <td style={{ color: (h.external_ratio || 0) > 0.5 ? '#ef4444' : '#64748b', fontWeight: (h.external_ratio || 0) > 0.5 ? 700 : 400 }}>
                        {((h.external_ratio || 0) * 100).toFixed(0)}%
                      </td>
                      <td>{h.num_flows || 0}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </>
  );
}

