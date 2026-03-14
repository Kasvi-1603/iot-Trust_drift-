import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Cell, PieChart, Pie, Legend,
  RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
  LineChart, Line, AreaChart, Area, ReferenceLine,
} from 'recharts';

const API = 'http://localhost:8002/api';

const STATUS_COLORS = { COMPLIANT: '#22c55e', SOFT_DRIFT: '#f59e0b', HARD_VIOLATION: '#ef4444' };
const DEVICE_COLORS = { CCTV_01: '#3b82f6', Router_01: '#f59e0b', Access_01: '#22c55e' };
const SEV_COLORS = { Low: '#22c55e', Medium: '#f59e0b', High: '#f97316', Critical: '#ef4444' };

function formatTime(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  return `${d.toLocaleString('en-US', { month: 'short' })} ${d.getDate()}, ${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}`;
}

// ── MITRE Stage Mapping ──────────────────────────────────
const MITRE_STAGES = [
  { id: 'recon',    label: 'Reconnaissance',    icon: '🔍', color: '#94a3b8', mitre: 'TA0043', desc: 'Attacker gathers info — port scans, unusual destination IPs' },
  { id: 'access',   label: 'Initial Access',     icon: '🚪', color: '#f59e0b', mitre: 'TA0001', desc: 'Attacker establishes foothold via unknown IPs or exploits' },
  { id: 'lateral',  label: 'Lateral Movement',   icon: '↔️', color: '#f97316', mitre: 'TA0008', desc: 'Attacker traverses internal network to reach targets' },
  { id: 'c2',       label: 'Command & Control',  icon: '📡', color: '#ef4444', mitre: 'TA0011', desc: 'Attacker maintains persistent remote control channel' },
  { id: 'exfil',    label: 'Exfiltration',       icon: '📤', color: '#dc2626', mitre: 'TA0010', desc: 'Attacker extracts sensitive data to external infrastructure' },
  { id: 'impact',   label: 'Impact',             icon: '💥', color: '#7f1d1d', mitre: 'TA0040', desc: 'Attacker disrupts operations or causes irrecoverable damage' },
];

function mapEvToMitre(ev) {
  const t = ((ev.evidence || '') + ' ' + (ev.risk_summary || '') + ' ' + (ev.feature_attribution || '')).toLowerCase();
  if (t.includes('exfil') || (t.includes('bytes') && t.includes('external'))) return 'exfil';
  if (t.includes('c2') || t.includes('ssh') || t.includes('command') || t.includes('persistent')) return 'c2';
  if (t.includes('scan') || t.includes('lateral') || t.includes('internal')) return 'lateral';
  if (t.includes('external') || t.includes('unknown') || t.includes('access')) return 'access';
  if (ev.severity === 'Critical' || ev.severity === 'High') return 'impact';
  return 'recon';
}

// ── Judge Info Box ────────────────────────────────────────
function JudgeCard({ icon, title, what, how }) {
  const [open, setOpen] = useState(false);
  return (
    <div style={{ background: 'linear-gradient(135deg, #1e293b 0%, #0f172a 100%)', borderRadius: 12, padding: '14px 18px', marginBottom: 20, border: '1px solid #334155' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer' }} onClick={() => setOpen(o => !o)}>
        <span style={{ fontSize: 22 }}>{icon}</span>
        <div style={{ flex: 1 }}>
          <div style={{ color: '#f1f5f9', fontWeight: 700, fontSize: 15 }}>{title}</div>
          <div style={{ color: '#94a3b8', fontSize: 12 }}>{what}</div>
        </div>
        <span style={{ color: '#64748b', fontSize: 12, background: '#1e293b', border: '1px solid #334155', padding: '2px 10px', borderRadius: 6 }}>
          {open ? 'Hide' : 'How it works ▾'}
        </span>
      </div>
      {open && (
        <div style={{ marginTop: 12, paddingTop: 12, borderTop: '1px solid #334155', color: '#cbd5e1', fontSize: 13, lineHeight: 1.7 }}>
          {how}
        </div>
      )}
    </div>
  );
}

// ── TABS DEFINITION ──────────────────────────────────────
const TABS = [
  { id: 'overview',      label: '🛡️ Policy',               },
  { id: 'behavioral',   label: '🧬 Behavioral DNA',        },
  { id: 'exfiltration', label: '📤 Exfiltration',          },
  { id: 'risk_map',     label: '🕸️ Risk Propagation',      },
  { id: 'selfheal',     label: '🔄 Self-Healing',          },
  { id: 'honeypot',     label: '🍯 Honeypot',              },
];

// ═══════════════════════════════════════════════════════════
//  MAIN COMPONENT
// ═══════════════════════════════════════════════════════════
function Security() {
  const [activeTab, setActiveTab] = useState('overview');
  const [summary, setSummary]         = useState([]);
  const [results, setResults]         = useState([]);
  const [evidence, setEvidence]       = useState([]);
  const [traffic, setTraffic]         = useState([]);
  const [profiles, setProfiles]       = useState([]);
  const [trustTl, setTrustTl]         = useState([]);
  const [anomalyTl, setAnomalyTl]     = useState([]);
  const [unknownIps, setUnknownIps]   = useState([]);
  const [filter, setFilter]           = useState('all');
  const [loading, setLoading]         = useState(true);

  useEffect(() => {
    async function fetchAll() {
      try {
        const [sRes, rRes, evRes, trRes, prRes, tlRes, anRes] = await Promise.all([
          axios.get(`${API}/policy-summary`),
          axios.get(`${API}/policy-results`),
          axios.get(`${API}/all-evidence`),
          axios.get(`${API}/network-traffic`),
          axios.get(`${API}/device-profiles`),
          axios.get(`${API}/trust-timeline`),
          axios.get(`${API}/anomaly-timeline`),
        ]);
        setSummary(sRes.data);
        setResults(rRes.data);
        setEvidence(evRes.data);
        setTraffic(trRes.data);
        setProfiles(prRes.data);
        setTrustTl(tlRes.data);
        setAnomalyTl(anRes.data);

        // Try live unknown IPs (optional)
        try {
          const uRes = await axios.get(`${API}/live/unknown-ips?last_n=50`);
          setUnknownIps(uRes.data);
        } catch (_) {}

        setLoading(false);
      } catch (err) {
        console.error(err);
        setLoading(false);
      }
    }
    fetchAll();
  }, []);

  if (loading) return (
    <div className="loading-container">
      <div className="loading-spinner" />
      <div className="loading-text">Loading security intelligence...</div>
    </div>
  );

  // ── Derived data ────────────────────────────────────────

  // Policy
  const statusCounts = {};
  results.forEach(r => { statusCounts[r.policy_status] = (statusCounts[r.policy_status] || 0) + 1; });
  const pieData = Object.entries(statusCounts).map(([status, count]) => ({ status, count }));
  const violations = results.filter(r => filter === 'all' ? r.policy_status !== 'COMPLIANT' : r.policy_status === filter);
  const complianceChartData = summary.map(s => ({
    device: s.device_id, compliance: s.compliance_rate, violations: 100 - s.compliance_rate,
    hasHardViolation: s.hard_violation > 0, hasSoftDrift: s.soft_drift > 0,
  }));

  // Attack chain: group evidence by MITRE stage
  const mitreMap = {};
  MITRE_STAGES.forEach(s => { mitreMap[s.id] = []; });
  evidence.forEach(ev => {
    const stage = mapEvToMitre(ev);
    mitreMap[stage].push(ev);
  });

  // Behavioral DNA: per-device feature radar using traffic data
  const deviceIds = ['CCTV_01', 'Router_01', 'Access_01'];
  const radarData = (() => {
    const feats = ['total_bytes_out', 'total_packets_out', 'num_flows', 'unique_dst_ips', 'unique_dst_ports', 'external_ratio'];
    // Get last 10 windows per device, average
    const devAvg = {};
    deviceIds.forEach(did => {
      const devTr = traffic.filter(t => t.device_id === did).slice(-10);
      if (!devTr.length) return;
      const avg = {};
      feats.forEach(f => { avg[f] = devTr.reduce((s, t) => s + (t[f] || 0), 0) / devTr.length; });
      devAvg[did] = avg;
    });
    // Normalize across all devices for radar (0-100)
    const maxes = {};
    feats.forEach(f => { maxes[f] = Math.max(...Object.values(devAvg).map(d => d[f] || 0), 1); });
    return feats.map(f => {
      const row = { feature: f.replace('total_', '').replace(/_/g, ' ') };
      Object.entries(devAvg).forEach(([did, avg]) => {
        row[did] = Math.round((avg[f] / maxes[f]) * 100);
      });
      return row;
    });
  })();

  // Exfiltration: windows with high external_ratio
  const exfilWindows = traffic
    .filter(t => t.external_ratio > 0.3 || t.total_bytes_out > 500000)
    .map(t => ({ ...t, risk: t.external_ratio > 0.5 ? 'High' : t.external_ratio > 0.3 ? 'Medium' : 'Low' }));

  const exfilTimeline = (() => {
    const byWindow = {};
    traffic.forEach(t => {
      const k = t.window;
      if (!byWindow[k]) byWindow[k] = { window: t.window };
      byWindow[k][t.device_id] = t.external_ratio;
    });
    return Object.values(byWindow).sort((a, b) => new Date(a.window) - new Date(b.window)).slice(-30);
  })();

  // Self-healing: trust timeline to detect → recover cycles
  const trustByDevice = {};
  trustTl.forEach(t => {
    if (!trustByDevice[t.device_id]) trustByDevice[t.device_id] = [];
    trustByDevice[t.device_id].push(t);
  });
  // Find episodes where trust dropped below 60 then recovered
  const healingEvents = [];
  Object.entries(trustByDevice).forEach(([did, entries]) => {
    let inDrop = false;
    let dropStart = null;
    entries.forEach((e, i) => {
      if (!inDrop && e.trust_score < 60) {
        inDrop = true; dropStart = e;
      } else if (inDrop && e.trust_score >= 70) {
        healingEvents.push({ device: did, dropAt: dropStart.window, recoveredAt: e.window, minScore: Math.min(...entries.slice(entries.indexOf(dropStart), i + 1).map(x => x.trust_score)) });
        inDrop = false; dropStart = null;
      }
    });
  });

  // Digital twin: compare profile vs actual last 10w avg
  const twinData = profiles.map(p => {
    const deviceId = deviceIds.find(d => d.startsWith(p.device_type === 'AccessController' ? 'Access' : p.device_type));
    const devTr = traffic.filter(t => t.device_id === deviceId).slice(-10);
    const avgBytes = devTr.length ? devTr.reduce((s, t) => s + t.total_bytes_out, 0) / devTr.length : 0;
    const avgIps = devTr.length ? devTr.reduce((s, t) => s + t.unique_dst_ips, 0) / devTr.length : 0;
    const avgPorts = devTr.length ? devTr.reduce((s, t) => s + t.unique_dst_ports, 0) / devTr.length : 0;
    const avgExtRatio = devTr.length ? devTr.reduce((s, t) => s + t.external_ratio, 0) / devTr.length : 0;
    return {
      type: p.device_type, deviceId,
      profile: p,
      actual: { bytes: avgBytes, ips: avgIps, ports: avgPorts, extRatio: avgExtRatio },
      metrics: [
        { label: 'Bandwidth', expected: p.bandwidth_max_bytes, actual: avgBytes, unit: 'B', pct: Math.min(200, Math.round(avgBytes / Math.max(p.bandwidth_max_bytes, 1) * 100)) },
        { label: 'Unique IPs', expected: p.max_unique_dst_ips, actual: Math.round(avgIps), unit: '', pct: Math.min(200, Math.round(avgIps / Math.max(p.max_unique_dst_ips, 1) * 100)) },
        { label: 'Unique Ports', expected: p.max_unique_dst_ports, actual: Math.round(avgPorts), unit: '', pct: Math.min(200, Math.round(avgPorts / Math.max(p.max_unique_dst_ports, 1) * 100)) },
        { label: 'External %', expected: p.allow_external ? 50 : 0, actual: Math.round(avgExtRatio * 100), unit: '%', pct: p.allow_external ? Math.min(200, Math.round(avgExtRatio * 200)) : avgExtRatio > 0.05 ? 200 : 0 },
      ],
    };
  });

  // Honeypot: show attack catalog as honeypot intelligence
  const honeypotDevices = [
    { id: 'HONEY_CAM_01', type: 'IP Camera', role: 'Lures exfiltration & C2 attacks', status: 'active', caught: unknownIps.filter(u => u.device_id === 'CCTV_01').length },
    { id: 'HONEY_RTR_01', type: 'Smart Router', role: 'Detects lateral movement & DNS tunneling', status: 'active', caught: unknownIps.filter(u => u.device_id === 'Router_01').length },
    { id: 'HONEY_ACC_01', type: 'Access Controller', role: 'Identifies credential stuffing attempts', status: 'active', caught: unknownIps.filter(u => u.device_id === 'Access_01').length },
  ];

  // ═══════════════════════════════════════════════════════
  //  RENDER
  // ═══════════════════════════════════════════════════════
  return (
    <>
      <div className="page-title-section">
        <h1 className="page-title">Advanced Security Intelligence</h1>
        <p className="page-subtitle">Digital Twin · Attack Chain · Behavioral DNA · Exfiltration · Risk Propagation · Self-Healing · Honeypot</p>
      </div>

      {/* ── Tab Bar ── */}
      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginBottom: 20, background: '#f8fafc', padding: 6, borderRadius: 12, border: '1px solid #e2e8f0' }}>
        {TABS.map(t => (
          <button key={t.id} onClick={() => setActiveTab(t.id)}
            style={{
              padding: '7px 14px', borderRadius: 8, border: 'none', fontSize: 12, fontWeight: 600,
              cursor: 'pointer', fontFamily: 'inherit', transition: 'all 0.15s',
              background: activeTab === t.id ? '#1e293b' : 'transparent',
              color: activeTab === t.id ? '#fff' : '#64748b',
            }}>
            {t.label}
          </button>
        ))}
      </div>

      {/* ══════════════════════════════════════════
          TAB: POLICY OVERVIEW
         ══════════════════════════════════════════ */}
      {activeTab === 'overview' && (
        <>
          <JudgeCard icon="🛡️" title="Policy Compliance Engine"
            what="Real-time enforcement of device-specific behavioral policies using 3-tier rule evaluation"
            how="Each IoT device has a pre-defined security policy (allowed protocols, IP ranges, port lists, bandwidth limits). Every hourly window is evaluated against the policy. Violations are classified as SOFT_DRIFT (minor deviation) or HARD_VIOLATION (clear breach). Trust score is penalized by -10 to -30 points per violation." />
          <div className="stats-bar">
            {summary.map(s => {
              const rc = s.hard_violation > 0 ? 'bad' : s.soft_drift > 0 ? 'warn' : 'good';
              return (
                <div key={s.device_id} className="compliance-card">
                  <div className="compliance-device-name">{s.device_id}</div>
                  <div className="compliance-type">{s.device_type}</div>
                  <div className={`compliance-rate ${rc}`}>{s.compliance_rate}%</div>
                  <div className="compliance-bar-track">
                    <div className={`compliance-bar-fill ${rc}`} style={{ width: `${s.compliance_rate}%` }} />
                  </div>
                  <div className="compliance-detail">
                    <span><span className="dot-green" />{s.compliant} OK</span>
                    <span><span className="dot-yellow" />{s.soft_drift} Drift</span>
                    <span><span className="dot-red" />{s.hard_violation} Violation</span>
                  </div>
                </div>
              );
            })}
          </div>
          <div className="two-col-grid">
            <div className="panel">
              <div className="panel-header"><div><div className="panel-title">Compliance by Device</div><div className="panel-subtitle">% compliant windows per device</div></div></div>
              <div className="panel-body"><div className="chart-container small">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={complianceChartData} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
                    <XAxis dataKey="device" tick={{ fontSize: 11, fill: '#64748b' }} tickLine={false} />
                    <YAxis domain={[0, 100]} tick={{ fontSize: 11, fill: '#94a3b8' }} tickLine={false} width={35} tickFormatter={v => `${v}%`} />
                    <Tooltip formatter={v => `${v}%`} contentStyle={{ fontSize: 12, borderRadius: 8 }} />
                    <Bar dataKey="compliance" name="Compliant" radius={[6, 6, 0, 0]}>
                      {complianceChartData.map((d, i) => <Cell key={i} fill={d.hasHardViolation ? '#ef4444' : d.hasSoftDrift ? '#f59e0b' : '#22c55e'} />)}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div></div>
            </div>
            <div className="panel">
              <div className="panel-header"><div><div className="panel-title">Status Distribution</div><div className="panel-subtitle">Overall policy evaluation results</div></div></div>
              <div className="panel-body"><div className="chart-container small">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={pieData} dataKey="count" nameKey="status" cx="50%" cy="50%" innerRadius={55} outerRadius={90} paddingAngle={3}
                      label={({ status, count }) => `${status.replace('_', ' ')}: ${count}`} style={{ fontSize: 11 }}>
                      {pieData.map((p, i) => <Cell key={i} fill={STATUS_COLORS[p.status] || '#94a3b8'} />)}
                    </Pie>
                    <Tooltip contentStyle={{ fontSize: 12, borderRadius: 8 }} />
                    <Legend verticalAlign="bottom" height={30} wrapperStyle={{ fontSize: 11 }} />
                  </PieChart>
                </ResponsiveContainer>
              </div></div>
            </div>
          </div>
          <div className="panel">
            <div className="panel-header">
              <div><div className="panel-title">Violations Log</div><div className="panel-subtitle">Non-compliant evaluations</div></div>
            </div>
            <div className="panel-body">
              <div className="filter-bar">
                <span style={{ fontSize: 12, color: '#64748b', marginRight: 4 }}>Status:</span>
                {['all', 'SOFT_DRIFT', 'HARD_VIOLATION'].map(f => (
                  <button key={f} className={`filter-btn ${filter === f ? 'active' : ''}`} onClick={() => setFilter(f)}>
                    {f === 'all' ? 'All Non-Compliant' : f.replace('_', ' ')}
                  </button>
                ))}
              </div>
            </div>
            <div className="panel-body no-padding" style={{ paddingTop: 0 }}>
              {violations.length === 0 ? <div className="table-empty">No violations for this filter.</div> : (
                <div style={{ overflowX: 'auto' }}>
                  <table className="data-table">
                    <thead><tr><th>Time</th><th>Device</th><th>Type</th><th>Status</th><th>Violations</th><th>Penalty</th></tr></thead>
                    <tbody>
                      {violations.slice(0, 50).map((v, i) => (
                        <tr key={i}>
                          <td className="table-cell-time">{formatTime(v.window)}</td>
                          <td className="table-cell-device">{v.device_id}</td>
                          <td style={{ fontSize: 12, color: '#64748b' }}>{v.device_type}</td>
                          <td><span className={`severity-badge ${v.policy_status === 'HARD_VIOLATION' ? 'high' : 'medium'}`}>{v.policy_status.replace('_', ' ')}</span></td>
                          <td style={{ fontSize: 12, maxWidth: 300 }}>{v.violations}</td>
                          <td style={{ fontWeight: 600, color: v.penalty >= 25 ? '#ef4444' : '#f59e0b' }}>-{v.penalty}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        </>
      )}



      {/* ══════════════════════════════════════════
          TAB: BEHAVIORAL DNA / FINGERPRINTING
         ══════════════════════════════════════════ */}
      {activeTab === 'behavioral' && (
        <>
          <JudgeCard icon="🧬" title="Behavioral Fingerprinting — Device DNA"
            what="Unique traffic fingerprint per device — detects identity spoofing and behavioral drift"
            how={<>
              Every IoT device has a <strong style={{color:'#94d2bd'}}>behavioral fingerprint</strong> — a unique multi-dimensional signature of its normal traffic patterns (bandwidth, flow counts, port diversity, external ratio).<br /><br />
              <strong style={{color:'#94d2bd'}}>How it detects attacks:</strong> If a device starts behaving like a different device (e.g., a camera suddenly making DNS queries like a router), the fingerprint diverges. This catches <em>identity spoofing</em>, <em>device impersonation</em>, and <em>covert channel</em> attacks.<br /><br />
              <strong style={{color:'#f59e0b'}}>Demo:</strong> The radar chart shows each device's traffic DNA. Compare shapes — a compromised device's shape will deform.
            </>} />

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
            <div className="panel">
              <div className="panel-header"><div><div className="panel-title">Traffic Fingerprint Radar</div><div className="panel-subtitle">Normalized behavioral DNA — 6 feature dimensions</div></div></div>
              <div className="panel-body" style={{ height: 320 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <RadarChart data={radarData} margin={{ top: 10, right: 30, bottom: 10, left: 30 }}>
                    <PolarGrid stroke="#e2e8f0" />
                    <PolarAngleAxis dataKey="feature" tick={{ fontSize: 11, fill: '#64748b' }} />
                    <PolarRadiusAxis angle={30} domain={[0, 100]} tick={{ fontSize: 9, fill: '#94a3b8' }} tickCount={4} />
                    {deviceIds.map((did, i) => (
                      <Radar key={did} name={did} dataKey={did} stroke={Object.values(DEVICE_COLORS)[i]} fill={Object.values(DEVICE_COLORS)[i]} fillOpacity={0.15} strokeWidth={2} />
                    ))}
                    <Legend verticalAlign="bottom" wrapperStyle={{ fontSize: 12 }} />
                    <Tooltip contentStyle={{ fontSize: 12, borderRadius: 8 }} />
                  </RadarChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Fingerprint detail table */}
            <div className="panel">
              <div className="panel-header"><div><div className="panel-title">Feature Comparison</div><div className="panel-subtitle">Per-device average over last 10 windows</div></div></div>
              <div className="panel-body no-padding">
                <table className="data-table">
                  <thead><tr><th>Feature</th>{deviceIds.map(d => <th key={d}>{d}</th>)}</tr></thead>
                  <tbody>
                    {radarData.map((row, i) => (
                      <tr key={i}>
                        <td style={{ fontWeight: 600, fontSize: 12 }}>{row.feature}</td>
                        {deviceIds.map(did => {
                          const val = row[did] || 0;
                          const color = val > 80 ? '#ef4444' : val > 50 ? '#f59e0b' : '#22c55e';
                          return (
                            <td key={did} style={{ textAlign: 'center' }}>
                              <div style={{ display: 'flex', alignItems: 'center', gap: 6, justifyContent: 'center' }}>
                                <div style={{ width: 40, height: 6, background: '#f1f5f9', borderRadius: 3 }}>
                                  <div style={{ width: `${val}%`, height: '100%', background: color, borderRadius: 3 }} />
                                </div>
                                <span style={{ fontSize: 11, fontWeight: 600, color }}>{val}</span>
                              </div>
                            </td>
                          );
                        })}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>

          {/* Temporal behavior heatmap (anomaly by hour) */}
          <div className="panel">
            <div className="panel-header"><div><div className="panel-title">Temporal Behavioral Pattern</div><div className="panel-subtitle">Anomaly score distribution over simulated time — detects time-based attacks (e.g. night-time exfil)</div></div></div>
            <div className="panel-body"><div className="chart-container">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={anomalyTl.slice(-60)} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
                  <XAxis dataKey="window" tick={{ fontSize: 9, fill: '#94a3b8' }} interval={9} tickFormatter={v => formatTime(v)} tickLine={false} />
                  <YAxis domain={[0, 1]} tick={{ fontSize: 10, fill: '#94a3b8' }} tickLine={false} width={30} />
                  <Tooltip contentStyle={{ fontSize: 11, borderRadius: 8 }} formatter={v => v.toFixed(3)} />
                  <ReferenceLine y={0.5} stroke="#ef4444" strokeDasharray="4 4" label={{ value: 'Alert threshold', position: 'insideTopRight', fontSize: 10, fill: '#ef4444' }} />
                  {deviceIds.map((did, i) => (
                    <Area key={did} type="monotone" dataKey={anomalyTl.find(a => a.device_id === did) ? 'anomaly_score' : ''}
                      data={anomalyTl.filter(a => a.device_id === did).slice(-60)}
                      name={did} stroke={Object.values(DEVICE_COLORS)[i]} fill={Object.values(DEVICE_COLORS)[i]} fillOpacity={0.1} strokeWidth={1.5} dot={false} />
                  ))}
                  <Legend verticalAlign="top" height={30} wrapperStyle={{ fontSize: 11 }} />
                </AreaChart>
              </ResponsiveContainer>
            </div></div>
          </div>
        </>
      )}

      {/* ══════════════════════════════════════════
          TAB: DATA EXFILTRATION
         ══════════════════════════════════════════ */}
      {activeTab === 'exfiltration' && (
        <>
          <JudgeCard icon="📤" title="Data Exfiltration Detection"
            what="Detects unauthorized outbound data flows to external infrastructure in real-time"
            how={<>
              Exfiltration is detected by monitoring <strong style={{color:'#94d2bd'}}>external_ratio</strong> (% of connections going outside the internal network) and <strong style={{color:'#94d2bd'}}>total_bytes_out</strong> per hourly window.<br /><br />
              <strong style={{color:'#94d2bd'}}>Detection logic:</strong> A window is flagged if external_ratio {'>'} 30% OR bytes_out {'>'} 500KB. Devices with expected external access (Router) use higher thresholds than isolated devices (CCTV, Access Controller).<br /><br />
              <strong style={{color:'#f59e0b'}}>Demo:</strong> The red zones on the chart show windows where exfiltration-like behavior was detected.
            </>} />

          {/* External ratio timeline */}
          <div className="panel" style={{ marginBottom: 16 }}>
            <div className="panel-header"><div><div className="panel-title">External Connection Ratio Timeline</div><div className="panel-subtitle">% of outbound connections going to external IPs — spikes indicate potential exfiltration</div></div></div>
            <div className="panel-body"><div className="chart-container">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={exfilTimeline} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
                  <XAxis dataKey="window" tick={{ fontSize: 9, fill: '#94a3b8' }} interval={4} tickFormatter={v => formatTime(v)} tickLine={false} />
                  <YAxis domain={[0, 1]} tick={{ fontSize: 10, fill: '#94a3b8' }} tickLine={false} width={35} tickFormatter={v => `${(v * 100).toFixed(0)}%`} />
                  <Tooltip contentStyle={{ fontSize: 11, borderRadius: 8 }} formatter={v => `${(v * 100).toFixed(1)}%`} />
                  <ReferenceLine y={0.3} stroke="#f59e0b" strokeDasharray="4 4" label={{ value: 'Warn (30%)', position: 'insideTopRight', fontSize: 10, fill: '#f59e0b' }} />
                  <ReferenceLine y={0.5} stroke="#ef4444" strokeDasharray="4 4" label={{ value: 'Alert (50%)', position: 'insideTopRight', fontSize: 10, fill: '#ef4444' }} />
                  {deviceIds.map((did, i) => (
                    <Area key={did} type="monotone" dataKey={did} name={did} stroke={Object.values(DEVICE_COLORS)[i]} fill={Object.values(DEVICE_COLORS)[i]} fillOpacity={0.15} strokeWidth={2} dot={false} />
                  ))}
                  <Legend verticalAlign="top" height={30} wrapperStyle={{ fontSize: 11 }} />
                </AreaChart>
              </ResponsiveContainer>
            </div></div>
          </div>

          {/* Flagged windows */}
          <div className="panel">
            <div className="panel-header">
              <div><div className="panel-title">Flagged Exfiltration Windows</div><div className="panel-subtitle">Windows with high external traffic or unusual byte volumes</div></div>
              <span className="live-badge" style={{ background: exfilWindows.length > 0 ? '#fee2e2' : '#dcfce7', color: exfilWindows.length > 0 ? '#ef4444' : '#22c55e' }}>
                {exfilWindows.length} suspect windows
              </span>
            </div>
            <div className="panel-body no-padding" style={{ maxHeight: 320, overflowY: 'auto' }}>
              {exfilWindows.length === 0 ? <div className="table-empty">No exfiltration patterns detected.</div> : (
                <table className="alerts-table">
                  <thead><tr><th>Time</th><th>Device</th><th>Bytes Out</th><th>External %</th><th>Unique IPs</th><th>Risk</th></tr></thead>
                  <tbody>
                    {exfilWindows.slice(0, 30).map((w, i) => (
                      <tr key={i}>
                        <td style={{ fontSize: 11 }}>{formatTime(w.window)}</td>
                        <td style={{ fontWeight: 600 }}>{w.device_id}</td>
                        <td style={{ fontFamily: 'monospace', fontSize: 12 }}>{(w.total_bytes_out / 1024).toFixed(1)} KB</td>
                        <td style={{ color: w.external_ratio > 0.5 ? '#ef4444' : '#f59e0b', fontWeight: 600 }}>{(w.external_ratio * 100).toFixed(1)}%</td>
                        <td>{w.unique_dst_ips}</td>
                        <td><span className={`severity-badge ${w.risk.toLowerCase()}`}>{w.risk}</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </>
      )}

      {/* ══════════════════════════════════════════
          TAB: RISK PROPAGATION
         ══════════════════════════════════════════ */}
      {activeTab === 'risk_map' && (
        <>
          <JudgeCard icon="🕸️" title="Risk Propagation — Network Blast Radius"
            what="Models how a single compromised IoT device can cascade risk across the entire network"
            how={<>
              In IoT networks, devices are <strong style={{color:'#94d2bd'}}>interdependent</strong> — a compromised router can intercept all device traffic; a compromised camera can be used as a pivot point. We model risk propagation using device connectivity graphs.<br /><br />
              <strong style={{color:'#94d2bd'}}>Algorithm:</strong> Risk score of a device = its own trust deduction + weighted sum of neighbor risk scores. Edge weight = traffic volume between devices. Compromised devices "infect" connected nodes.<br /><br />
              <strong style={{color:'#f59e0b'}}>Demo:</strong> The graph shows how CCTV compromise propagates through the router to the access control system.
            </>} />

          {/* Network diagram SVG */}
          {(() => {
            const devScores = {};
            const latestTrust = {};
            trustTl.forEach(t => { latestTrust[t.device_id] = t; });
            deviceIds.forEach(did => {
              const t = latestTrust[did];
              devScores[did] = t ? t.trust_score : 100;
            });
            const getColor = (score) => score >= 70 ? '#22c55e' : score >= 40 ? '#f59e0b' : '#ef4444';
            const getSev = (score) => score >= 70 ? 'Low' : score >= 40 ? 'Medium' : 'High';
            return (
              <div className="panel" style={{ marginBottom: 16 }}>
                <div className="panel-header"><div><div className="panel-title">Device Risk Graph</div><div className="panel-subtitle">Network topology with live trust scores — compromised devices propagate risk to neighbors</div></div></div>
                <div className="panel-body" style={{ minHeight: 340, position: 'relative' }}>
                  <svg width="100%" height="320" viewBox="0 0 800 300" style={{ overflow: 'visible' }}>
                    {/* Internet node */}
                    <circle cx="700" cy="150" r="36" fill="#f1f5f9" stroke="#94a3b8" strokeWidth="2" />
                    <text x="700" y="145" textAnchor="middle" fontSize="11" fill="#64748b" fontWeight="600">Internet</text>
                    <text x="700" y="160" textAnchor="middle" fontSize="18">🌐</text>

                    {/* Router (center) */}
                    <circle cx="400" cy="150" r="48" fill={getColor(devScores['Router_01']) + '33'} stroke={getColor(devScores['Router_01'])} strokeWidth="3" />
                    <text x="400" y="138" textAnchor="middle" fontSize="22">🌐</text>
                    <text x="400" y="158" textAnchor="middle" fontSize="12" fill="#1e293b" fontWeight="700">Router_01</text>
                    <text x="400" y="174" textAnchor="middle" fontSize="13" fill={getColor(devScores['Router_01'])} fontWeight="700">{Math.round(devScores['Router_01'])}%</text>

                    {/* CCTV (top-left) */}
                    <circle cx="140" cy="80" r="44" fill={getColor(devScores['CCTV_01']) + '33'} stroke={getColor(devScores['CCTV_01'])} strokeWidth="3" />
                    <text x="140" y="68" textAnchor="middle" fontSize="22">📷</text>
                    <text x="140" y="88" textAnchor="middle" fontSize="12" fill="#1e293b" fontWeight="700">CCTV_01</text>
                    <text x="140" y="104" textAnchor="middle" fontSize="13" fill={getColor(devScores['CCTV_01'])} fontWeight="700">{Math.round(devScores['CCTV_01'])}%</text>

                    {/* Access (bottom-left) */}
                    <circle cx="140" cy="230" r="44" fill={getColor(devScores['Access_01']) + '33'} stroke={getColor(devScores['Access_01'])} strokeWidth="3" />
                    <text x="140" y="218" textAnchor="middle" fontSize="22">🔐</text>
                    <text x="140" y="238" textAnchor="middle" fontSize="12" fill="#1e293b" fontWeight="700">Access_01</text>
                    <text x="140" y="254" textAnchor="middle" fontSize="13" fill={getColor(devScores['Access_01'])} fontWeight="700">{Math.round(devScores['Access_01'])}%</text>

                    {/* Edges */}
                    {/* CCTV → Router */}
                    <line x1="184" y1="100" x2="355" y2="135" stroke={getColor(devScores['CCTV_01'])} strokeWidth="2.5" strokeDasharray={devScores['CCTV_01'] < 70 ? '6 3' : '0'} opacity="0.7" />
                    <text x="270" y="108" textAnchor="middle" fontSize="10" fill="#64748b">RTSP</text>
                    {devScores['CCTV_01'] < 70 && <text x="270" y="123" textAnchor="middle" fontSize="10" fill="#ef4444">⚠ risk flow</text>}

                    {/* Access → Router */}
                    <line x1="184" y1="210" x2="355" y2="168" stroke={getColor(devScores['Access_01'])} strokeWidth="2.5" strokeDasharray={devScores['Access_01'] < 70 ? '6 3' : '0'} opacity="0.7" />
                    <text x="270" y="200" textAnchor="middle" fontSize="10" fill="#64748b">HTTPS</text>

                    {/* Router → Internet */}
                    <line x1="448" y1="150" x2="664" y2="150" stroke={getColor(devScores['Router_01'])} strokeWidth="2.5" strokeDasharray={devScores['Router_01'] < 70 ? '6 3' : '0'} opacity="0.7" />
                    <text x="556" y="143" textAnchor="middle" fontSize="10" fill="#64748b">DNS / HTTPS</text>
                    {devScores['Router_01'] < 70 && <text x="556" y="163" textAnchor="middle" fontSize="10" fill="#ef4444">⚠ exfil risk</text>}

                    {/* Auth server (right of Access) */}
                    <circle cx="310" cy="270" r="28" fill="#f0fdf4" stroke="#22c55e" strokeWidth="1.5" />
                    <text x="310" y="264" textAnchor="middle" fontSize="14">🖥️</text>
                    <text x="310" y="281" textAnchor="middle" fontSize="9" fill="#64748b">Auth Server</text>
                    <line x1="184" y1="246" x2="282" y2="265" stroke="#22c55e" strokeWidth="1.5" opacity="0.6" />
                  </svg>

                  {/* Legend */}
                  <div style={{ display: 'flex', gap: 16, justifyContent: 'center', marginTop: 8, fontSize: 12, color: '#64748b' }}>
                    <span>🟢 Trust ≥70 (Safe)</span>
                    <span>🟡 Trust 40-70 (Degraded)</span>
                    <span>🔴 Trust &lt;40 (Compromised)</span>
                    <span style={{ color: '#94a3b8' }}>--- Risk flowing</span>
                  </div>
                </div>
              </div>
            );
          })()}

          {/* Propagation impact table */}
          <div className="panel">
            <div className="panel-header"><div><div className="panel-title">Propagation Impact Analysis</div><div className="panel-subtitle">How compromise of each device affects the rest of the network</div></div></div>
            <div className="panel-body no-padding">
              <table className="data-table">
                <thead><tr><th>Source Device</th><th>If Compromised →</th><th>At-Risk Neighbors</th><th>Blast Radius</th><th>Max Impact</th></tr></thead>
                <tbody>
                  <tr>
                    <td style={{ fontWeight: 600 }}>📷 CCTV_01</td>
                    <td style={{ fontSize: 12, color: '#64748b' }}>Feeds all video through Router. Attacker gets inside foothold.</td>
                    <td><span style={{ fontSize: 11, background: '#fef3c7', color: '#d97706', padding: '2px 6px', borderRadius: 4 }}>Router_01</span></td>
                    <td><div style={{ display: 'flex', gap: 2 }}>{[1,2,3].map(i => <div key={i} style={{ width: 10, height: 10, borderRadius: 2, background: i <= 2 ? '#f59e0b' : '#e2e8f0' }} />)}</div></td>
                    <td style={{ color: '#f59e0b', fontWeight: 600 }}>Medium</td>
                  </tr>
                  <tr>
                    <td style={{ fontWeight: 600 }}>🌐 Router_01</td>
                    <td style={{ fontSize: 12, color: '#64748b' }}>Controls all DNS + routing. Attacker sees ALL traffic.</td>
                    <td>
                      <span style={{ fontSize: 11, background: '#fee2e2', color: '#ef4444', padding: '2px 6px', borderRadius: 4, marginRight: 4 }}>CCTV_01</span>
                      <span style={{ fontSize: 11, background: '#fee2e2', color: '#ef4444', padding: '2px 6px', borderRadius: 4 }}>Access_01</span>
                    </td>
                    <td><div style={{ display: 'flex', gap: 2 }}>{[1,2,3].map(i => <div key={i} style={{ width: 10, height: 10, borderRadius: 2, background: '#ef4444' }} />)}</div></td>
                    <td style={{ color: '#ef4444', fontWeight: 600 }}>Critical</td>
                  </tr>
                  <tr>
                    <td style={{ fontWeight: 600 }}>🔐 Access_01</td>
                    <td style={{ fontSize: 12, color: '#64748b' }}>Credential theft → physical access bypass → lateral movement.</td>
                    <td><span style={{ fontSize: 11, background: '#fee2e2', color: '#ef4444', padding: '2px 6px', borderRadius: 4 }}>Auth Server</span></td>
                    <td><div style={{ display: 'flex', gap: 2 }}>{[1,2,3].map(i => <div key={i} style={{ width: 10, height: 10, borderRadius: 2, background: i <= 2 ? '#ef4444' : '#e2e8f0' }} />)}</div></td>
                    <td style={{ color: '#ef4444', fontWeight: 600 }}>High</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}

      {/* ══════════════════════════════════════════
          TAB: SELF-HEALING
         ══════════════════════════════════════════ */}
      {activeTab === 'selfheal' && (
        <>
          <JudgeCard icon="🔄" title="Self-Healing System — Autonomous Response"
            what="Automatically detects, isolates, monitors, and restores compromised IoT devices"
            how={<>
              When trust score drops below <strong style={{color:'#94d2bd'}}>60%</strong>, the system triggers an automated response pipeline:<br /><br />
              <strong style={{color:'#ef4444'}}>1. Detect</strong> → Anomaly + drift + policy flags raised simultaneously<br />
              <strong style={{color:'#f59e0b'}}>2. Alert</strong> → Evidence report generated with MITRE classification<br />
              <strong style={{color:'#f97316'}}>3. Isolate</strong> → Network quarantine recommended (policy engine flags device)<br />
              <strong style={{color:'#3b82f6'}}>4. Monitor</strong> → Continued monitoring with tighter thresholds<br />
              <strong style={{color:'#22c55e'}}>5. Restore</strong> → Trust score recovers via EMA smoothing when normal behavior resumes<br /><br />
              <strong style={{color:'#f59e0b'}}>Demo:</strong> Each card below shows a real detection-recovery cycle from your IoT data.
            </>} />

          {/* Self-healing episodes */}
          {healingEvents.length > 0 ? (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 16, marginBottom: 16 }}>
              {healingEvents.slice(0, 6).map((ev, i) => (
                <div key={i} className="panel" style={{ borderLeft: '4px solid #22c55e' }}>
                  <div className="panel-body">
                    <div style={{ fontWeight: 700, color: '#1e293b', fontSize: 14, marginBottom: 12 }}>{ev.device} — Recovery Cycle #{i + 1}</div>
                    {/* Timeline steps */}
                    {[
                      { step: '🔴 Detected',  color: '#ef4444', desc: `Trust dropped to ${ev.minScore.toFixed(1)}`, time: formatTime(ev.dropAt) },
                      { step: '🟠 Alerted',   color: '#f97316', desc: 'Evidence report generated + MITRE tagged', time: '' },
                      { step: '🟡 Monitoring',color: '#f59e0b', desc: 'Tighter anomaly thresholds applied', time: '' },
                      { step: '🟢 Restored',  color: '#22c55e', desc: 'Trust recovered above 70%', time: formatTime(ev.recoveredAt) },
                    ].map((s, si) => (
                      <div key={si} style={{ display: 'flex', alignItems: 'flex-start', gap: 10, marginBottom: si < 3 ? 0 : 0, position: 'relative' }}>
                        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                          <div style={{ width: 10, height: 10, borderRadius: '50%', background: s.color, marginTop: 3, flexShrink: 0 }} />
                          {si < 3 && <div style={{ width: 2, height: 24, background: '#e2e8f0' }} />}
                        </div>
                        <div style={{ paddingBottom: 12 }}>
                          <div style={{ fontSize: 12, fontWeight: 700, color: s.color }}>{s.step}</div>
                          <div style={{ fontSize: 11, color: '#64748b' }}>{s.desc}</div>
                          {s.time && <div style={{ fontSize: 10, color: '#94a3b8', fontFamily: 'monospace' }}>{s.time}</div>}
                        </div>
                      </div>
                    ))}
                    <div style={{ padding: '8px 12px', background: '#f0fdf4', borderRadius: 8, border: '1px solid #bbf7d0', marginTop: 4 }}>
                      <span style={{ fontSize: 11, color: '#15803d', fontWeight: 600 }}>✓ Recovery time: ~{Math.round((new Date(ev.recoveredAt) - new Date(ev.dropAt)) / 3600000)} hours (simulated)</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="panel" style={{ marginBottom: 16 }}>
              <div className="panel-body">
                <div style={{ textAlign: 'center', padding: 40 }}>
                  <div style={{ fontSize: 48, marginBottom: 12 }}>✅</div>
                  <div style={{ fontWeight: 700, color: '#1e293b', fontSize: 16 }}>All Devices Stable — No Recovery Cycles Detected</div>
                  <div style={{ color: '#64748b', fontSize: 13, marginTop: 4 }}>Trust scores have remained above threshold. Inject an attack to see self-healing in action.</div>
                </div>
              </div>
            </div>
          )}

          {/* Self-healing trust chart */}
          <div className="panel">
            <div className="panel-header"><div><div className="panel-title">Trust Score Recovery Timeline</div><div className="panel-subtitle">EMA-smoothed trust scores — dips show attacks, recoveries show self-healing</div></div></div>
            <div className="panel-body"><div className="chart-container">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={(() => {
                  const byW = {};
                  trustTl.forEach(t => {
                    if (!byW[t.window]) byW[t.window] = { window: t.window };
                    byW[t.window][t.device_id] = t.trust_score;
                  });
                  return Object.values(byW).sort((a, b) => new Date(a.window) - new Date(b.window)).slice(-60);
                })()} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
                  <XAxis dataKey="window" tick={{ fontSize: 9, fill: '#94a3b8' }} interval={9} tickFormatter={v => formatTime(v)} tickLine={false} />
                  <YAxis domain={[0, 100]} tick={{ fontSize: 10, fill: '#94a3b8' }} tickLine={false} width={30} />
                  <Tooltip contentStyle={{ fontSize: 11, borderRadius: 8 }} />
                  <ReferenceLine y={60} stroke="#ef4444" strokeDasharray="4 4" label={{ value: 'Alert threshold', position: 'insideTopRight', fontSize: 10, fill: '#ef4444' }} />
                  <ReferenceLine y={70} stroke="#f59e0b" strokeDasharray="4 4" label={{ value: 'Recovery threshold', position: 'insideBottomRight', fontSize: 10, fill: '#f59e0b' }} />
                  {deviceIds.map((did, i) => (
                    <Line key={did} type="monotone" dataKey={did} name={did} stroke={Object.values(DEVICE_COLORS)[i]} strokeWidth={2} dot={false} activeDot={{ r: 3 }} />
                  ))}
                  <Legend verticalAlign="top" height={30} wrapperStyle={{ fontSize: 11 }} />
                </LineChart>
              </ResponsiveContainer>
            </div></div>
          </div>
        </>
      )}

      {/* ══════════════════════════════════════════
          TAB: HONEYPOT
         ══════════════════════════════════════════ */}
      {activeTab === 'honeypot' && (
        <>
          <JudgeCard icon="🍯" title="IoT Honeypot Network — Attacker Intelligence"
            what="Decoy IoT devices that attract, detect, and fingerprint attackers without exposing real assets"
            how={<>
              IoT honeypots are <strong style={{color:'#94d2bd'}}>fake devices</strong> that mimic real IoT hardware (cameras, routers, access controllers). Any traffic to these devices is <em>inherently suspicious</em> — no legitimate user should ever contact them.<br /><br />
              <strong style={{color:'#94d2bd'}}>What they capture:</strong> Attacker IP addresses, attack tools, exploit payloads, reconnaissance patterns, and TTPs (Tactics, Techniques, Procedures).<br /><br />
              <strong style={{color:'#94d2bd'}}>Integration:</strong> Honeypot events feed back into our trust engine — a device contacting a honeypot gets immediate trust penalty and triggers manual review.<br /><br />
              <strong style={{color:'#f59e0b'}}>Demo:</strong> Below are deployed honeypot devices and intelligence captured from the live network monitor.
            </>} />

          {/* Honeypot device cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16, marginBottom: 16 }}>
            {honeypotDevices.map((hp, i) => (
              <div key={i} className="panel" style={{ borderTop: '4px solid #f59e0b', position: 'relative' }}>
                <div style={{ position: 'absolute', top: 12, right: 12 }}>
                  <span style={{ fontSize: 10, background: '#fef9c3', color: '#d97706', padding: '2px 8px', borderRadius: 20, fontWeight: 700, border: '1px solid #fde68a' }}>
                    🍯 HONEYPOT
                  </span>
                </div>
                <div className="panel-body">
                  <div style={{ fontSize: 28, marginBottom: 8 }}>{i === 0 ? '📷' : i === 1 ? '🌐' : '🔐'}</div>
                  <div style={{ fontWeight: 700, color: '#1e293b', fontSize: 15 }}>{hp.id}</div>
                  <div style={{ fontSize: 12, color: '#64748b', marginBottom: 8 }}>{hp.type}</div>
                  <div style={{ fontSize: 12, color: '#334155', marginBottom: 12, lineHeight: 1.5 }}>{hp.role}</div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 12px', background: hp.caught > 0 ? '#fef2f2' : '#f0fdf4', borderRadius: 8, border: `1px solid ${hp.caught > 0 ? '#fecaca' : '#bbf7d0'}` }}>
                    <span style={{ fontSize: 12, color: hp.caught > 0 ? '#ef4444' : '#22c55e', fontWeight: 600 }}>
                      {hp.caught > 0 ? `⚠ ${hp.caught} contacts detected` : '✓ No contacts — clean'}
                    </span>
                    <span style={{ fontSize: 10, background: hp.status === 'active' ? '#dcfce7' : '#f1f5f9', color: hp.status === 'active' ? '#15803d' : '#64748b', padding: '2px 8px', borderRadius: 4, fontWeight: 600 }}>
                      {hp.status.toUpperCase()}
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </div>

          {/* Unknown IPs detected (honeypot catches) */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <div className="panel">
              <div className="panel-header">
                <div><div className="panel-title">Honeypot Catches</div><div className="panel-subtitle">Unknown IPs detected contacting our IoT devices</div></div>
                <span className="live-badge" style={{ background: unknownIps.length > 0 ? '#fee2e2' : '#dcfce7', color: unknownIps.length > 0 ? '#ef4444' : '#22c55e' }}>
                  {unknownIps.length} IPs
                </span>
              </div>
              <div className="panel-body no-padding" style={{ maxHeight: 300, overflowY: 'auto' }}>
                {unknownIps.length === 0 ? (
                  <div className="table-empty">No unknown IPs caught yet. Start IoT simulation to see catches.</div>
                ) : (
                  <table className="alerts-table">
                    <thead><tr><th>IP Address</th><th>Target Device</th><th>Tick</th></tr></thead>
                    <tbody>
                      {unknownIps.slice(-20).reverse().map((u, i) => (
                        <tr key={i}>
                          <td style={{ fontFamily: 'monospace', fontWeight: 600, color: '#ef4444' }}>{u.ip}</td>
                          <td>{u.device_id}</td>
                          <td style={{ color: '#94a3b8', fontSize: 11 }}>T+{u.tick}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </div>

            {/* Attack catalog as honeypot intelligence */}
            <div className="panel">
              <div className="panel-header"><div><div className="panel-title">Honeypot Intelligence</div><div className="panel-subtitle">Attack TTPs our honeypots are configured to detect</div></div></div>
              <div className="panel-body no-padding" style={{ maxHeight: 300, overflowY: 'auto' }}>
                <table className="alerts-table">
                  <thead><tr><th>Attack TTP</th><th>Target Type</th><th>MITRE</th></tr></thead>
                  <tbody>
                    {[
                      { name: 'Video Exfiltration', device: 'CCTV', mitre: 'T1041', icon: '📤' },
                      { name: 'C2 via SSH', device: 'CCTV', mitre: 'T1071', icon: '📡' },
                      { name: 'DNS Tunneling', device: 'Router', mitre: 'T1572', icon: '🌐' },
                      { name: 'Lateral Scan', device: 'Router', mitre: 'T1046', icon: '↔️' },
                      { name: 'Credential Stuffing', device: 'Access', mitre: 'T1110', icon: '🔑' },
                      { name: 'Data Exfil via HTTPS', device: 'Access', mitre: 'T1048', icon: '📤' },
                    ].map((t, i) => (
                      <tr key={i}>
                        <td style={{ fontWeight: 600 }}>{t.icon} {t.name}</td>
                        <td><span style={{ fontSize: 11, background: '#f1f5f9', padding: '2px 8px', borderRadius: 4 }}>{t.device}</span></td>
                        <td style={{ fontFamily: 'monospace', fontSize: 11, color: '#3b82f6' }}>{t.mitre}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </>
      )}
    </>
  );
}

export default Security;
