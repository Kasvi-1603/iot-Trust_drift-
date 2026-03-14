import React, { useState, useEffect, useCallback, useRef } from 'react';
import axios from 'axios';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Cell, PieChart, Pie, Legend,
} from 'recharts';

const API = 'http://localhost:8002/api';

/* ── color maps ─────────────────────────────────────────────── */
const SEV_COLOR  = { Low: '#22c55e', Medium: '#f59e0b', High: '#f97316', Critical: '#ef4444' };
const SEV_BG     = { Low: '#f0fdf4', Medium: '#fffbeb', High: '#fff7ed', Critical: '#fef2f2' };
const SEV_BORDER = { Low: '#bbf7d0', Medium: '#fde68a', High: '#fed7aa', Critical: '#fecaca' };
const STATUS_COLORS = { COMPLIANT: '#22c55e', SOFT_DRIFT: '#f59e0b', HARD_VIOLATION: '#ef4444' };
const ACT_COLOR  = { info: '#6366f1', warning: '#f59e0b', error: '#ef4444', success: '#22c55e' };
const MITRE_COLORS = {
  TA0043: '#94a3b8', TA0001: '#6366f1', TA0002: '#8b5cf6',
  TA0003: '#a855f7', TA0007: '#f59e0b', TA0008: '#f97316',
  TA0010: '#ef4444', TA0011: '#dc2626',
};

/* ── SVG Radar / Behavioral DNA ─────────────────────────────── */
function RadarChart({ dimensions, current, baseline, severity, size = 200 }) {
  const cx = size / 2, cy = size / 2, r = size * 0.36, n = dimensions.length;
  const angle = i => (i * 2 * Math.PI / n) - Math.PI / 2;
  const pt    = (i, val) => ({
    x: cx + r * (val / 100) * Math.cos(angle(i)),
    y: cy + r * (val / 100) * Math.sin(angle(i)),
  });
  const labelPt = i => ({
    x: cx + (r + 22) * Math.cos(angle(i)),
    y: cy + (r + 22) * Math.sin(angle(i)),
  });
  const poly = vals =>
    dimensions.map((d, i) => pt(i, vals[d] ?? 0)).map(p => `${p.x},${p.y}`).join(' ');
  const color = SEV_COLOR[severity] || '#6366f1';

  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      {[25, 50, 75, 100].map(v => (
        <polygon key={v}
          points={dimensions.map((_, i) => pt(i, v)).map(p => `${p.x},${p.y}`).join(' ')}
          fill="none" stroke="#f0f0f0" strokeWidth="1"
        />
      ))}
      {dimensions.map((_, i) => (
        <line key={i} x1={cx} y1={cy} x2={pt(i, 100).x} y2={pt(i, 100).y}
          stroke="#e2e8f0" strokeWidth="1"
        />
      ))}
      <polygon points={poly(baseline)} fill="rgba(148,163,184,0.15)" stroke="#cbd5e1" strokeWidth="1.5" />
      <polygon points={poly(current)}  fill={`${color}20`}           stroke={color}    strokeWidth="2"
        style={{ transition: 'all 0.5s ease' }}
      />
      {dimensions.map((d, i) => {
        const p = pt(i, current[d] ?? 0);
        return <circle key={i} cx={p.x} cy={p.y} r="3" fill={color} />;
      })}
      {dimensions.map((d, i) => {
        const lp = labelPt(i);
        const words = d.split(' ');
        const abbr  = words.map(w => w[0]).join('').toUpperCase();
        return (
          <text key={i} x={lp.x} y={lp.y} textAnchor="middle" dominantBaseline="middle"
            fontSize="9" fill="#64748b" fontWeight="700"
          >{abbr}</text>
        );
      })}
    </svg>
  );
}

/* ── SVG Network Risk Map ────────────────────────────────────── */
function RiskMap({ nodes, edges }) {
  const W = 600, H = 340;
  const layout = {
    Router_01:   { x: 300, y: 90  },
    CCTV_01:     { x: 120, y: 250 },
    Access_01:   { x: 480, y: 250 },
    Honeypot_01: { x: 300, y: 295 },
  };
  const nodeMap = {};
  nodes.forEach(n => { nodeMap[n.id] = n; });

  const riskColor = r => r > 60 ? '#ef4444' : r > 30 ? '#f97316' : r > 10 ? '#f59e0b' : '#22c55e';
  const nodeR     = r => 30 + r * 0.18;

  return (
    <svg width="100%" viewBox={`0 0 ${W} ${H}`}>
      {/* Edges */}
      {edges.map((e, i) => {
        const f = layout[e.from], t = layout[e.to];
        if (!f || !t) return null;
        const active = e.risk_flow > 8;
        const mx = (f.x + t.x) / 2, my = (f.y + t.y) / 2;
        return (
          <g key={i}>
            <line x1={f.x} y1={f.y} x2={t.x} y2={t.y}
              stroke={active ? '#ef444466' : '#e2e8f0'}
              strokeWidth={active ? 2.5 : 1.5}
              strokeDasharray={active ? '6 3' : 'none'}
            />
            {active && (
              <text x={mx} y={my - 7} textAnchor="middle" fontSize="9" fill="#ef4444" fontWeight="700">
                {e.risk_flow}% risk
              </text>
            )}
          </g>
        );
      })}

      {/* Nodes */}
      {nodes.map(node => {
        const pos = layout[node.id];
        if (!pos) return null;
        const r     = nodeR(node.risk);
        const color = node.is_honeypot
          ? (node.severity === 'Critical' ? '#7c3aed' : '#6366f1')
          : riskColor(node.risk);
        const icon  = node.type === 'CCTV' ? '📷' : node.type === 'Router' ? '🌐'
          : node.type === 'AccessController' ? '🔑' : '🍯';

        return (
          <g key={node.id}>
            {node.risk > 25 && (
              <circle cx={pos.x} cy={pos.y} r={r + 10} fill={`${color}12`} stroke={`${color}30`} strokeWidth="1" />
            )}
            <circle cx={pos.x} cy={pos.y} r={r}
              fill={`${color}18`} stroke={color} strokeWidth="2.5"
            />
            <text x={pos.x} y={pos.y - 5} textAnchor="middle" fontSize="15">{icon}</text>
            {node.risk > 0 && (
              <text x={pos.x} y={pos.y + 12} textAnchor="middle" fontSize="9" fill={color} fontWeight="800">
                {node.risk}%
              </text>
            )}
            <text x={pos.x} y={pos.y + r + 14} textAnchor="middle" fontSize="11" fill="#1e293b" fontWeight="700">
              {node.id}
            </text>
            <text x={pos.x} y={pos.y + r + 26} textAnchor="middle" fontSize="9" fill="#64748b">
              {node.is_honeypot ? '🍯 LURE ACTIVE' : `Trust: ${node.trust}`}
            </text>
            {node.is_attacked && (
              <>
                <circle cx={pos.x + r - 4} cy={pos.y - r + 4} r="9" fill="#ef4444" />
                <text x={pos.x + r - 4} y={pos.y - r + 8} textAnchor="middle" fontSize="10" fill="#fff" fontWeight="700">!</text>
              </>
            )}
            {node.is_honeypot && node.severity === 'Critical' && (
              <>
                <circle cx={pos.x + r - 4} cy={pos.y - r + 4} r="9" fill="#7c3aed" />
                <text x={pos.x + r - 4} y={pos.y - r + 9} textAnchor="middle" fontSize="9" fill="#fff">⚡</text>
              </>
            )}
          </g>
        );
      })}
    </svg>
  );
}

/* ── Kill Chain ─────────────────────────────────────────────── */
function KillChain({ chain, stagesActive, events, patientZero, activeStage }) {
  const tactic_order = {};
  chain.forEach((t, i) => { tactic_order[t.id] = i; });

  return (
    <div>
      {/* MITRE stage strip */}
      <div style={{ display: 'flex', gap: 3, marginBottom: 24, overflowX: 'auto', paddingBottom: 4 }}>
        {chain.map((stage, i) => {
          const active    = stagesActive.includes(stage.id);
          const isCurrent = stage.id === activeStage;
          return (
            <div key={stage.id} style={{ display: 'flex', alignItems: 'center', gap: 3, flexShrink: 0 }}>
              <div style={{
                padding: '10px 12px', borderRadius: 10, textAlign: 'center', minWidth: 78,
                border:     `2px solid ${active ? stage.color : '#e2e8f0'}`,
                background: active ? `${stage.color}12` : '#f8fafc',
                opacity:    active ? 1 : 0.45,
                transition: 'all 0.3s',
                position:   'relative',
                cursor:     'default',
              }}>
                {isCurrent && (
                  <div style={{
                    position: 'absolute', top: -9, left: '50%', transform: 'translateX(-50%)',
                    background: stage.color, color: '#fff', fontSize: 8, fontWeight: 800,
                    padding: '2px 7px', borderRadius: 4, whiteSpace: 'nowrap', letterSpacing: 0.5,
                  }}>◉ ACTIVE</div>
                )}
                <div style={{ fontSize: 9, fontWeight: 700, color: active ? stage.color : '#94a3b8', marginBottom: 3 }}>
                  {stage.id}
                </div>
                <div style={{ fontSize: 11, fontWeight: 600, color: active ? '#1e293b' : '#94a3b8' }}>
                  {stage.short}
                </div>
              </div>
              {i < chain.length - 1 && <div style={{ color: '#cbd5e1', fontSize: 14 }}>›</div>}
            </div>
          );
        })}
      </div>

      {/* Patient zero banner */}
      {patientZero && (
        <div style={{
          background: '#fef2f2', border: '1px solid #fecaca', borderRadius: 10,
          padding: '12px 18px', marginBottom: 18,
          display: 'flex', alignItems: 'center', gap: 12,
        }}>
          <span style={{ fontSize: 22 }}>🎯</span>
          <div>
            <div style={{ fontSize: 12, fontWeight: 800, color: '#dc2626', letterSpacing: 0.5 }}>
              PATIENT ZERO IDENTIFIED
            </div>
            <div style={{ fontSize: 12, color: '#64748b', marginTop: 2 }}>
              First compromise detected on <strong style={{ color: '#1e293b' }}>{patientZero}</strong> —
              attack chain propagated from this device
            </div>
          </div>
        </div>
      )}

      {/* Event timeline */}
      <div style={{ maxHeight: 310, overflowY: 'auto' }}>
        {events.length === 0 ? (
          <div style={{ textAlign: 'center', color: '#94a3b8', padding: 40, fontSize: 13 }}>
            🛡 No attack events detected — system operating normally
          </div>
        ) : [...events].reverse().map((e, i) => {
          const mc = MITRE_COLORS[e.mitre_tactic] || '#94a3b8';
          const stageName = chain.find(s => s.id === e.mitre_tactic)?.name || e.mitre_tactic;
          return (
            <div key={i} style={{
              display: 'flex', gap: 12, padding: '10px 0',
              borderBottom: '1px solid #f1f5f9', alignItems: 'flex-start',
            }}>
              <div style={{ flexShrink: 0, paddingTop: 2 }}>
                <div style={{
                  background: `${mc}15`, border: `1px solid ${mc}40`,
                  borderRadius: 6, padding: '3px 7px', fontSize: 8,
                  fontWeight: 800, color: mc, textAlign: 'center', whiteSpace: 'nowrap',
                }}>
                  {e.mitre_tactic}
                </div>
                <div style={{ fontSize: 9, color: mc, textAlign: 'center', marginTop: 2, fontWeight: 600 }}>
                  {stageName.split(' ').map(w => w.slice(0, 5)).join(' ')}
                </div>
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 3 }}>
                  <span style={{ fontSize: 12, fontWeight: 700, color: '#1e293b' }}>{e.device_id}</span>
                  <span style={{
                    fontSize: 10, padding: '1px 8px', borderRadius: 20, fontWeight: 700,
                    background: SEV_BG[e.severity] || '#f8fafc', color: SEV_COLOR[e.severity] || '#94a3b8',
                    border: `1px solid ${SEV_BORDER[e.severity] || '#e2e8f0'}`,
                  }}>{e.severity}</span>
                </div>
                <div style={{ fontSize: 11, color: '#64748b', lineHeight: 1.5 }}>{e.evidence}</div>
              </div>
              <div style={{ fontSize: 10, color: '#94a3b8', whiteSpace: 'nowrap', flexShrink: 0, paddingTop: 2 }}>
                {new Date(e.window).toLocaleString('en-US', { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' })}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ── Self-Healing Console ────────────────────────────────────── */
function HealingConsole({ actions }) {
  const endRef = useRef(null);
  const ACT_ICON = {
    MONITOR: '📡', ALERT: '⚠️', THROTTLE: '🔻', BLOCK: '🚫',
    ISOLATE: '🔒', RESTORE: '✅', FINGERPRINT: '🧬', C2_BLOCK: '⛔',
    EXFIL_BLOCK: '📤', HEALED: '💚', ATTACK_DETECTED: '🔴',
  };

  return (
    <div style={{
      background: '#0f172a', borderRadius: 12, padding: '18px 20px',
      fontFamily: "'Courier New', monospace", maxHeight: 400, overflowY: 'auto',
      border: '1px solid #1e293b', position: 'relative',
    }}>
      <div style={{ color: '#22c55e', fontSize: 11, marginBottom: 14, fontWeight: 700, letterSpacing: 1 }}>
        ▶ TrustGuard Self-Healing Engine v2.1 — {actions.length > 0 ? 'ACTIVE' : 'STANDBY'}
      </div>
      {actions.length === 0 ? (
        <div style={{ color: '#475569', fontSize: 11 }}>
          [ No remediation actions required — system nominal ]
        </div>
      ) : actions.map((a, i) => {
        const lc = ACT_COLOR[a.level] || '#94a3b8';
        const icon = ACT_ICON[a.action] || '•';
        const ts = (() => {
          try { return new Date(a.timestamp).toLocaleTimeString(); } catch { return a.timestamp; }
        })();
        return (
          <div key={i} style={{ display: 'flex', gap: 8, marginBottom: 7, alignItems: 'flex-start' }}>
            <span style={{ color: '#334155', fontSize: 10, whiteSpace: 'nowrap', paddingTop: 1, minWidth: 60 }}>
              {ts}
            </span>
            <span style={{ fontSize: 12, flexShrink: 0 }}>{icon}</span>
            <span style={{
              fontSize: 9, fontWeight: 800, padding: '1px 6px', borderRadius: 3, flexShrink: 0,
              background: `${lc}20`, border: `1px solid ${lc}40`, color: lc, letterSpacing: 0.3,
            }}>
              [{a.action}]
            </span>
            <span style={{ color: '#94a3b8', fontSize: 11, flex: 1, lineHeight: 1.5 }}>
              {a.message}
            </span>
            {a.automated && (
              <span style={{ color: '#22c55e', fontSize: 8, whiteSpace: 'nowrap', paddingTop: 2, letterSpacing: 0.5 }}>
                AUTO
              </span>
            )}
          </div>
        );
      })}
      <div ref={endRef} />
    </div>
  );
}

/* ── Honeypot Panel ─────────────────────────────────────────── */
function HoneypotPanel({ honeypot }) {
  if (!honeypot) return null;
  const triggered = honeypot.triggered;

  return (
    <div style={{
      background: triggered ? '#3b0764' : '#0f172a',
      border: `2px solid ${triggered ? '#7c3aed' : '#1e293b'}`,
      borderRadius: 16, padding: 24, color: '#e2e8f0',
      transition: 'all 0.4s',
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
        <div>
          <div style={{ fontSize: 24, marginBottom: 6 }}>🍯</div>
          <div style={{ fontSize: 16, fontWeight: 800, color: triggered ? '#c4b5fd' : '#94a3b8' }}>
            Honeypot Device
          </div>
          <div style={{ fontSize: 12, color: '#475569', marginTop: 2, fontFamily: 'monospace' }}>
            {honeypot.honeypot_ip} — Decoy IoT Node
          </div>
        </div>
        <div style={{
          padding: '8px 20px', borderRadius: 30, fontSize: 12, fontWeight: 800, letterSpacing: 1,
          background: triggered ? '#7c3aed' : '#1e3a5f',
          color: triggered ? '#fff' : '#94a3b8',
          border: `1px solid ${triggered ? '#a78bfa' : '#334155'}`,
        }}>
          {triggered ? '⚡ TRIGGERED' : '🟢 ARMED'}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 20 }}>
        {[
          { label: 'Lure Events',       value: honeypot.lure_count,        color: triggered ? '#c4b5fd' : '#94a3b8' },
          { label: 'Active Injections', value: honeypot.active_injections,  color: triggered ? '#f87171' : '#94a3b8' },
        ].map(s => (
          <div key={s.label} style={{
            background: 'rgba(255,255,255,0.05)', borderRadius: 10, padding: '14px 18px',
            border: '1px solid rgba(255,255,255,0.08)',
          }}>
            <div style={{ fontSize: 28, fontWeight: 800, color: s.color }}>{s.value}</div>
            <div style={{ fontSize: 11, color: '#64748b', marginTop: 2 }}>{s.label}</div>
          </div>
        ))}
      </div>

      <div style={{ background: 'rgba(0,0,0,0.3)', borderRadius: 10, padding: 14, fontFamily: 'monospace' }}>
        <div style={{ fontSize: 10, color: '#475569', marginBottom: 8, fontWeight: 700, letterSpacing: 1 }}>
          LURE EVENTS LOG
        </div>
        {honeypot.lure_events.length === 0 ? (
          <div style={{ color: '#334155', fontSize: 11 }}>
            [ No traffic to honeypot — all quiet ]
          </div>
        ) : honeypot.lure_events.map((ev, i) => (
          <div key={i} style={{ fontSize: 11, color: '#94a3b8', marginBottom: 5 }}>
            <span style={{ color: '#7c3aed' }}>{ev.timestamp?.slice(0, 19)}</span>
            {' | '}
            <span style={{ color: '#c4b5fd' }}>{ev.device_id}</span>
            {' → '}
            <span style={{ color: '#f87171' }}>{ev.protocol}</span>
            {' '}
            <span style={{ color: '#ef4444', fontWeight: 700 }}>⚠ HONEYPOT HIT</span>
          </div>
        ))}
        {triggered && honeypot.lure_events.length === 0 && (
          <div style={{ color: '#7c3aed', fontSize: 11 }}>
            [ Risk propagated to honeypot via {honeypot.active_injections} active attack(s) ]
          </div>
        )}
      </div>

      <div style={{ marginTop: 16, fontSize: 11, color: '#475569', lineHeight: 1.7 }}>
        The honeypot is a dark IoT node that should receive zero legitimate traffic.
        Any connection attempt indicates lateral movement or adversarial scanning.
        {triggered && (
          <span style={{ color: '#c4b5fd', fontWeight: 700 }}>
            {' '}Threat actor has probed this decoy — attack chain confirmed.
          </span>
        )}
      </div>
    </div>
  );
}

/* ══════════════════════════════════════
   MAIN PAGE
   ══════════════════════════════════════ */
function Security() {
  const [tab,         setTab]         = useState('simulate');
  const [policyData,  setPolicyData]  = useState({ summary: [], results: [] });
  const [chainData,   setChainData]   = useState(null);
  const [fingerprints,setFingerprints]= useState([]);
  const [riskMap,     setRiskMap]     = useState(null);
  const [healing,     setHealing]     = useState([]);
  const [honeypot,    setHoneypot]    = useState(null);
  const [catalog,     setCatalog]     = useState({});
  const [injections,  setInjections]  = useState({});
  const [simLoading,  setSimLoading]  = useState(false);
  const [simResult,   setSimResult]   = useState(null);
  const [resetting,   setResetting]   = useState(false);
  const [loading,     setLoading]     = useState(true);
  const [lastRefresh, setLastRefresh] = useState(null);
  const fetchRef = useRef(null);

  const fetchAll = useCallback(async () => {
    try {
      const [polSum, polRes, chain, fp, risk, heal, honey, cat, inj] = await Promise.all([
        axios.get(`${API}/policy-summary`).catch(() => ({ data: [] })),
        axios.get(`${API}/policy-results`).catch(() => ({ data: [] })),
        axios.get(`${API}/attack-chain`).catch(() => ({ data: null })),
        axios.get(`${API}/behavioral-fingerprint`).catch(() => ({ data: [] })),
        axios.get(`${API}/risk-propagation`).catch(() => ({ data: null })),
        axios.get(`${API}/self-healing-actions`).catch(() => ({ data: { actions: [] } })),
        axios.get(`${API}/honeypot-status`).catch(() => ({ data: null })),
        axios.get(`${API}/attack-catalog`).catch(() => ({ data: {} })),
        axios.get(`${API}/injection-status`).catch(() => ({ data: { active_injections: {} } })),
      ]);
      setPolicyData({ summary: polSum.data || [], results: polRes.data || [] });
      setChainData(chain.data);
      setFingerprints(fp.data || []);
      setRiskMap(risk.data);
      setHealing(heal.data?.actions || []);
      setHoneypot(honey.data);
      setCatalog(cat.data || {});
      setInjections(inj.data?.active_injections || {});
      setLastRefresh(new Date().toLocaleTimeString());
        setLoading(false);
      } catch (err) {
        console.error(err);
        setLoading(false);
      }
  }, []);

  useEffect(() => { fetchRef.current = fetchAll; }, [fetchAll]);

  useEffect(() => {
    fetchAll();
    const iv = setInterval(fetchAll, 8000);
    const onVisible = () => { if (document.visibilityState === 'visible') fetchRef.current?.(); };
    document.addEventListener('visibilitychange', onVisible);
    return () => { clearInterval(iv); document.removeEventListener('visibilitychange', onVisible); };
  }, [fetchAll]);

  if (loading) {
    return (
      <div className="loading-container">
        <div className="loading-spinner" />
        <div className="loading-text">Loading security intelligence...</div>
      </div>
    );
  }

  /* ── attack simulation handlers ── */
  const injectAttack = async (deviceId, attackType) => {
    setSimLoading(true);
    setSimResult(null);
    try {
      const res = await axios.post(`${API}/inject-attack`, { device_id: deviceId, attack_type: attackType });
      setSimResult({ ok: true, msg: `✅ ${res.data.attack_name} injected on ${deviceId} — pipeline rerunning, all tabs will update in ~10s` });
      setTimeout(fetchAll, 3000);
      setTimeout(fetchAll, 10000);
    } catch (e) {
      setSimResult({ ok: false, msg: `❌ Injection failed: ${e.message}` });
    }
    setSimLoading(false);
  };

  const resetAll = async () => {
    setResetting(true);
    setSimResult(null);
    try {
      await axios.post(`${API}/reset`);
      setSimResult({ ok: true, msg: '✅ System reset to clean baseline — all devices restored to green' });
      setTimeout(fetchAll, 4000);
    } catch (e) {
      setSimResult({ ok: false, msg: `❌ Reset failed: ${e.message}` });
    }
    setResetting(false);
  };

  /* policy helpers */
  const statusCounts = {};
  policyData.results.forEach(r => {
    statusCounts[r.policy_status] = (statusCounts[r.policy_status] || 0) + 1;
  });
  const pieData    = Object.entries(statusCounts).map(([s, c]) => ({ status: s, count: c }));
  const violations = policyData.results.filter(r => r.policy_status !== 'COMPLIANT').slice(0, 20);

  const TABS = [
    { id: 'simulate',   label: '🚀 Simulate Attack',  desc: 'Inject & Watch' },
    { id: 'killchain',  label: '⛓ Kill Chain',        desc: 'MITRE ATT&CK' },
    { id: 'behavioral', label: '🧬 Behavioral DNA',    desc: 'Fingerprinting' },
    { id: 'riskmap',    label: '🗺 Risk Map',          desc: 'Network Map' },
    { id: 'healing',    label: '💊 Self-Healing',      desc: 'Auto-Response' },
    { id: 'honeypot',   label: '🍯 Honeypot',          desc: 'Decoy Lure' },
    { id: 'policy',     label: '📋 Policy',            desc: 'Compliance' },
  ];

  const attackCount   = chainData?.events?.length ?? 0;
  const honeypotAlert = honeypot?.triggered ?? false;
  const healingActs   = healing.filter(a => a.automated).length;

  return (
    <>
      {/* ── Page header ── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 24 }}>
        <div>
          <h1 className="page-title">Security Intelligence</h1>
          <p className="page-subtitle">
            Kill chain · Behavioral fingerprinting · Risk propagation · Self-healing response
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          {honeypotAlert && (
            <div style={{
              background: '#7c3aed', color: '#fff', borderRadius: 8,
              padding: '6px 14px', fontSize: 11, fontWeight: 800,
              display: 'flex', alignItems: 'center', gap: 6, letterSpacing: 0.5,
            }}>
              🍯 HONEYPOT TRIGGERED
            </div>
          )}
          {attackCount > 0 && (
            <div style={{
              background: '#fef2f2', border: '1px solid #fecaca', color: '#dc2626',
              borderRadius: 8, padding: '6px 14px', fontSize: 11, fontWeight: 700,
            }}>
              ⚠ {attackCount} Attack Events
            </div>
          )}
          <div style={{ fontSize: 11, color: '#94a3b8' }}>Updated {lastRefresh}</div>
          <button onClick={fetchAll} style={{
            background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: 8,
            padding: '6px 14px', fontSize: 12, cursor: 'pointer', color: '#64748b',
          }}>↺ Refresh</button>
        </div>
      </div>

      {/* ── Summary bar ── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 24 }}>
        {[
          { icon: '⛓', label: 'Kill Chain Events', value: attackCount,     color: '#ef4444', bg: '#fef2f2' },
          { icon: '🧬', label: 'Devices Fingerprinted', value: fingerprints.length, color: '#6366f1', bg: '#eef2ff' },
          { icon: '💊', label: 'Healing Actions',   value: healingActs,    color: '#22c55e', bg: '#f0fdf4' },
          { icon: '🍯', label: 'Honeypot Status',   value: honeypotAlert ? 'TRIGGERED' : 'ARMED', color: '#7c3aed', bg: '#f5f3ff' },
        ].map(s => (
          <div key={s.label} style={{
            background: s.bg, border: `1px solid ${s.color}30`,
            borderRadius: 12, padding: '14px 18px',
            display: 'flex', alignItems: 'center', gap: 12,
          }}>
            <span style={{ fontSize: 24 }}>{s.icon}</span>
            <div>
              <div style={{ fontSize: 22, fontWeight: 800, color: s.color }}>{s.value}</div>
              <div style={{ fontSize: 11, color: '#64748b' }}>{s.label}</div>
            </div>
          </div>
        ))}
      </div>

      {/* ── Tab bar ── */}
      <div style={{ display: 'flex', gap: 2, marginBottom: 20, borderBottom: '2px solid #f1f5f9' }}>
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)} style={{
            padding: '10px 16px', border: 'none', cursor: 'pointer', background: 'transparent',
            borderBottom: tab === t.id ? '2px solid #6366f1' : '2px solid transparent',
            marginBottom: -2, borderRadius: '8px 8px 0 0',
            color: tab === t.id ? '#6366f1' : '#64748b',
            fontWeight: tab === t.id ? 700 : 500, fontSize: 13, transition: 'all 0.2s',
          }}>
            {t.label}
          </button>
        ))}
      </div>

      {/* ══ Simulate Attack ══ */}
      {tab === 'simulate' && (
        <div>
          {/* Active injections banner */}
          {Object.keys(injections).length > 0 && (
            <div style={{
              background: '#fef2f2', border: '2px solid #fecaca', borderRadius: 12,
              padding: '14px 20px', marginBottom: 20,
              display: 'flex', justifyContent: 'space-between', alignItems: 'center',
            }}>
              <div>
                <div style={{ fontSize: 13, fontWeight: 800, color: '#dc2626', marginBottom: 6 }}>
                  ⚠ ACTIVE ATTACKS — {Object.keys(injections).length} device(s) compromised
                </div>
                {Object.entries(injections).map(([dev, inj]) => (
                  <div key={dev} style={{ fontSize: 12, color: '#64748b', marginBottom: 2 }}>
                    <strong style={{ color: '#1e293b' }}>{dev}</strong>: {inj.attack_name} · {inj.mitre} · injected at {new Date(inj.injected_at).toLocaleTimeString()}
                  </div>
                ))}
              </div>
              <button onClick={resetAll} disabled={resetting} style={{
                background: resetting ? '#f1f5f9' : '#fff',
                border: '2px solid #e2e8f0', borderRadius: 10,
                padding: '10px 20px', fontSize: 12, fontWeight: 700,
                cursor: resetting ? 'not-allowed' : 'pointer', color: '#64748b',
                flexShrink: 0, marginLeft: 16,
              }}>
                {resetting ? '⏳ Resetting...' : '↺ Reset to Baseline'}
              </button>
            </div>
          )}

          {/* Result message */}
          {simResult && (
            <div style={{
              padding: '12px 18px', borderRadius: 10, marginBottom: 20,
              fontSize: 12, fontWeight: 600,
              background: simResult.ok ? '#f0fdf4' : '#fef2f2',
              border: `1px solid ${simResult.ok ? '#bbf7d0' : '#fecaca'}`,
              color: simResult.ok ? '#16a34a' : '#dc2626',
            }}>
              {simResult.msg}
            </div>
          )}

          {/* Instruction bar */}
          <div style={{
            background: '#eef2ff', border: '1px solid #c7d2fe', borderRadius: 10,
            padding: '12px 18px', marginBottom: 24, fontSize: 12, color: '#4338ca',
            display: 'flex', alignItems: 'center', gap: 10,
          }}>
            <span style={{ fontSize: 20 }}>💡</span>
            <span>
              <strong>Demo flow:</strong> Click any attack below → pipeline reruns (~10s) →
              switch to <strong>⛓ Kill Chain</strong>, <strong>🧬 Behavioral DNA</strong>,{' '}
              <strong>🗺 Risk Map</strong>, and <strong>💊 Self-Healing</strong> tabs to watch everything change live.
            </span>
          </div>

          {/* Device attack cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 20 }}>
            {Object.entries(catalog).map(([deviceType, attacks]) => {
              const deviceIds = { CCTV: 'CCTV_01', Router: 'Router_01', AccessController: 'Access_01' };
              const deviceId  = deviceIds[deviceType] || deviceType;
              const isActive  = !!injections[deviceId];
              const fp        = fingerprints.find(f => f.device_id === deviceId);
              const icons     = { CCTV: '📷', Router: '🌐', AccessController: '🔑' };

              return (
                <div key={deviceType} style={{
                  background: '#fff', borderRadius: 16, overflow: 'hidden',
                  border: `2px solid ${isActive ? '#ef4444' : '#e2e8f0'}`,
                  boxShadow: isActive ? '0 0 0 4px rgba(239,68,68,0.08)' : '0 2px 8px rgba(0,0,0,0.04)',
                  transition: 'all 0.3s',
                }}>
                  {isActive && (
                    <div style={{
                      background: 'linear-gradient(90deg,#ef4444,#dc2626)',
                      color: '#fff', fontSize: 10, fontWeight: 800,
                      textAlign: 'center', padding: '5px 0', letterSpacing: 1.5,
                      display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6,
                    }}>
                      <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#fff', opacity: 0.85, display: 'inline-block' }} />
                      ATTACK ACTIVE
                    </div>
                  )}
                  <div style={{ padding: 20 }}>
                    {/* Device header */}
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
                      <span style={{ fontSize: 24 }}>{icons[deviceType] || '📡'}</span>
                      <div style={{ flex: 1 }}>
                        <div style={{ fontSize: 15, fontWeight: 700, color: '#1e293b' }}>{deviceId}</div>
                        <div style={{ fontSize: 11, color: '#64748b' }}>{deviceType}</div>
                      </div>
                      {fp && (
                        <span style={{
                          fontSize: 11, fontWeight: 700, padding: '3px 10px', borderRadius: 20,
                          background: SEV_BG[fp.severity], color: SEV_COLOR[fp.severity],
                          border: `1px solid ${SEV_BORDER[fp.severity]}`,
                        }}>{fp.severity}</span>
                      )}
                    </div>

                    {/* Trust bar */}
                    {fp && (
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
                        <div style={{ fontSize: 11, color: '#64748b', width: 32, flexShrink: 0 }}>Trust</div>
                        <div style={{ flex: 1, height: 6, background: '#f0f0f0', borderRadius: 3 }}>
                          <div style={{
                            height: '100%', borderRadius: 3, transition: 'width 0.5s',
                            width: `${fp.trust_score}%`,
                            background: SEV_COLOR[fp.severity],
                          }} />
                        </div>
                        <div style={{ fontSize: 12, fontWeight: 700, color: SEV_COLOR[fp.severity], width: 44, textAlign: 'right' }}>
                          {fp.trust_score}/100
                        </div>
                      </div>
                    )}

                    {/* Attack buttons */}
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                      {attacks.map(attack => (
                        <button
                          key={attack.id}
                          onClick={() => injectAttack(deviceId, attack.id)}
                          disabled={simLoading}
                          style={{
                            background: simLoading ? '#f8fafc' : '#fff',
                            border: '1.5px solid #e2e8f0', borderRadius: 10,
                            padding: '12px 16px', cursor: simLoading ? 'not-allowed' : 'pointer',
                            textAlign: 'left', transition: 'all 0.15s',
                            opacity: simLoading ? 0.6 : 1,
                          }}
                          onMouseEnter={e => { if (!simLoading) { e.currentTarget.style.borderColor = '#ef4444'; e.currentTarget.style.background = '#fef2f2'; } }}
                          onMouseLeave={e => { e.currentTarget.style.borderColor = '#e2e8f0'; e.currentTarget.style.background = simLoading ? '#f8fafc' : '#fff'; }}
                        >
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 5 }}>
                            <span style={{ fontSize: 13, fontWeight: 700, color: '#1e293b' }}>{attack.name}</span>
                            <span style={{
                              fontSize: 9, fontWeight: 800, color: '#ef4444',
                              background: '#fef2f2', padding: '2px 8px', borderRadius: 4, letterSpacing: 0.5,
                            }}>
                              {simLoading ? '⏳' : '⚡ INJECT'}
                            </span>
                          </div>
                          <div style={{ fontSize: 11, color: '#64748b', lineHeight: 1.5 }}>{attack.description}</div>
                          <div style={{ fontSize: 10, color: '#94a3b8', marginTop: 5, fontFamily: 'monospace' }}>{attack.mitre}</div>
                        </button>
                      ))}
                    </div>
                  </div>
                </div>
              );
            })}
            {Object.keys(catalog).length === 0 && (
              <div style={{ gridColumn: '1/-1', textAlign: 'center', padding: 48, color: '#94a3b8' }}>
                Loading attack catalog...
              </div>
            )}
      </div>

          {/* Reset button at bottom */}
          <div style={{ textAlign: 'center', marginTop: 28 }}>
            <button onClick={resetAll} disabled={resetting} style={{
              background: '#f8fafc', border: '1.5px solid #e2e8f0', borderRadius: 10,
              padding: '11px 28px', fontSize: 12, fontWeight: 700,
              cursor: resetting ? 'not-allowed' : 'pointer', color: '#64748b',
            }}>
              {resetting ? '⏳ Resetting pipeline...' : '↺ Reset all devices to clean baseline'}
            </button>
          </div>
        </div>
      )}

      {/* ══ Kill Chain ══ */}
      {tab === 'killchain' && (
        <div className="panel">
          <div className="panel-header">
            <div>
              <div className="panel-title">MITRE ATT&CK Kill Chain Analyzer</div>
              <div className="panel-subtitle">
                Attack progression mapped to MITRE framework — {attackCount} events detected
                {chainData?.patient_zero && ` · Patient Zero: ${chainData.patient_zero}`}
              </div>
            </div>
            {chainData?.active_stage && (
              <div style={{
                background: `${MITRE_COLORS[chainData.active_stage] || '#94a3b8'}15`,
                border: `1px solid ${MITRE_COLORS[chainData.active_stage] || '#e2e8f0'}`,
                borderRadius: 8, padding: '6px 14px',
                fontSize: 11, fontWeight: 700,
                color: MITRE_COLORS[chainData.active_stage] || '#64748b',
              }}>
                Active: {chainData.chain?.find(s => s.id === chainData.active_stage)?.name || chainData.active_stage}
              </div>
            )}
          </div>
          <div className="panel-body">
            {chainData ? (
              <KillChain
                chain={chainData.chain || []}
                stagesActive={chainData.stages_active || []}
                events={chainData.events || []}
                patientZero={chainData.patient_zero}
                activeStage={chainData.active_stage}
              />
            ) : (
              <div style={{ textAlign: 'center', color: '#94a3b8', padding: 40 }}>No kill chain data available</div>
            )}
          </div>
        </div>
      )}

      {/* ══ Behavioral DNA ══ */}
      {tab === 'behavioral' && (
        <div>
          <div style={{ background: '#eef2ff', border: '1px solid #c7d2fe', borderRadius: 10, padding: '12px 18px', marginBottom: 20, fontSize: 12, color: '#4338ca' }}>
            <strong>Behavioral DNA Fingerprinting</strong> — Each device's network behavior is decomposed into 6 
            dimensions and compared against its personal baseline. Deviations (red/orange bars) indicate anomalous 
            activity consistent with compromise, lateral movement, or exfiltration.
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(290px, 1fr))', gap: 18 }}>
            {fingerprints.map(fp => {
              const color = SEV_COLOR[fp.severity] || '#22c55e';
              const maxDelta = Math.max(0, ...fp.dimensions.map(d => (fp.current[d] ?? 0) - (fp.baseline[d] ?? 0)));
              return (
                <div key={fp.device_id} style={{
                  background: '#fff', borderRadius: 16, overflow: 'hidden',
                  border: `2px solid ${maxDelta > 30 ? color : SEV_BORDER[fp.severity] || '#e2e8f0'}`,
                  boxShadow: maxDelta > 30 ? `0 0 0 3px ${color}15` : '0 2px 8px rgba(0,0,0,0.04)',
                }}>
                  <div style={{
                    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                    padding: '14px 20px', borderBottom: '1px solid #f1f5f9',
                  }}>
                    <div>
                      <div style={{ fontSize: 14, fontWeight: 700, color: '#1e293b' }}>{fp.device_id}</div>
                      <div style={{ fontSize: 11, color: '#64748b' }}>Trust: {fp.trust_score}/100 · Behavioral fingerprint</div>
                    </div>
                    <span style={{
                      fontSize: 11, fontWeight: 700, padding: '3px 10px', borderRadius: 20,
                      background: SEV_BG[fp.severity], color: SEV_COLOR[fp.severity],
                      border: `1px solid ${SEV_BORDER[fp.severity]}`,
                    }}>{fp.severity}</span>
                  </div>
                  <div style={{ padding: '14px 20px 20px', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                    <RadarChart
                      dimensions={fp.dimensions} current={fp.current}
                      baseline={fp.baseline} severity={fp.severity} size={200}
                    />
                    {/* Dimension bars */}
                    <div style={{ width: '100%', marginTop: 14 }}>
                      {fp.dimensions.map(d => {
                        const cur   = fp.current[d]  ?? 0;
                        const base  = fp.baseline[d] ?? 0;
                        const delta = cur - base;
                        const isHigh = delta > 30;
                        const barColor = isHigh ? '#ef4444' : delta > 15 ? '#f97316' : color;
                        return (
                          <div key={d} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                            <div style={{ fontSize: 10, color: '#64748b', width: 115, flexShrink: 0 }}>{d}</div>
                            <div style={{ flex: 1, height: 5, background: '#f0f0f0', borderRadius: 3, overflow: 'hidden' }}>
                              <div style={{ height: '100%', width: `${Math.min(cur, 100)}%`, borderRadius: 3, background: barColor, transition: 'width 0.5s' }} />
                            </div>
                            <div style={{ fontSize: 10, width: 42, textAlign: 'right', fontWeight: 700, color: isHigh ? '#ef4444' : '#64748b' }}>
                              {delta > 0 ? `+${delta.toFixed(0)}` : delta.toFixed(0)}%
                            </div>
                          </div>
                        );
                      })}
                    </div>
                    <div style={{ marginTop: 12, fontSize: 10, color: '#94a3b8', display: 'flex', gap: 14 }}>
                      <span>
                        <span style={{ display: 'inline-block', width: 18, height: 2, background: '#cbd5e1', verticalAlign: 'middle', marginRight: 4, borderRadius: 2 }} />
                        Baseline
                      </span>
                      <span>
                        <span style={{ display: 'inline-block', width: 18, height: 2, background: color, verticalAlign: 'middle', marginRight: 4, borderRadius: 2 }} />
                        Current
                      </span>
                    </div>
                  </div>
                </div>
              );
            })}
            {fingerprints.length === 0 && (
              <div style={{ gridColumn: '1/-1', textAlign: 'center', padding: 48, color: '#94a3b8', fontSize: 13 }}>
                No behavioral fingerprint data — run the pipeline first.
              </div>
            )}
          </div>
        </div>
      )}

      {/* ══ Risk Map ══ */}
      {tab === 'riskmap' && (
        <div className="panel">
          <div className="panel-header">
            <div>
              <div className="panel-title">Network Risk Propagation Map</div>
              <div className="panel-subtitle">
                Live risk flow between IoT devices — honeypot lure node embedded in topology
              </div>
            </div>
            {riskMap?.honeypot_triggered && (
              <div style={{
                background: '#f5f3ff', border: '1px solid #7c3aed', borderRadius: 8,
                padding: '6px 14px', fontSize: 11, fontWeight: 700, color: '#7c3aed',
              }}>
                🍯 Honeypot Triggered
              </div>
            )}
          </div>
          <div className="panel-body">
            {riskMap ? (
              <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 28 }}>
                <div>
                  <RiskMap nodes={riskMap.nodes} edges={riskMap.edges} />
                </div>
                <div>
                  <div style={{ fontSize: 12, fontWeight: 700, color: '#1e293b', marginBottom: 14 }}>Device Risk Levels</div>
                  {riskMap.nodes.map(node => {
                    const riskColor = node.risk > 60 ? '#ef4444' : node.risk > 30 ? '#f97316' : node.risk > 10 ? '#f59e0b' : '#22c55e';
                    return (
                      <div key={node.id} style={{ marginBottom: 14 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 5 }}>
                          <span style={{ fontSize: 12, color: '#1e293b', fontWeight: 600 }}>
                            {node.is_honeypot ? '🍯 ' : ''}{node.id}
                            {node.is_attacked && <span style={{ marginLeft: 6, fontSize: 10, color: '#ef4444', fontWeight: 700 }}>ATTACKED</span>}
                          </span>
                          <span style={{ fontSize: 13, fontWeight: 800, color: riskColor }}>{node.risk}%</span>
                        </div>
                        <div style={{ height: 7, background: '#f0f0f0', borderRadius: 4, overflow: 'hidden' }}>
                          <div style={{ height: '100%', width: `${node.risk}%`, borderRadius: 4, background: riskColor, transition: 'width 0.5s' }} />
                        </div>
                        <div style={{ fontSize: 10, color: '#94a3b8', marginTop: 3 }}>
                          {node.is_honeypot ? 'Decoy · should be 0%' : `Trust: ${node.trust}/100`}
                        </div>
                      </div>
                    );
                  })}
                  <div style={{ marginTop: 8, padding: 14, background: '#f8fafc', borderRadius: 10, border: '1px solid #e2e8f0' }}>
                    <div style={{ fontSize: 11, fontWeight: 700, color: '#1e293b', marginBottom: 8 }}>Propagation Model</div>
                    <div style={{ fontSize: 11, color: '#64748b', lineHeight: 1.8 }}>
                      Router compromise → <strong>35%</strong> risk to endpoints<br />
                      Honeypot receives <strong>50%</strong> of router risk<br />
                      Triggered honeypot = lateral movement confirmed<br />
                      Each active attack adds <strong>+15%</strong> honeypot pressure
                    </div>
                  </div>
                </div>
              </div>
            ) : (
              <div style={{ textAlign: 'center', color: '#94a3b8', padding: 40 }}>Risk map data unavailable</div>
            )}
          </div>
        </div>
      )}

      {/* ══ Self-Healing ══ */}
      {tab === 'healing' && (
        <div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 20 }}>
            {[
              { icon: '⚡', label: 'Auto Actions',       value: healing.filter(a => a.automated).length,             color: '#6366f1' },
              { icon: '🚫', label: 'Threats Blocked',    value: healing.filter(a => a.action === 'BLOCK').length,    color: '#ef4444' },
              { icon: '🔒', label: 'Devices Isolated',   value: healing.filter(a => a.action === 'ISOLATE').length,  color: '#f97316' },
              { icon: '✅', label: 'Devices Restored',   value: healing.filter(a => a.action === 'RESTORE').length,  color: '#22c55e' },
            ].map(s => (
              <div key={s.label} style={{
                background: '#fff', borderRadius: 12, border: '1px solid #e2e8f0',
                padding: '16px 20px', display: 'flex', alignItems: 'center', gap: 14,
              }}>
                <div style={{ fontSize: 28 }}>{s.icon}</div>
                <div>
                  <div style={{ fontSize: 26, fontWeight: 800, color: s.color }}>{s.value}</div>
                  <div style={{ fontSize: 11, color: '#64748b' }}>{s.label}</div>
                </div>
              </div>
            ))}
          </div>
          <div className="panel">
            <div className="panel-header">
              <div>
                <div className="panel-title">Autonomous Response Console</div>
                <div className="panel-subtitle">
                  Real-time self-healing actions — automated threat containment and remediation
                </div>
              </div>
              <div style={{
                display: 'flex', alignItems: 'center', gap: 6,
                background: '#f0fdf4', border: '1px solid #bbf7d0',
                borderRadius: 8, padding: '5px 14px', fontSize: 11, fontWeight: 700, color: '#16a34a',
              }}>
                <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#22c55e', display: 'inline-block' }} />
                Engine Active
              </div>
            </div>
            <div className="panel-body">
              <HealingConsole actions={healing} />
            </div>
          </div>
        </div>
      )}

      {/* ══ Honeypot ══ */}
      {tab === 'honeypot' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
          <HoneypotPanel honeypot={honeypot} />
          <div>
            <div className="panel" style={{ marginBottom: 16 }}>
              <div className="panel-header">
                <div>
                  <div className="panel-title">How It Works</div>
                  <div className="panel-subtitle">Deception-based threat detection</div>
                </div>
              </div>
              <div className="panel-body">
                <div style={{ fontSize: 12, color: '#64748b', lineHeight: 2 }}>
                  {[
                    ['🎭 Digital Decoy',   'A fake IoT node (192.168.1.99) is embedded in the network topology but runs no real services.'],
                    ['📡 Zero Traffic',    'Under normal operation, no device should ever communicate with the honeypot IP.'],
                    ['🔍 Lure Detection',  'Any packet to the honeypot indicates an attacker scanning or moving laterally.'],
                    ['⚡ Instant Alert',   'Detection triggers immediate risk elevation and self-healing isolation sequence.'],
                    ['🧬 Attribution',     'Source device and protocol reveal the attack vector and patient-zero device.'],
                  ].map(([title, desc]) => (
                    <div key={title} style={{ marginBottom: 12, display: 'flex', gap: 10 }}>
                      <span style={{ fontWeight: 700, color: '#1e293b', minWidth: 130 }}>{title}</span>
                      <span>{desc}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
            <div className="panel">
              <div className="panel-header">
                <div>
                  <div className="panel-title">Digital Twin Comparison</div>
                  <div className="panel-subtitle">Expected vs actual device behavior</div>
                </div>
              </div>
              <div className="panel-body">
                {fingerprints.slice(0, 2).map(fp => {
                  const color = SEV_COLOR[fp.severity] || '#22c55e';
                  const topDev = fp.dimensions.reduce((a, d) => {
                    const delta = (fp.current[d] ?? 0) - (fp.baseline[d] ?? 0);
                    return delta > (a.delta ?? 0) ? { dim: d, delta } : a;
                  }, { dim: null, delta: 0 });
                  return (
                    <div key={fp.device_id} style={{ marginBottom: 16, padding: 14, background: '#f8fafc', borderRadius: 10, border: '1px solid #e2e8f0' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                        <span style={{ fontSize: 13, fontWeight: 700, color: '#1e293b' }}>{fp.device_id}</span>
                        <span style={{ fontSize: 11, color: color, fontWeight: 700 }}>{fp.severity}</span>
                      </div>
                      <div style={{ fontSize: 11, color: '#64748b' }}>
                        Digital twin deviation: <strong style={{ color }}>
                          {topDev.dim ? `+${topDev.delta.toFixed(0)}% on ${topDev.dim}` : 'Within normal range'}
                        </strong>
                      </div>
                      <div style={{ marginTop: 8, height: 4, background: '#e2e8f0', borderRadius: 2, overflow: 'hidden' }}>
                        <div style={{
                          height: '100%', borderRadius: 2, background: color,
                          width: `${Math.min(100, Math.abs(topDev.delta))}%`, transition: 'width 0.5s',
                        }} />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ══ Policy ══ */}
      {tab === 'policy' && (
        <>
      <div className="stats-bar">
            {policyData.summary.map(s => {
          const rateClass = s.hard_violation > 0 ? 'bad' : s.soft_drift > 0 ? 'warn' : 'good';
          return (
            <div key={s.device_id} className="compliance-card">
              <div className="compliance-device-name">{s.device_id}</div>
              <div className="compliance-type">{s.device_type}</div>
              <div className={`compliance-rate ${rateClass}`}>{s.compliance_rate}%</div>
              <div className="compliance-bar-track">
                <div className={`compliance-bar-fill ${rateClass}`} style={{ width: `${s.compliance_rate}%` }} />
              </div>
              <div className="compliance-detail">
                <span><span className="dot-green" /> {s.compliant} OK</span>
                <span><span className="dot-yellow" /> {s.soft_drift} Drift</span>
                <span><span className="dot-red" /> {s.hard_violation} Violation</span>
              </div>
            </div>
          );
        })}
      </div>

      <div className="two-col-grid">
        <div className="panel">
              <div className="panel-header"><div>
              <div className="panel-title">Compliance Rate by Device</div>
              <div className="panel-subtitle">Percentage of compliant hourly windows</div>
              </div></div>
          <div className="panel-body">
            <div className="chart-container small">
              <ResponsiveContainer width="100%" height="100%">
                    <BarChart
                      data={policyData.summary.map(s => ({
                        device: s.device_id, compliance: s.compliance_rate,
                        hv: s.hard_violation > 0, sd: s.soft_drift > 0,
                      }))}
                      margin={{ top: 10, right: 20, left: 0, bottom: 0 }}
                    >
                  <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
                  <XAxis dataKey="device" tick={{ fontSize: 11, fill: '#64748b' }} tickLine={false} />
                  <YAxis domain={[0, 100]} tick={{ fontSize: 11, fill: '#94a3b8' }} tickLine={false} width={35} tickFormatter={v => `${v}%`} />
                      <Tooltip contentStyle={{ fontSize: 12, borderRadius: 8 }} formatter={v => `${v}%`} />
                      <Bar dataKey="compliance" radius={[6, 6, 0, 0]}>
                        {policyData.summary.map((d, i) => (
                          <Cell key={i} fill={d.hard_violation > 0 ? '#ef4444' : d.soft_drift > 0 ? '#f59e0b' : '#22c55e'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        <div className="panel">
              <div className="panel-header"><div>
              <div className="panel-title">Policy Status Distribution</div>
                <div className="panel-subtitle">Overall policy evaluation breakdown</div>
              </div></div>
          <div className="panel-body">
            <div className="chart-container small">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                      <Pie data={pieData} dataKey="count" nameKey="status"
                        cx="50%" cy="50%" innerRadius={55} outerRadius={90} paddingAngle={3}
                    label={({ status, count }) => `${status.replace('_', ' ')}: ${count}`}
                    style={{ fontSize: 11 }}
                  >
                        {pieData.map((p, i) => <Cell key={i} fill={STATUS_COLORS[p.status] || '#94a3b8'} />)}
                  </Pie>
                      <Tooltip contentStyle={{ fontSize: 12, borderRadius: 8 }} />
                  <Legend verticalAlign="bottom" height={30} wrapperStyle={{ fontSize: 11 }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      </div>

      <div className="panel">
            <div className="panel-header"><div>
              <div className="panel-title">Violations Log</div>
              <div className="panel-subtitle">All non-compliant evaluations with details</div>
            </div></div>
        <div className="panel-body no-padding" style={{ paddingTop: 0 }}>
          {violations.length === 0 ? (
                <div className="table-empty">No violations found</div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table className="data-table">
                <thead>
                  <tr>
                        <th>Time</th><th>Device</th><th>Type</th>
                        <th>Status</th><th>Violations</th><th>Penalty</th>
                  </tr>
                </thead>
                <tbody>
                  {violations.map((v, i) => (
                    <tr key={i}>
                          <td className="table-cell-time">{new Date(v.window).toLocaleString()}</td>
                      <td className="table-cell-device">{v.device_id}</td>
                      <td style={{ fontSize: 12, color: '#64748b' }}>{v.device_type}</td>
                      <td>
                            <span className={`severity-badge ${v.policy_status === 'HARD_VIOLATION' ? 'high' : 'medium'}`}>
                          {v.policy_status.replace('_', ' ')}
                        </span>
                      </td>
                      <td style={{ fontSize: 12, maxWidth: 300 }}>{v.violations}</td>
                          <td style={{ fontWeight: 600, color: v.penalty >= 25 ? '#ef4444' : '#f59e0b' }}>
                            -{v.penalty}
                          </td>
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
    </>
  );
}

export default Security;
