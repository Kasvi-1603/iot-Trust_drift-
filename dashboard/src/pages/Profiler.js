import React, { useState, useEffect, useCallback, useRef } from 'react';
import axios from 'axios';

const API = 'http://localhost:8002/api';

const SEV_COLOR  = { Low: '#22c55e', Medium: '#f59e0b', High: '#f97316', Critical: '#ef4444' };
const SEV_BG     = { Low: '#f0fdf4', Medium: '#fffbeb', High: '#fff7ed', Critical: '#fef2f2' };
const SEV_BORDER = { Low: '#bbf7d0', Medium: '#fde68a', High: '#fed7aa', Critical: '#fecaca' };

const DEVICE_ICON = {
  CCTV:             '📷',
  Router:           '🌐',
  AccessController: '🔑',
};

/* ── helpers ── */
function sev(s) { return (s || 'low').toLowerCase(); }
function errorPct(trust) { return Math.max(0, 100 - trust).toFixed(1); }

/* ── circular gauge ── */
function TrustGauge({ score, severity }) {
  const r = 38;
  const circ = 2 * Math.PI * r;
  const pct  = Math.max(0, Math.min(100, score)) / 100;
  const dash  = circ * pct;
  const color = SEV_COLOR[severity] || '#94a3b8';

  return (
    <svg width="100" height="100" viewBox="0 0 100 100">
      <circle cx="50" cy="50" r={r} fill="none" stroke="#f0f0f0" strokeWidth="9" />
      <circle
        cx="50" cy="50" r={r} fill="none"
        stroke={color} strokeWidth="9"
        strokeDasharray={`${dash} ${circ}`}
        strokeLinecap="round"
        transform="rotate(-90 50 50)"
        style={{ transition: 'stroke-dasharray 0.6s ease' }}
      />
      <text x="50" y="46" textAnchor="middle" fontSize="18" fontWeight="700" fill={color}>{score}</text>
      <text x="50" y="60" textAnchor="middle" fontSize="9" fill="#94a3b8">/ 100</text>
    </svg>
  );
}

/* ── deduction bar ── */
function DeductionBar({ label, value, max, color }) {
  const pct = Math.min(100, (value / max) * 100);
  return (
    <div style={{ marginBottom: 8 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: '#64748b', marginBottom: 3 }}>
        <span>{label}</span>
        <span style={{ fontWeight: 600, color: value > 0 ? color : '#22c55e' }}>
          {value > 0 ? `-${value} pts` : '0 pts'}
        </span>
      </div>
      <div style={{ height: 5, background: '#f0f0f0', borderRadius: 3, overflow: 'hidden' }}>
        <div style={{ height: '100%', width: `${pct}%`, background: color, borderRadius: 3, transition: 'width 0.5s ease' }} />
      </div>
    </div>
  );
}

/* ── single device profiler card ── */
function DeviceProfileCard({ device, assessment, injection, rank }) {
  const severity   = device.severity || 'Low';
  const errPct     = errorPct(device.trust_score);
  const isAttacked = !!injection;
  const isWorst    = rank === 1;

  const anomDed    = assessment ? assessment.anomaly_deduction : device.anomaly_deduction || 0;
  const driftDed   = assessment ? assessment.drift?.penalty    : device.drift_deduction   || 0;
  const polDed     = assessment ? assessment.policy?.penalty   : device.policy_deduction  || 0;
  const totalDed   = Math.min(100, anomDed + driftDed + polDed);
  const confidence = assessment?.confidence ?? null;

  return (
    <div style={{
      background: '#fff',
      borderRadius: 16,
      border: `2px solid ${isAttacked ? '#ef4444' : isWorst ? '#f97316' : SEV_BORDER[severity]}`,
      boxShadow: isAttacked
        ? '0 0 0 3px rgba(239,68,68,0.12), 0 4px 16px rgba(0,0,0,0.06)'
        : '0 2px 8px rgba(0,0,0,0.05)',
      overflow: 'hidden',
      position: 'relative',
    }}>

      {/* Attack / Worst banner */}
      {isAttacked && (
        <div style={{
          background: '#ef4444', color: '#fff', fontSize: 10, fontWeight: 700,
          textAlign: 'center', padding: '4px 0', letterSpacing: 1,
          display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 5,
        }}>
          <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#fff', animation: 'pulse-ring 1.2s infinite', display: 'inline-block' }} />
          ATTACK ACTIVE
        </div>
      )}
      {!isAttacked && isWorst && (
        <div style={{
          background: '#f97316', color: '#fff', fontSize: 10, fontWeight: 700,
          textAlign: 'center', padding: '4px 0', letterSpacing: 1,
        }}>
          ⚠ HIGHEST RISK
        </div>
      )}

      <div style={{ padding: 20 }}>
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 16 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 3 }}>
              <span style={{ fontSize: 20 }}>{DEVICE_ICON[device.device_type] || '📡'}</span>
              <span style={{ fontSize: 15, fontWeight: 700, color: '#1a1a2e' }}>{device.device_id}</span>
            </div>
            <div style={{ fontSize: 11, color: '#64748b' }}>{device.description || device.device_type}</div>
          </div>
          <span style={{
            fontSize: 11, fontWeight: 700, padding: '4px 10px', borderRadius: 20,
            background: SEV_BG[severity], color: SEV_COLOR[severity], border: `1px solid ${SEV_BORDER[severity]}`,
          }}>
            {severity}
          </span>
        </div>

        {/* Gauge + Error % */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 20, marginBottom: 18 }}>
          <TrustGauge score={device.trust_score} severity={severity} />
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 11, color: '#94a3b8', marginBottom: 2 }}>Error Rate</div>
            <div style={{
              fontSize: 32, fontWeight: 800, letterSpacing: -1,
              color: parseFloat(errPct) > 40 ? '#ef4444' : parseFloat(errPct) > 15 ? '#f59e0b' : '#22c55e',
            }}>
              {errPct}%
            </div>
            <div style={{ fontSize: 11, color: '#94a3b8' }}>trust deficit</div>

            {/* Fault rank badge */}
            <div style={{
              marginTop: 8, display: 'inline-block',
              fontSize: 10, fontWeight: 700, padding: '3px 8px', borderRadius: 6,
              background: rank === 1 ? '#fef2f2' : rank === 2 ? '#fffbeb' : '#f0fdf4',
              color: rank === 1 ? '#ef4444' : rank === 2 ? '#f59e0b' : '#22c55e',
              border: `1px solid ${rank === 1 ? '#fecaca' : rank === 2 ? '#fde68a' : '#bbf7d0'}`,
            }}>
              #{rank} FAULT RANK
            </div>

            {/* ML Confidence indicator */}
            {confidence !== null && (
              <div style={{ marginTop: 10 }}>
                <div style={{ fontSize: 10, color: '#94a3b8', marginBottom: 3 }}>ML Confidence</div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <div style={{ flex: 1, height: 4, background: '#f0f0f0', borderRadius: 2, overflow: 'hidden' }}>
                    <div style={{
                      height: '100%',
                      width: `${confidence}%`,
                      background: confidence > 75 ? '#3b82f6' : confidence > 40 ? '#f59e0b' : '#94a3b8',
                      borderRadius: 2,
                      transition: 'width 0.6s ease',
                    }} />
                  </div>
                  <span style={{
                    fontSize: 11, fontWeight: 700, minWidth: 34, textAlign: 'right',
                    color: confidence > 75 ? '#3b82f6' : confidence > 40 ? '#f59e0b' : '#94a3b8',
                  }}>{confidence}%</span>
                </div>
                <div style={{ fontSize: 9, color: '#94a3b8', marginTop: 2 }}>
                  {confidence > 75 ? 'High confidence signal' : confidence > 40 ? 'Moderate confidence' : 'Near decision boundary'}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Deduction bars */}
        <div style={{ borderTop: '1px solid #f0f0f0', paddingTop: 14 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: '#64748b', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 10 }}>
            Deduction Breakdown
          </div>
          <DeductionBar label="ML Anomaly" value={parseFloat(anomDed.toFixed(1))} max={40} color="#ef4444" />
          <DeductionBar label="Statistical Drift" value={driftDed} max={20} color="#f59e0b" />
          <DeductionBar label="Policy Violations" value={polDed} max={40} color="#8b5cf6" />

          {/* Total deduction */}
          <div style={{
            marginTop: 10, padding: '8px 12px', borderRadius: 8,
            background: totalDed > 40 ? '#fef2f2' : totalDed > 15 ? '#fffbeb' : '#f0fdf4',
            display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          }}>
            <span style={{ fontSize: 11, fontWeight: 600, color: '#64748b' }}>Total Deduction</span>
            <span style={{
              fontSize: 14, fontWeight: 700,
              color: totalDed > 40 ? '#ef4444' : totalDed > 15 ? '#f59e0b' : '#22c55e',
            }}>
              -{totalDed.toFixed(1)} pts
            </span>
          </div>
        </div>

        {/* Attack injection info */}
        {isAttacked && injection && (
          <div style={{
            marginTop: 12, padding: '10px 12px', borderRadius: 8,
            background: '#fef2f2', border: '1px solid #fecaca',
          }}>
            <div style={{ fontSize: 10, fontWeight: 700, color: '#ef4444', textTransform: 'uppercase', marginBottom: 4 }}>
              Active Attack
            </div>
            <div style={{ fontSize: 12, fontWeight: 600, color: '#1a1a2e' }}>{injection.attack_name}</div>
            <div style={{ fontSize: 11, color: '#64748b', marginTop: 2 }}>
              {injection.mitre} &bull; {injection.attack_flows} flows injected
            </div>
          </div>
        )}

        {/* Drift class + policy status pills */}
        {assessment && (
          <div style={{ marginTop: 12, display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            <span style={{
              fontSize: 10, fontWeight: 600, padding: '3px 8px', borderRadius: 6,
              background: assessment.drift?.drift_class === 'DRIFT_STRONG' ? '#fef2f2'
                        : assessment.drift?.drift_class === 'DRIFT_MILD'   ? '#fffbeb' : '#f0fdf4',
              color: assessment.drift?.drift_class === 'DRIFT_STRONG' ? '#ef4444'
                   : assessment.drift?.drift_class === 'DRIFT_MILD'   ? '#f59e0b' : '#22c55e',
            }}>
              {(assessment.drift?.drift_class || 'DRIFT_NONE').replace('DRIFT_', '')}
            </span>
            <span style={{
              fontSize: 10, fontWeight: 600, padding: '3px 8px', borderRadius: 6,
              background: assessment.policy?.policy_status === 'HARD_VIOLATION' ? '#fef2f2'
                        : assessment.policy?.policy_status === 'SOFT_DRIFT'     ? '#fffbeb' : '#f0fdf4',
              color: assessment.policy?.policy_status === 'HARD_VIOLATION' ? '#ef4444'
                   : assessment.policy?.policy_status === 'SOFT_DRIFT'     ? '#f59e0b' : '#22c55e',
            }}>
              {(assessment.policy?.policy_status || 'COMPLIANT').replace('_', ' ')}
            </span>
          </div>
        )}
      </div>
    </div>
  );
}

/* ══════════════════════════════════════
   MAIN PAGE
   ══════════════════════════════════════ */
function Profiler() {
  const [devices,     setDevices]     = useState([]);
  const [assessments, setAssessments] = useState({});   // {device_id: assessment}
  const [injections,  setInjections]  = useState({});   // {device_id: injection_info}
  const [loading,     setLoading]     = useState(true);
  const [lastRefresh, setLastRefresh] = useState(null);
  const fetchAllRef = useRef(null);

  const fetchAll = useCallback(async () => {
    try {
      const [devRes, injRes] = await Promise.all([
        axios.get(`${API}/devices`),
        axios.get(`${API}/injection-status`),
      ]);

      const devList = devRes.data;
      setDevices(devList);
      setInjections(injRes.data.active_injections || {});

      // Fetch full assessment for each device in parallel
      const assessResults = await Promise.all(
        devList.map(d =>
          axios.get(`${API}/device/${d.device_id}/assessment`)
            .then(r => [d.device_id, r.data])
            .catch(() => [d.device_id, null])
        )
      );
      const assessMap = {};
      assessResults.forEach(([id, data]) => { assessMap[id] = data; });
      setAssessments(assessMap);

      setLastRefresh(new Date().toLocaleTimeString());
      setLoading(false);
    } catch (err) {
      console.error(err);
      setLoading(false);
    }
  }, []);

  // Keep ref in sync so visibility handler always calls latest fetchAll
  useEffect(() => { fetchAllRef.current = fetchAll; }, [fetchAll]);

  useEffect(() => {
    fetchAll();
    const iv = setInterval(fetchAll, 5000);   // auto-refresh every 5 s

    // Immediately re-fetch when user switches back to this tab/page
    const onVisible = () => {
      if (document.visibilityState === 'visible') fetchAllRef.current?.();
    };
    document.addEventListener('visibilitychange', onVisible);

    return () => {
      clearInterval(iv);
      document.removeEventListener('visibilitychange', onVisible);
    };
  }, [fetchAll]);

  if (loading) {
    return (
      <div className="loading-container">
        <div className="loading-spinner" />
        <div className="loading-text">Loading device profiles...</div>
      </div>
    );
  }

  /* ── derived stats ── */
  const sorted       = [...devices].sort((a, b) => a.trust_score - b.trust_score);   // worst first
  const affected     = devices.filter(d => d.severity !== 'Low');
  const attacked     = Object.keys(injections);
  const atFault      = sorted[0];
  const avgError     = devices.length
    ? (devices.reduce((s, d) => s + parseFloat(errorPct(d.trust_score)), 0) / devices.length).toFixed(1)
    : 0;

  return (
    <>
      {/* ── Page title ── */}
      <div className="page-title-section" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h1 className="page-title">Device Profiler</h1>
          <p className="page-subtitle">
            Attack attribution, fault ranking, and per-device error analysis
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          {lastRefresh && (
            <span style={{ fontSize: 11, color: '#94a3b8' }}>Updated {lastRefresh}</span>
          )}
          <button
            onClick={fetchAll}
            style={{
              padding: '7px 16px', borderRadius: 8, border: '1px solid #e2e8f0',
              background: '#fff', color: '#3b82f6', fontSize: 12, fontWeight: 600,
              cursor: 'pointer', fontFamily: 'inherit',
            }}
          >
            ↻ Refresh
          </button>
        </div>
      </div>

      {/* ── Summary row ── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14, marginBottom: 24 }}>
        {/* Devices monitored */}
        <div style={{ background: '#fff', borderRadius: 12, padding: '16px 20px', border: '1px solid #e2e8f0' }}>
          <div style={{ fontSize: 11, color: '#94a3b8', fontWeight: 600, textTransform: 'uppercase', marginBottom: 6 }}>Devices Monitored</div>
          <div style={{ fontSize: 30, fontWeight: 800, color: '#1a1a2e' }}>{devices.length}</div>
        </div>

        {/* Affected */}
        <div style={{
          background: affected.length > 0 ? '#fff7ed' : '#f0fdf4',
          borderRadius: 12, padding: '16px 20px',
          border: `1px solid ${affected.length > 0 ? '#fed7aa' : '#bbf7d0'}`,
        }}>
          <div style={{ fontSize: 11, color: '#94a3b8', fontWeight: 600, textTransform: 'uppercase', marginBottom: 6 }}>Affected Devices</div>
          <div style={{ fontSize: 30, fontWeight: 800, color: affected.length > 0 ? '#f97316' : '#22c55e' }}>
            {affected.length}
          </div>
          <div style={{ fontSize: 11, color: '#94a3b8', marginTop: 2 }}>severity &gt; Low</div>
        </div>

        {/* Active attacks */}
        <div style={{
          background: attacked.length > 0 ? '#fef2f2' : '#f0fdf4',
          borderRadius: 12, padding: '16px 20px',
          border: `1px solid ${attacked.length > 0 ? '#fecaca' : '#bbf7d0'}`,
        }}>
          <div style={{ fontSize: 11, color: '#94a3b8', fontWeight: 600, textTransform: 'uppercase', marginBottom: 6 }}>Active Attacks</div>
          <div style={{ fontSize: 30, fontWeight: 800, color: attacked.length > 0 ? '#ef4444' : '#22c55e' }}>
            {attacked.length}
          </div>
          {attacked.length > 0 && (
            <div style={{ fontSize: 11, color: '#ef4444', marginTop: 2, fontWeight: 600 }}>
              {attacked.join(', ')}
            </div>
          )}
        </div>

        {/* Avg error */}
        <div style={{
          background: parseFloat(avgError) > 20 ? '#fef2f2' : '#f0fdf4',
          borderRadius: 12, padding: '16px 20px',
          border: `1px solid ${parseFloat(avgError) > 20 ? '#fecaca' : '#bbf7d0'}`,
        }}>
          <div style={{ fontSize: 11, color: '#94a3b8', fontWeight: 600, textTransform: 'uppercase', marginBottom: 6 }}>Avg Error Rate</div>
          <div style={{ fontSize: 30, fontWeight: 800, color: parseFloat(avgError) > 20 ? '#ef4444' : '#22c55e' }}>
            {avgError}%
          </div>
          <div style={{ fontSize: 11, color: '#94a3b8', marginTop: 2 }}>across all devices</div>
        </div>
      </div>

      {/* ── At-fault callout ── */}
      {atFault && atFault.severity !== 'Low' && (
        <div style={{
          background: '#fef2f2', border: '1px solid #fecaca', borderRadius: 12,
          padding: '14px 20px', marginBottom: 20,
          display: 'flex', alignItems: 'center', gap: 14,
        }}>
          <span style={{ fontSize: 28 }}>{DEVICE_ICON[atFault.device_type] || '📡'}</span>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 13, fontWeight: 700, color: '#ef4444' }}>
              ⚠ PRIMARY FAULT: {atFault.device_id}
            </div>
            <div style={{ fontSize: 12, color: '#64748b', marginTop: 2 }}>
              Lowest trust score ({atFault.trust_score}/100) &bull; {errorPct(atFault.trust_score)}% error rate &bull; {atFault.severity} severity
              {injections[atFault.device_id] && ` &bull; Attack: ${injections[atFault.device_id].attack_name}`}
            </div>
          </div>
          <span style={{
            fontSize: 11, fontWeight: 700, padding: '6px 14px', borderRadius: 8,
            background: '#ef4444', color: '#fff',
          }}>
            INVESTIGATE
          </span>
        </div>
      )}

      {/* ── Device profile cards (sorted worst → best) ── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 18, marginBottom: 28 }}>
        {sorted.map((device, idx) => (
          <DeviceProfileCard
            key={device.device_id}
            device={device}
            assessment={assessments[device.device_id]}
            injection={injections[device.device_id] || null}
            rank={idx + 1}
          />
        ))}
      </div>

      {/* ── Fault attribution table ── */}
      <div className="panel">
        <div className="panel-header">
          <div>
            <div className="panel-title">Fault Attribution Table</div>
            <div className="panel-subtitle">
              All devices ranked by risk — shows which device is responsible for each anomaly signal
            </div>
          </div>
        </div>
        <div className="panel-body no-padding">
          <table className="alerts-table">
            <thead>
              <tr>
                <th>Rank</th>
                <th>Device</th>
                <th>Trust Score</th>
                <th>Error %</th>
                <th>Anomaly Ded.</th>
                <th>Drift Ded.</th>
                <th>Policy Ded.</th>
                <th>Drift Class</th>
                <th>Policy Status</th>
                <th>Attack</th>
                <th>Verdict</th>
              </tr>
            </thead>
            <tbody>
              {sorted.map((device, idx) => {
                const a         = assessments[device.device_id];
                const anomDed   = a ? a.anomaly_deduction        : device.anomaly_deduction || 0;
                const driftDed  = a ? a.drift?.penalty           : device.drift_deduction   || 0;
                const polDed    = a ? a.policy?.penalty          : device.policy_deduction  || 0;
                const driftCls  = a?.drift?.drift_class  || '—';
                const polStatus = a?.policy?.policy_status || '—';
                const inj       = injections[device.device_id];
                const severity  = device.severity || 'Low';

                return (
                  <tr key={device.device_id}>
                    <td>
                      <span style={{
                        fontWeight: 700, fontSize: 13,
                        color: idx === 0 ? '#ef4444' : idx === 1 ? '#f59e0b' : '#22c55e',
                      }}>#{idx + 1}</span>
                    </td>
                    <td>
                      <span style={{ fontWeight: 600 }}>
                        {DEVICE_ICON[device.device_type]} {device.device_id}
                      </span>
                    </td>
                    <td>
                      <span style={{ fontWeight: 700, color: SEV_COLOR[severity] }}>
                        {device.trust_score}
                      </span>
                    </td>
                    <td>
                      <span style={{
                        fontWeight: 700,
                        color: parseFloat(errorPct(device.trust_score)) > 40 ? '#ef4444'
                             : parseFloat(errorPct(device.trust_score)) > 15 ? '#f59e0b' : '#22c55e',
                      }}>
                        {errorPct(device.trust_score)}%
                      </span>
                    </td>
                    <td style={{ color: anomDed > 0 ? '#ef4444' : '#94a3b8', fontWeight: 600 }}>
                      {anomDed > 0 ? `-${parseFloat(anomDed).toFixed(1)}` : '—'}
                    </td>
                    <td style={{ color: driftDed > 0 ? '#f59e0b' : '#94a3b8', fontWeight: 600 }}>
                      {driftDed > 0 ? `-${driftDed}` : '—'}
                    </td>
                    <td style={{ color: polDed > 0 ? '#8b5cf6' : '#94a3b8', fontWeight: 600 }}>
                      {polDed > 0 ? `-${polDed}` : '—'}
                    </td>
                    <td>
                      <span style={{
                        fontSize: 10, fontWeight: 600, padding: '2px 7px', borderRadius: 5,
                        background: driftCls === 'DRIFT_STRONG' ? '#fef2f2'
                                  : driftCls === 'DRIFT_MILD'   ? '#fffbeb' : '#f0fdf4',
                        color: driftCls === 'DRIFT_STRONG' ? '#ef4444'
                             : driftCls === 'DRIFT_MILD'   ? '#f59e0b' : '#22c55e',
                      }}>
                        {driftCls.replace('DRIFT_', '')}
                      </span>
                    </td>
                    <td>
                      <span style={{
                        fontSize: 10, fontWeight: 600, padding: '2px 7px', borderRadius: 5,
                        background: polStatus === 'HARD_VIOLATION' ? '#fef2f2'
                                  : polStatus === 'SOFT_DRIFT'     ? '#fffbeb' : '#f0fdf4',
                        color: polStatus === 'HARD_VIOLATION' ? '#ef4444'
                             : polStatus === 'SOFT_DRIFT'     ? '#f59e0b' : '#22c55e',
                      }}>
                        {polStatus.replace('_', ' ')}
                      </span>
                    </td>
                    <td>
                      {inj ? (
                        <span style={{
                          fontSize: 10, fontWeight: 700, padding: '2px 7px', borderRadius: 5,
                          background: '#fef2f2', color: '#ef4444',
                        }}>
                          {inj.attack_name}
                        </span>
                      ) : <span style={{ color: '#94a3b8', fontSize: 12 }}>—</span>}
                    </td>
                    <td>
                      <span className={`severity-badge ${sev(severity)}`}>{severity}</span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}

export default Profiler;

