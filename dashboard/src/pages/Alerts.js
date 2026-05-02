import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

const API = 'http://localhost:8002/api';

function severityClass(severity) {
  return (severity || 'low').toLowerCase();
}

function formatTime(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  return `${d.toLocaleString('en-US', { month: 'short' })} ${d.getDate()}, ${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}`;
}

function severityIcon(sev) {
  switch (sev) {
    case 'critical': return '🚨';
    case 'high': return '🔴';
    case 'medium': return '🟡';
    case 'low': return '🟢';
    default: return '⚪';
  }
}

function SeverityStatCard({ label, count, color, bgColor, borderColor, icon, isActive, onClick }) {
  return (
    <div
      className={`alert-stat-card ${isActive ? 'alert-stat-card-active' : ''}`}
      style={{
        '--card-color': color,
        '--card-bg': bgColor,
        '--card-border': borderColor,
        cursor: 'pointer',
      }}
      onClick={onClick}
    >
      <div className="alert-stat-icon">{icon}</div>
      <div className="alert-stat-count" style={{ color }}>{count}</div>
      <div className="alert-stat-label">{label}</div>
      {isActive && <div className="alert-stat-indicator" style={{ background: color }} />}
    </div>
  );
}

function AlertDetailModal({ alert, onClose }) {
  if (!alert) return null;
  const sev = severityClass(alert.severity);
  
  return (
    <div className="alert-modal-overlay" onClick={onClose}>
      <div className="alert-modal" onClick={e => e.stopPropagation()}>
        <div className={`alert-modal-header alert-modal-header-${sev}`}>
          <div className="alert-modal-header-left">
            <span className="alert-modal-icon">{severityIcon(sev)}</span>
            <div>
              <div className="alert-modal-title">{alert.device_id}</div>
              <div className="alert-modal-subtitle">{alert.device_type} — {formatTime(alert.window)}</div>
            </div>
          </div>
          <div className="alert-modal-header-right">
            <span className={`severity-badge ${sev}`} style={{ fontSize: 13, padding: '5px 14px' }}>
              {alert.severity}
            </span>
            <button className="alert-modal-close" onClick={onClose}>✕</button>
          </div>
        </div>

        <div className="alert-modal-body">
          {/* Trust Score Display */}
          <div className="alert-modal-trust">
            <div className="alert-modal-trust-label">Trust Score</div>
            <div className={`alert-modal-trust-value alert-modal-trust-${sev}`}>
              {alert.trust_score}
            </div>
            <div className="alert-modal-trust-bar">
              <div
                className={`alert-modal-trust-bar-fill alert-modal-trust-bar-${sev}`}
                style={{ width: `${alert.trust_score}%` }}
              />
            </div>
          </div>

          {/* Evidence Section */}
          <div className="alert-modal-section">
            <div className="alert-modal-section-title">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/>
              </svg>
              Risk Summary
            </div>
            <div className="alert-modal-section-content alert-modal-risk-text">
              {alert.risk_summary || 'No risk summary available'}
            </div>
          </div>

          <div className="alert-modal-section">
            <div className="alert-modal-section-title">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M16 13H8"/><path d="M16 17H8"/><path d="M10 9H8"/>
              </svg>
              Evidence
            </div>
            <div className="alert-modal-section-content">
              {alert.evidence || 'No evidence details available'}
            </div>
          </div>

          <div className="alert-modal-section">
            <div className="alert-modal-section-title">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              </svg>
              Feature Attribution
            </div>
            <div className="alert-modal-section-content" style={{ fontFamily: 'monospace', fontSize: 12 }}>
              {alert.feature_attribution || 'N/A'}
            </div>
          </div>

          <div className={`alert-modal-action alert-modal-action-${sev}`}>
            <div className="alert-modal-action-label">Recommended Action</div>
            <div className="alert-modal-action-text">
              {alert.recommended_action || 'Monitor and investigate'}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function Alerts() {
  const [allData, setAllData] = useState([]);
  const [activeInjections, setActiveInjections] = useState({});
  const [filter, setFilter] = useState('all');
  const [deviceFilter, setDeviceFilter] = useState('all');
  const [loading, setLoading] = useState(true);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    Promise.all([
      axios.get(`${API}/all-evidence`),
      axios.get(`${API}/injection-status`),
    ]).then(([evRes, injRes]) => {
      setAllData(evRes.data);
      setActiveInjections(injRes.data.active_injections || {});
      setLoading(false);
    }).catch(() => setLoading(false));
  }, []);

  if (loading) {
    return <div className="loading-container"><div className="loading-spinner" /><div className="loading-text">Loading alerts...</div></div>;
  }

  const filtered = allData.filter(a => {
    if (filter !== 'all' && severityClass(a.severity) !== filter) return false;
    if (deviceFilter !== 'all' && a.device_id !== deviceFilter) return false;
    return true;
  });

  const devices = [...new Set(allData.map(a => a.device_id))];
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  allData.forEach(a => { const s = severityClass(a.severity); if (severityCounts[s] !== undefined) severityCounts[s]++; });

  const hasActiveAttack = Object.keys(activeInjections).length > 0;
  const criticalAndHigh = severityCounts.critical + severityCounts.high;

  return (
    <>
      <div className="page-title-section">
        <h1 className="page-title">Alerts & Evidence</h1>
        <p className="page-subtitle">All device assessments with explainable AI evidence</p>
      </div>

      {/* Active Attack Warning Banner */}
      {hasActiveAttack && (
        <div className="alerts-attack-banner">
          <div className="alerts-attack-banner-glow" />
          <div className="alerts-attack-banner-content">
            <div className="alerts-attack-banner-left">
              <span className="alerts-attack-banner-icon">🚨</span>
              <div>
                <div className="alerts-attack-banner-title">ACTIVE ATTACK DETECTED</div>
                <div className="alerts-attack-banner-desc">
                  {Object.entries(activeInjections).map(([devId, info]) =>
                    `${devId}: ${info.attack_name} — ${info.mitre} — ${info.attack_flows} malicious flows injected`
                  ).join(' | ')}
                </div>
              </div>
            </div>
            <div className="alerts-attack-banner-badge">
              <span className="attack-pulse-dot" />
              LIVE THREAT
            </div>
          </div>
        </div>
      )}

      {/* Summary Stats with Interactive Cards */}
      <div className="alert-stats-grid">
        <SeverityStatCard
          label="Total" count={allData.length} color="#3b82f6" bgColor="#eff6ff"
          borderColor="#bfdbfe" icon="📊" isActive={filter === 'all'} onClick={() => setFilter('all')}
        />
        <SeverityStatCard
          label="Critical" count={severityCounts.critical} color="#991b1b" bgColor="#fef2f2"
          borderColor="#fecaca" icon="🚨" isActive={filter === 'critical'} onClick={() => setFilter('critical')}
        />
        <SeverityStatCard
          label="High" count={severityCounts.high} color="#dc2626" bgColor="#fef2f2"
          borderColor="#fecaca" icon="🔴" isActive={filter === 'high'} onClick={() => setFilter('high')}
        />
        <SeverityStatCard
          label="Medium" count={severityCounts.medium} color="#f59e0b" bgColor="#fffbeb"
          borderColor="#fde68a" icon="🟡" isActive={filter === 'medium'} onClick={() => setFilter('medium')}
        />
        <SeverityStatCard
          label="Low" count={severityCounts.low} color="#22c55e" bgColor="#f0fdf4"
          borderColor="#bbf7d0" icon="🟢" isActive={filter === 'low'} onClick={() => setFilter('low')}
        />
      </div>

      {/* Threat Level Indicator */}
      {criticalAndHigh > 0 && (
        <div className="threat-level-bar">
          <div className="threat-level-label">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
              <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
            </svg>
            Threat Level
          </div>
          <div className="threat-level-track">
            <div
              className="threat-level-fill"
              style={{
                width: `${Math.min((criticalAndHigh / Math.max(allData.length, 1)) * 100 * 3, 100)}%`,
                background: criticalAndHigh > 10
                  ? 'linear-gradient(90deg, #f59e0b, #ef4444, #991b1b)'
                  : criticalAndHigh > 5
                    ? 'linear-gradient(90deg, #f59e0b, #ef4444)'
                    : 'linear-gradient(90deg, #22c55e, #f59e0b)',
              }}
            />
          </div>
          <div className="threat-level-value">
            {criticalAndHigh > 10 ? 'CRITICAL' : criticalAndHigh > 5 ? 'HIGH' : criticalAndHigh > 0 ? 'ELEVATED' : 'NORMAL'}
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="filter-bar">
        <span style={{ fontSize: 12, color: '#64748b', marginRight: 4 }}>Device:</span>
        <button className={`filter-btn ${deviceFilter === 'all' ? 'active' : ''}`} onClick={() => setDeviceFilter('all')}>All</button>
        {devices.map(d => (
          <button key={d} className={`filter-btn ${deviceFilter === d ? 'active' : ''}`} onClick={() => setDeviceFilter(d)}>
            {d}
            {activeInjections[d] && <span style={{ marginLeft: 4, color: '#ef4444' }}>⚡</span>}
          </button>
        ))}
      </div>

      {/* Table */}
      <div className="panel">
        <div className="panel-header">
          <div>
            <div className="panel-title">
              {filter === 'all' ? 'All Assessments' : `${filter.charAt(0).toUpperCase() + filter.slice(1)} Severity Alerts`}
              <span style={{ marginLeft: 8, fontSize: 12, color: '#94a3b8', fontWeight: 400 }}>
                ({filtered.length} records)
              </span>
            </div>
          </div>
        </div>
        <div className="panel-body no-padding">
          {filtered.length === 0 ? (
            <div className="table-empty">No matching alerts.</div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table className="alerts-table">
                <thead>
                  <tr>
                    <th></th>
                    <th>Time</th>
                    <th>Device</th>
                    <th>Severity</th>
                    <th>Trust</th>
                    <th>Evidence</th>
                    <th>Attribution</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((a, i) => {
                    const sev = severityClass(a.severity);
                    const isAttacked = !!activeInjections[a.device_id];
                    return (
                      <tr
                        key={i}
                        className={`alert-row alert-row-${sev} ${isAttacked ? 'alert-row-attacked' : ''}`}
                        style={{ cursor: 'pointer' }}
                      >
                        <td style={{ width: 30, textAlign: 'center', fontSize: 16, padding: '12px 8px' }}>
                          {severityIcon(sev)}
                        </td>
                        <td className="table-cell-time" onClick={() => navigate(`/device/${a.device_id}`)}>
                          {formatTime(a.window)}
                        </td>
                        <td className="table-cell-device" onClick={() => navigate(`/device/${a.device_id}`)}>
                          <span>{a.device_id}</span>
                          {isAttacked && (
                            <span className="alert-attack-tag">⚡ ATTACK</span>
                          )}
                        </td>
                        <td onClick={() => setSelectedAlert(a)}>
                          <span className={`severity-badge ${sev}`}>{a.severity}</span>
                        </td>
                        <td onClick={() => setSelectedAlert(a)} style={{ fontVariantNumeric: 'tabular-nums', fontWeight: 600 }}>
                          <span className={`alert-trust-value alert-trust-${sev}`}>{a.trust_score}</span>
                        </td>
                        <td className="table-cell-summary" style={{ fontSize: 12 }} onClick={() => setSelectedAlert(a)}>
                          {a.evidence}
                        </td>
                        <td style={{ fontSize: 12, color: '#64748b', maxWidth: 200 }} onClick={() => setSelectedAlert(a)}>
                          {a.feature_attribution}
                        </td>
                        <td className="table-cell-action" onClick={() => setSelectedAlert(a)}>
                          {a.recommended_action}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* Alert Detail Modal */}
      <AlertDetailModal alert={selectedAlert} onClose={() => setSelectedAlert(null)} />
    </>
  );
}

export default Alerts;
