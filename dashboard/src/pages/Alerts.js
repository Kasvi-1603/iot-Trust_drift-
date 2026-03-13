import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

const API = 'http://localhost:8001/api';

function severityClass(severity) {
  return (severity || 'low').toLowerCase();
}

function formatTime(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  return `${d.toLocaleString('en-US', { month: 'short' })} ${d.getDate()}, ${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}`;
}

function Alerts() {
  const [allData, setAllData] = useState([]);
  const [filter, setFilter] = useState('all');
  const [deviceFilter, setDeviceFilter] = useState('all');
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    axios.get(`${API}/all-evidence`).then(res => {
      setAllData(res.data);
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

  return (
    <>
      <div className="page-title-section">
        <h1 className="page-title">Alerts & Evidence</h1>
        <p className="page-subtitle">All device assessments with explainable AI evidence</p>
      </div>

      {/* Summary Stats */}
      <div className="stats-bar">
        <div className="stat-card">
          <div className="stat-card-label">Total Assessments</div>
          <div className="stat-card-value">{allData.length}</div>
        </div>
        <div className="stat-card">
          <div className="stat-card-label">Critical</div>
          <div className="stat-card-value red">{severityCounts.critical}</div>
        </div>
        <div className="stat-card">
          <div className="stat-card-label">High</div>
          <div className="stat-card-value red">{severityCounts.high}</div>
        </div>
        <div className="stat-card">
          <div className="stat-card-label">Medium</div>
          <div className="stat-card-value yellow">{severityCounts.medium}</div>
        </div>
        <div className="stat-card">
          <div className="stat-card-label">Low</div>
          <div className="stat-card-value green">{severityCounts.low}</div>
        </div>
      </div>

      {/* Filters */}
      <div className="filter-bar">
        <span style={{ fontSize: 12, color: '#64748b', marginRight: 4 }}>Severity:</span>
        {['all', 'critical', 'high', 'medium', 'low'].map(f => (
          <button key={f} className={`filter-btn ${filter === f ? 'active' : ''}`} onClick={() => setFilter(f)}>
            {f === 'all' ? 'All' : f.charAt(0).toUpperCase() + f.slice(1)}
          </button>
        ))}
        <span style={{ fontSize: 12, color: '#64748b', marginLeft: 12, marginRight: 4 }}>Device:</span>
        <button className={`filter-btn ${deviceFilter === 'all' ? 'active' : ''}`} onClick={() => setDeviceFilter('all')}>All</button>
        {devices.map(d => (
          <button key={d} className={`filter-btn ${deviceFilter === d ? 'active' : ''}`} onClick={() => setDeviceFilter(d)}>{d}</button>
        ))}
      </div>

      {/* Table */}
      <div className="panel">
        <div className="panel-body no-padding">
          {filtered.length === 0 ? (
            <div className="table-empty">No matching alerts.</div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table className="alerts-table">
                <thead>
                  <tr>
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
                  {filtered.map((a, i) => (
                    <tr key={i} onClick={() => navigate(`/device/${a.device_id}`)} style={{ cursor: 'pointer' }}>
                      <td className="table-cell-time">{formatTime(a.window)}</td>
                      <td className="table-cell-device">{a.device_id}</td>
                      <td><span className={`severity-badge ${severityClass(a.severity)}`}>{a.severity}</span></td>
                      <td style={{ fontVariantNumeric: 'tabular-nums', fontWeight: 500 }}>{a.trust_score}</td>
                      <td className="table-cell-summary" style={{ fontSize: 12 }}>{a.evidence}</td>
                      <td style={{ fontSize: 12, color: '#64748b', maxWidth: 200 }}>{a.feature_attribution}</td>
                      <td className="table-cell-action">{a.recommended_action}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </>
  );
}

export default Alerts;

