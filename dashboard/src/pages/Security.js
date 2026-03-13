import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Cell, PieChart, Pie, Legend,
} from 'recharts';

const API = 'http://localhost:8001/api';

const STATUS_COLORS = {
  COMPLIANT: '#22c55e',
  SOFT_DRIFT: '#f59e0b',
  HARD_VIOLATION: '#ef4444',
};

function severityClass(status) {
  if (status === 'HARD_VIOLATION') return 'high';
  if (status === 'SOFT_DRIFT') return 'medium';
  return 'low';
}

function formatTime(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  return `${d.toLocaleString('en-US', { month: 'short' })} ${d.getDate()}, ${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}`;
}

function Security() {
  const [summary, setSummary] = useState([]);
  const [results, setResults] = useState([]);
  const [filter, setFilter] = useState('all');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchData() {
      try {
        const [sRes, rRes] = await Promise.all([
          axios.get(`${API}/policy-summary`),
          axios.get(`${API}/policy-results`),
        ]);
        setSummary(sRes.data);
        setResults(rRes.data);
        setLoading(false);
      } catch (err) {
        console.error(err);
        setLoading(false);
      }
    }
    fetchData();
  }, []);

  if (loading) {
    return <div className="loading-container"><div className="loading-spinner" /><div className="loading-text">Loading security data...</div></div>;
  }

  // Aggregate status counts for pie chart
  const statusCounts = {};
  results.forEach(r => {
    statusCounts[r.policy_status] = (statusCounts[r.policy_status] || 0) + 1;
  });
  const pieData = Object.entries(statusCounts).map(([status, count]) => ({ status, count }));

  // Filter violations list
  const violations = results.filter(r => {
    if (filter === 'all') return r.policy_status !== 'COMPLIANT';
    return r.policy_status === filter;
  });

  // Compliance rate chart data
  const complianceChartData = summary.map(s => ({
    device: s.device_id,
    compliance: s.compliance_rate,
    violations: 100 - s.compliance_rate,
  }));

  return (
    <>
      <div className="page-title-section">
        <h1 className="page-title">Security Policy</h1>
        <p className="page-subtitle">Policy compliance monitoring and violation tracking</p>
      </div>

      {/* Compliance Cards */}
      <div className="stats-bar">
        {summary.map((s) => {
          const rateClass = s.compliance_rate >= 90 ? 'good' : s.compliance_rate >= 70 ? 'warn' : 'bad';
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
        {/* Compliance by Device */}
        <div className="panel">
          <div className="panel-header">
            <div>
              <div className="panel-title">Compliance Rate by Device</div>
              <div className="panel-subtitle">Percentage of compliant hourly windows</div>
            </div>
          </div>
          <div className="panel-body">
            <div className="chart-container small">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={complianceChartData} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
                  <XAxis dataKey="device" tick={{ fontSize: 11, fill: '#64748b' }} tickLine={false} />
                  <YAxis domain={[0, 100]} tick={{ fontSize: 11, fill: '#94a3b8' }} tickLine={false} width={35} tickFormatter={v => `${v}%`} />
                  <Tooltip contentStyle={{ fontSize: 12, borderRadius: 8, border: '1px solid #e2e8f0' }} formatter={(val) => `${val}%`} />
                  <Bar dataKey="compliance" name="Compliant" radius={[6, 6, 0, 0]}>
                    {complianceChartData.map((d, i) => (
                      <Cell key={i} fill={d.compliance >= 90 ? '#22c55e' : d.compliance >= 70 ? '#f59e0b' : '#ef4444'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        {/* Status Distribution Pie */}
        <div className="panel">
          <div className="panel-header">
            <div>
              <div className="panel-title">Policy Status Distribution</div>
              <div className="panel-subtitle">Overall policy evaluation results</div>
            </div>
          </div>
          <div className="panel-body">
            <div className="chart-container small">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={pieData} dataKey="count" nameKey="status"
                    cx="50%" cy="50%" innerRadius={55} outerRadius={90}
                    paddingAngle={3}
                    label={({ status, count }) => `${status.replace('_', ' ')}: ${count}`}
                    style={{ fontSize: 11 }}
                  >
                    {pieData.map((p, i) => (
                      <Cell key={i} fill={STATUS_COLORS[p.status] || '#94a3b8'} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ fontSize: 12, borderRadius: 8, border: '1px solid #e2e8f0' }} />
                  <Legend verticalAlign="bottom" height={30} wrapperStyle={{ fontSize: 11 }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      </div>

      {/* Violations Table */}
      <div className="panel">
        <div className="panel-header">
          <div>
            <div className="panel-title">Policy Violations Log</div>
            <div className="panel-subtitle">All non-compliant evaluations with violation details</div>
          </div>
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
          {violations.length === 0 ? (
            <div className="table-empty">No violations found for the selected filter.</div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Device</th>
                    <th>Type</th>
                    <th>Status</th>
                    <th>Violations</th>
                    <th>Penalty</th>
                  </tr>
                </thead>
                <tbody>
                  {violations.map((v, i) => (
                    <tr key={i}>
                      <td className="table-cell-time">{formatTime(v.window)}</td>
                      <td className="table-cell-device">{v.device_id}</td>
                      <td style={{ fontSize: 12, color: '#64748b' }}>{v.device_type}</td>
                      <td>
                        <span className={`severity-badge ${severityClass(v.policy_status)}`}>
                          {v.policy_status.replace('_', ' ')}
                        </span>
                      </td>
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
  );
}

export default Security;

