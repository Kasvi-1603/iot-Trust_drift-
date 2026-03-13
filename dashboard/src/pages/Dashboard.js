import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, ReferenceLine, Legend,
} from 'recharts';

const API = 'http://localhost:8001/api';

const DEVICE_COLORS = {
  CCTV_01: '#3b82f6',
  Router_01: '#f59e0b',
  Access_01: '#22c55e',
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

function DeviceCard({ device, onClick }) {
  const sev = severityClass(device.severity);
  return (
    <div className={`device-card severity-${sev}`} onClick={onClick}>
      <div className="device-card-header">
        <div>
          <div className="device-card-name">{device.device_id}</div>
          <div className="device-card-type">{device.description || device.device_type}</div>
        </div>
        <span className={`severity-badge ${sev}`}>{device.severity}</span>
      </div>
      <div className="device-card-score">
        <div className="device-card-score-label">Trust Score</div>
        <div className={`device-card-score-value ${sev}`}>{device.trust_score}</div>
      </div>
      <div className="trust-bar-container">
        <div className={`trust-bar-fill ${sev}`} style={{ width: `${device.trust_score}%` }} />
      </div>
      <span className="device-card-action">
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
  const navigate = useNavigate();

  useEffect(() => {
    async function fetchData() {
      try {
        const [devRes, tlRes, alRes, stRes] = await Promise.all([
          axios.get(`${API}/devices`),
          axios.get(`${API}/trust-timeline`),
          axios.get(`${API}/alerts`),
          axios.get(`${API}/stats`),
        ]);
        setDevices(devRes.data);
        setStats(stRes.data);

        const byWindow = {};
        tlRes.data.forEach((row) => {
          const t = formatTime(row.window);
          if (!byWindow[t]) byWindow[t] = { window: t };
          byWindow[t][row.device_id] = row.trust_score;
        });
        setTimeline(Object.values(byWindow));
        setAlerts(alRes.data.slice(0, 15));
        setLoading(false);
      } catch (err) {
        console.error(err);
        setError('Failed to connect to API. Make sure the FastAPI server is running on port 8001.');
        setLoading(false);
      }
    }
    fetchData();
  }, []);

  if (loading) {
    return <div className="loading-container"><div className="loading-spinner" /><div className="loading-text">Loading dashboard...</div></div>;
  }
  if (error) {
    return <div className="error-container"><div>{error}</div></div>;
  }

  const deviceIds = devices.map(d => d.device_id);

  return (
    <>
      <div className="page-title-section">
        <h1 className="page-title">Security Overview</h1>
        <p className="page-subtitle">Real-time trust monitoring across all IoT devices</p>
      </div>

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

      {/* Device Cards */}
      <div className="device-cards-grid">
        {devices.map((d) => (
          <DeviceCard key={d.device_id} device={d} onClick={() => navigate(`/device/${d.device_id}`)} />
        ))}
      </div>

      {/* Trust Timeline */}
      <div className="panel">
        <div className="panel-header">
          <div>
            <div className="panel-title">Trust Score Timeline</div>
            <div className="panel-subtitle">All devices — hourly smoothed trust score</div>
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
                  <tr key={i} onClick={() => navigate(`/device/${a.device_id}`)} style={{ cursor: 'pointer' }}>
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
