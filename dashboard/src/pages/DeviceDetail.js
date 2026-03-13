import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import axios from 'axios';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, ReferenceLine, BarChart, Bar, Legend,
} from 'recharts';

const API = 'http://localhost:8001/api';

function severityClass(s) { return (s || 'low').toLowerCase(); }

function formatTime(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  return `${d.toLocaleString('en-US', { month: 'short' })} ${d.getDate()}, ${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}`;
}

function DeviceDetail() {
  const { deviceId } = useParams();
  const [device, setDevice] = useState(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    axios.get(`${API}/device/${deviceId}`).then(res => {
      setDevice(res.data);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, [deviceId]);

  if (loading) {
    return <div className="loading-container"><div className="loading-spinner" /><div className="loading-text">Loading device...</div></div>;
  }

  if (!device || !device.timeline || device.timeline.length === 0) {
    return (
      <div className="error-container">
        <div>Device not found: {deviceId}</div>
        <button className="detail-back" onClick={() => navigate('/')}>Back to Dashboard</button>
      </div>
    );
  }

  const chartData = device.timeline.map(t => ({
    window: formatTime(t.window),
    trust: t.trust_score,
    anomaly: t.anomaly_deduction,
    drift: t.drift_deduction,
    policy: t.policy_deduction,
  }));

  const sev = severityClass(device.current_severity);

  return (
    <>
      <button className="detail-back" onClick={() => navigate('/')}>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M19 12H5M12 19l-7-7 7-7" />
        </svg>
        Back to Dashboard
      </button>

      <div className="detail-device-header">
        <div className="detail-device-info">
          <h2>{device.device_id}</h2>
          <p>{device.description || device.device_type}</p>
        </div>
        <div className="detail-trust-display">
          <div className={`detail-trust-value ${sev}`}>{device.current_trust}</div>
          <div className="detail-trust-label">
            <span className={`severity-badge ${sev}`}>{device.current_severity}</span>
          </div>
        </div>
      </div>

      {/* Trust Timeline */}
      <div className="panel">
        <div className="panel-header">
          <div>
            <div className="panel-title">Trust Score Over Time</div>
            <div className="panel-subtitle">Smoothed trust score with risk thresholds</div>
          </div>
        </div>
        <div className="panel-body">
          <div className="chart-container">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={chartData} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
                <XAxis dataKey="window" tick={{ fontSize: 10, fill: '#94a3b8' }} interval={Math.max(Math.floor(chartData.length / 8), 1)} tickLine={false} />
                <YAxis domain={[0, 100]} tick={{ fontSize: 11, fill: '#94a3b8' }} tickLine={false} width={35} />
                <Tooltip contentStyle={{ fontSize: 12, borderRadius: 8, border: '1px solid #e2e8f0' }} />
                <ReferenceLine y={30} stroke="#ef4444" strokeDasharray="4 4" strokeWidth={1} />
                <ReferenceLine y={60} stroke="#f59e0b" strokeDasharray="4 4" strokeWidth={1} />
                <Line type="monotone" dataKey="trust" name="Trust Score" stroke="#3b82f6" strokeWidth={2.5} dot={false} activeDot={{ r: 4, strokeWidth: 0 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Deduction Breakdown */}
      <div className="panel">
        <div className="panel-header">
          <div>
            <div className="panel-title">Trust Deduction Breakdown</div>
            <div className="panel-subtitle">Anomaly, drift, and policy penalties per window</div>
          </div>
        </div>
        <div className="panel-body">
          <div className="chart-container">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
                <XAxis dataKey="window" tick={{ fontSize: 10, fill: '#94a3b8' }} interval={Math.max(Math.floor(chartData.length / 8), 1)} tickLine={false} />
                <YAxis tick={{ fontSize: 11, fill: '#94a3b8' }} tickLine={false} width={35} />
                <Tooltip contentStyle={{ fontSize: 12, borderRadius: 8, border: '1px solid #e2e8f0' }} />
                <Legend verticalAlign="top" height={36} iconType="circle" wrapperStyle={{ fontSize: 11 }} />
                <Bar dataKey="anomaly" name="Anomaly" stackId="a" fill="#ef4444" radius={[0, 0, 0, 0]} />
                <Bar dataKey="drift" name="Drift" stackId="a" fill="#f59e0b" />
                <Bar dataKey="policy" name="Policy" stackId="a" fill="#8b5cf6" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Evidence Log */}
      <div className="panel">
        <div className="panel-header">
          <div>
            <div className="panel-title">Evidence Log</div>
            <div className="panel-subtitle">Explainable AI — generated evidence per window</div>
          </div>
        </div>
        <div className="panel-body no-padding">
          <div style={{ overflowX: 'auto' }}>
            <table className="evidence-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Severity</th>
                  <th>Trust</th>
                  <th>Status</th>
                  <th>Evidence</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {device.evidence.map((e, i) => (
                  <tr key={i}>
                    <td className="table-cell-time">{formatTime(e.window)}</td>
                    <td><span className={`severity-badge ${severityClass(e.severity)}`}>{e.severity}</span></td>
                    <td style={{ fontVariantNumeric: 'tabular-nums', fontWeight: 500 }}>{e.trust_score}</td>
                    <td>
                      <span className={`severity-badge ${severityClass(e.drift_class === 'DRIFT_NONE' && e.policy_status === 'COMPLIANT' ? 'Low' : e.policy_status === 'HARD_VIOLATION' ? 'High' : 'Medium')}`}>
                        {e.policy_status.replace('_', ' ')}
                      </span>
                    </td>
                    <td className="table-cell-summary" style={{ fontSize: 12 }}>{e.evidence}</td>
                    <td className="table-cell-action">{e.recommended_action}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </>
  );
}

export default DeviceDetail;
