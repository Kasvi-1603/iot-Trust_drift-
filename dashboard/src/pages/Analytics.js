import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, ReferenceLine, Legend, PieChart, Pie, Cell,
  BarChart, Bar,
} from 'recharts';

const API = 'http://localhost:8001/api';

const DEVICE_COLORS = { CCTV_01: '#3b82f6', Router_01: '#f59e0b', Access_01: '#22c55e' };
const SEV_COLORS = { Low: '#22c55e', Medium: '#f59e0b', High: '#ef4444', Critical: '#991b1b' };

function formatTime(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  return `${d.toLocaleString('en-US', { month: 'short' })} ${d.getDate()}, ${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}`;
}

function Analytics() {
  const [anomaly, setAnomaly] = useState([]);
  const [drift, setDrift] = useState([]);
  const [severity, setSeverity] = useState([]);
  
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchData() {
      try {
        const [aRes, dRes, sRes, tRes] = await Promise.all([
          axios.get(`${API}/anomaly-timeline`),
          axios.get(`${API}/drift-timeline`),
          axios.get(`${API}/severity-distribution`),
          axios.get(`${API}/trust-timeline`),
        ]);

        // Pivot anomaly data
        const anomByW = {};
        aRes.data.forEach((r) => {
          const t = formatTime(r.window);
          if (!anomByW[t]) anomByW[t] = { window: t };
          anomByW[t][r.device_id] = r.anomaly_score;
        });
        setAnomaly(Object.values(anomByW));

        // Pivot drift data
        const driftByW = {};
        dRes.data.forEach((r) => {
          const t = formatTime(r.window);
          if (!driftByW[t]) driftByW[t] = { window: t };
          driftByW[t][r.device_id] = r.drift_magnitude;
        });
        setDrift(Object.values(driftByW));

        setSeverity(sRes.data);

        // Trust deductions — aggregate deductions per window across devices
        const dedByW = {};
        tRes.data.forEach((r) => {
          const t = formatTime(r.window);
          const key = `${r.device_id}_${t}`;
          if (!dedByW[key]) dedByW[key] = { window: t, device_id: r.device_id };
        });
        // Trust timeline data available for future use
        void tRes.data;

        setLoading(false);
      } catch (err) {
        console.error(err);
        setLoading(false);
      }
    }
    fetchData();
  }, []);

  if (loading) {
    return <div className="loading-container"><div className="loading-spinner" /><div className="loading-text">Loading analytics...</div></div>;
  }

  const deviceIds = Object.keys(DEVICE_COLORS);

  return (
    <>
      <div className="page-title-section">
        <h1 className="page-title">Analytics</h1>
        <p className="page-subtitle">ML anomaly detection, behavioral drift, and trust score analysis</p>
      </div>

      <div className="two-col-grid">
        {/* Anomaly Score Timeline */}
        <div className="panel">
          <div className="panel-header">
            <div>
              <div className="panel-title">Anomaly Detection</div>
              <div className="panel-subtitle">Isolation Forest anomaly scores (0-1)</div>
            </div>
          </div>
          <div className="panel-body">
            <div className="chart-container small">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={anomaly} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
                  <XAxis dataKey="window" tick={{ fontSize: 10, fill: '#94a3b8' }} interval={Math.max(Math.floor(anomaly.length / 6), 1)} tickLine={false} />
                  <YAxis domain={[0, 1]} tick={{ fontSize: 10, fill: '#94a3b8' }} tickLine={false} width={30} />
                  <Tooltip contentStyle={{ fontSize: 12, borderRadius: 8, border: '1px solid #e2e8f0' }} />
                  <Legend verticalAlign="top" height={30} iconType="circle" wrapperStyle={{ fontSize: 11 }} />
                  <ReferenceLine y={0.5} stroke="#ef4444" strokeDasharray="4 4" strokeWidth={1} />
                  {deviceIds.map(id => (
                    <Line key={id} type="monotone" dataKey={id} name={id} stroke={DEVICE_COLORS[id]} strokeWidth={2} dot={false} />
                  ))}
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        {/* Drift Magnitude Timeline */}
        <div className="panel">
          <div className="panel-header">
            <div>
              <div className="panel-title">Behavioral Drift</div>
              <div className="panel-subtitle">Z-score drift magnitude per device</div>
            </div>
          </div>
          <div className="panel-body">
            <div className="chart-container small">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={drift} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
                  <XAxis dataKey="window" tick={{ fontSize: 10, fill: '#94a3b8' }} interval={Math.max(Math.floor(drift.length / 6), 1)} tickLine={false} />
                  <YAxis tick={{ fontSize: 10, fill: '#94a3b8' }} tickLine={false} width={30} />
                  <Tooltip contentStyle={{ fontSize: 12, borderRadius: 8, border: '1px solid #e2e8f0' }} />
                  <Legend verticalAlign="top" height={30} iconType="circle" wrapperStyle={{ fontSize: 11 }} />
                  <ReferenceLine y={1.5} stroke="#f59e0b" strokeDasharray="4 4" strokeWidth={1} />
                  <ReferenceLine y={3.0} stroke="#ef4444" strokeDasharray="4 4" strokeWidth={1} />
                  {deviceIds.map(id => (
                    <Line key={id} type="monotone" dataKey={id} name={id} stroke={DEVICE_COLORS[id]} strokeWidth={2} dot={false} />
                  ))}
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      </div>

      <div className="two-col-grid">
        {/* Severity Distribution */}
        <div className="panel">
          <div className="panel-header">
            <div>
              <div className="panel-title">Severity Distribution</div>
              <div className="panel-subtitle">Count of hourly windows by risk level</div>
            </div>
          </div>
          <div className="panel-body">
            <div className="chart-container small">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={severity}
                    dataKey="count"
                    nameKey="severity"
                    cx="50%" cy="50%"
                    innerRadius={60} outerRadius={95}
                    paddingAngle={3}
                    label={({ severity: s, count }) => `${s}: ${count}`}
                    style={{ fontSize: 12 }}
                  >
                    {severity.map((s, i) => (
                      <Cell key={i} fill={SEV_COLORS[s.severity] || '#94a3b8'} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ fontSize: 12, borderRadius: 8, border: '1px solid #e2e8f0' }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        {/* Attack Type Distribution */}
        <div className="panel">
          <div className="panel-header">
            <div>
              <div className="panel-title">Attack Type Distribution</div>
              <div className="panel-subtitle">Breakdown of detected attack categories</div>
            </div>
          </div>
          <div className="panel-body">
            <AttackChart />
          </div>
        </div>
      </div>
    </>
  );
}

function AttackChart() {
  const [data, setData] = useState([]);
  useEffect(() => {
    axios.get(`${API}/attack-distribution`).then(res => {
      setData(res.data.map(d => ({ ...d, name: d.attack_type.replace('attack_', '').replace('_', ' ').toUpperCase() })));
    }).catch(() => {});
  }, []);

  if (!data.length) return <div className="table-empty">No attack data.</div>;

  const COLORS = ['#ef4444', '#f59e0b', '#8b5cf6', '#3b82f6'];
  return (
    <div className="chart-container small">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
          <XAxis dataKey="name" tick={{ fontSize: 11, fill: '#64748b' }} tickLine={false} />
          <YAxis tick={{ fontSize: 11, fill: '#94a3b8' }} tickLine={false} width={40} />
          <Tooltip contentStyle={{ fontSize: 12, borderRadius: 8, border: '1px solid #e2e8f0' }} />
          <Bar dataKey="count" radius={[6, 6, 0, 0]}>
            {data.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

export default Analytics;

