import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Legend, PieChart, Pie, Cell,
  BarChart, Bar,
} from 'recharts';

const API = 'http://localhost:8002/api';
const DEVICE_COLORS = { CCTV_01: '#3b82f6', Router_01: '#f59e0b', Access_01: '#22c55e' };
const PIE_COLORS = ['#3b82f6', '#22c55e', '#f59e0b', '#ef4444', '#8b5cf6', '#06b6d4'];

function formatTime(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  return `${d.toLocaleString('en-US', { month: 'short' })} ${d.getDate()}, ${d.getHours().toString().padStart(2, '0')}:00`;
}

function formatBytes(b) {
  if (b >= 1000000) return `${(b / 1000000).toFixed(1)}MB`;
  if (b >= 1000) return `${(b / 1000).toFixed(0)}KB`;
  return `${b}B`;
}

function Network() {
  const [traffic, setTraffic] = useState([]);
  const [protocols, setProtocols] = useState([]);
  const [ports, setPorts] = useState([]);
  const [destinations, setDestinations] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchData() {
      try {
        const [tRes, pRes, portRes, dstRes] = await Promise.all([
          axios.get(`${API}/network-traffic`),
          axios.get(`${API}/protocol-distribution`),
          axios.get(`${API}/port-distribution`),
          axios.get(`${API}/top-destinations`),
        ]);

        // Pivot traffic by window
        const byW = {};
        tRes.data.forEach((r) => {
          const t = formatTime(r.window);
          if (!byW[t]) byW[t] = { window: t };
          byW[t][r.device_id] = r.total_bytes_out;
        });
        setTraffic(Object.values(byW));
        setProtocols(pRes.data);
        setPorts(portRes.data.map(p => ({ ...p, label: `Port ${p.port}` })));
        setDestinations(dstRes.data);
        setLoading(false);
      } catch (err) {
        console.error(err);
        setLoading(false);
      }
    }
    fetchData();
  }, []);

  if (loading) {
    return <div className="loading-container"><div className="loading-spinner" /><div className="loading-text">Loading network data...</div></div>;
  }

  const deviceIds = Object.keys(DEVICE_COLORS);

  return (
    <>
      <div className="page-title-section">
        <h1 className="page-title">Network Traffic</h1>
        <p className="page-subtitle">Traffic volume, protocol usage, and destination analysis</p>
      </div>

      {/* Traffic Volume Timeline */}
      <div className="panel">
        <div className="panel-header">
          <div>
            <div className="panel-title">Traffic Volume Over Time</div>
            <div className="panel-subtitle">Total bytes out per device per hour</div>
          </div>
        </div>
        <div className="panel-body">
          <div className="chart-container">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={traffic} margin={{ top: 10, right: 20, left: 10, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
                <XAxis dataKey="window" tick={{ fontSize: 10, fill: '#94a3b8' }} interval={Math.max(Math.floor(traffic.length / 8), 1)} tickLine={false} />
                <YAxis tick={{ fontSize: 10, fill: '#94a3b8' }} tickLine={false} tickFormatter={formatBytes} width={55} />
                <Tooltip contentStyle={{ fontSize: 12, borderRadius: 8, border: '1px solid #e2e8f0' }} formatter={(val) => formatBytes(val)} />
                <Legend verticalAlign="top" height={36} iconType="circle" wrapperStyle={{ fontSize: 11 }} />
                {deviceIds.map(id => (
                  <Line key={id} type="monotone" dataKey={id} name={id} stroke={DEVICE_COLORS[id]} strokeWidth={2} dot={false} />
                ))}
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="two-col-grid">
        {/* Protocol Distribution */}
        <div className="panel">
          <div className="panel-header">
            <div>
              <div className="panel-title">Protocol Distribution</div>
              <div className="panel-subtitle">Flow count by network protocol</div>
            </div>
          </div>
          <div className="panel-body">
            <div className="chart-container small">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={protocols} dataKey="count" nameKey="protocol"
                    cx="50%" cy="50%" innerRadius={55} outerRadius={90}
                    paddingAngle={3}
                    label={({ protocol, count }) => `${protocol}: ${count}`}
                    style={{ fontSize: 12 }}
                  >
                    {protocols.map((_, i) => <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />)}
                  </Pie>
                  <Tooltip contentStyle={{ fontSize: 12, borderRadius: 8, border: '1px solid #e2e8f0' }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        {/* Port Distribution */}
        <div className="panel">
          <div className="panel-header">
            <div>
              <div className="panel-title">Port Usage</div>
              <div className="panel-subtitle">Top destination ports by flow count</div>
            </div>
          </div>
          <div className="panel-body">
            <div className="chart-container small">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={ports} layout="vertical" margin={{ top: 10, right: 20, left: 10, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
                  <XAxis type="number" tick={{ fontSize: 10, fill: '#94a3b8' }} tickLine={false} />
                  <YAxis type="category" dataKey="label" tick={{ fontSize: 11, fill: '#64748b' }} tickLine={false} width={70} />
                  <Tooltip contentStyle={{ fontSize: 12, borderRadius: 8, border: '1px solid #e2e8f0' }} />
                  <Bar dataKey="count" fill="#3b82f6" radius={[0, 6, 6, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      </div>

      {/* Top Destinations */}
      <div className="panel">
        <div className="panel-header">
          <div>
            <div className="panel-title">Top Destination IPs</div>
            <div className="panel-subtitle">Most contacted IP addresses by flow count</div>
          </div>
        </div>
        <div className="panel-body no-padding">
          <table className="data-table">
            <thead>
              <tr>
                <th>Destination IP</th>
                <th>Flow Count</th>
                <th>Type</th>
              </tr>
            </thead>
            <tbody>
              {destinations.map((d, i) => (
                <tr key={i}>
                  <td style={{ fontFamily: 'monospace', fontSize: 13 }}>{d.dst_ip}</td>
                  <td style={{ fontVariantNumeric: 'tabular-nums' }}>{d.count.toLocaleString()}</td>
                  <td>
                    <span className={`severity-badge ${d.is_internal ? 'low' : 'high'}`}>
                      {d.is_internal ? 'Internal' : 'External'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}

export default Network;

