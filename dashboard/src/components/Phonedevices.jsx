// dashboard/src/components/PhoneDevices.jsx
import { useEffect, useState, useRef } from 'react';

const ROLE_ICONS = { cctv: '📹', access_controller: '🔑', router: '🌐' };
const RISK_COLORS = {
  LOW:      { bg: '#d1fae5', border: '#10b981', text: '#065f46' },
  MEDIUM:   { bg: '#fef3c7', border: '#f59e0b', text: '#92400e' },
  HIGH:     { bg: '#fee2e2', border: '#ef4444', text: '#991b1b' },
  CRITICAL: { bg: '#fce7f3', border: '#ec4899', text: '#831843' },
};

export default function PhoneDevices({ backendUrl = 'http://localhost:5000' }) {
  const [devices, setDevices] = useState({});
  const [wsStatus, setWsStatus] = useState('connecting');
  const wsRef = useRef(null);

  // Initial load
  useEffect(() => {
    fetch(`${backendUrl}/api/devices`)
      .then(r => r.json())
      .then(list => {
        const map = {};
        list.forEach(d => { map[d.device_id] = d; });
        setDevices(map);
      }).catch(() => {});
  }, [backendUrl]);

  // WebSocket live updates
  useEffect(() => {
    const wsUrl = backendUrl.replace('http', 'ws');
    const connect = () => {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => setWsStatus('connected');
      ws.onclose = () => {
        setWsStatus('reconnecting');
        setTimeout(connect, 3000);
      };
      ws.onerror = () => setWsStatus('error');
      ws.onmessage = (e) => {
        const msg = JSON.parse(e.data);
        if (msg.type === 'DEVICE_UPDATE') {
          setDevices(prev => ({ ...prev, [msg.data.device_id]: msg.data }));
        }
      };
    };
    connect();
    return () => wsRef.current?.close();
  }, [backendUrl]);

  const toggleMode = async (deviceId, currentMode) => {
    const newMode = currentMode === 'normal' ? 'malicious' : 'normal';
    await fetch(`${backendUrl}/api/devices/${encodeURIComponent(deviceId)}/mode`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: newMode }),
    });
    // The agent will pick up mode change on next POST cycle (or you can push via WS)
    setDevices(prev => ({
      ...prev,
      [deviceId]: { ...prev[deviceId], mode: newMode }
    }));
  };

  const deviceList = Object.values(devices);

  return (
    <div style={{ fontFamily: 'sans-serif', padding: '20px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 24 }}>
        <h2 style={{ margin: 0 }}>📱 Live Phone Devices</h2>
        <span style={{
          padding: '3px 10px', borderRadius: 999, fontSize: 12, fontWeight: 600,
          background: wsStatus === 'connected' ? '#d1fae5' : '#fee2e2',
          color: wsStatus === 'connected' ? '#065f46' : '#991b1b'
        }}>
          {wsStatus === 'connected' ? '● Live' : '○ ' + wsStatus}
        </span>
      </div>

      {deviceList.length === 0 && (
        <p style={{ color: '#6b7280' }}>No devices connected yet. Run the agent on your phones.</p>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: 16 }}>
        {deviceList.map(device => {
          const colors = RISK_COLORS[device.risk_level] || RISK_COLORS.LOW;
          const isActive = (Date.now() - new Date(device.last_seen).getTime()) < 15000;

          return (
            <div key={device.device_id} style={{
              border: `2px solid ${colors.border}`,
              borderRadius: 12,
              background: colors.bg,
              padding: 16,
              position: 'relative',
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                  <span style={{ fontSize: 28 }}>{ROLE_ICONS[device.role] || '📱'}</span>
                  <div style={{ fontWeight: 700, fontSize: 16, marginTop: 4 }}>{device.device_id}</div>
                  <div style={{ fontSize: 12, color: '#6b7280' }}>{device.role} · {device.ip}</div>
                </div>
                <div style={{ textAlign: 'right' }}>
                  <div style={{
                    fontWeight: 800, fontSize: 28, color: colors.text
                  }}>{device.trust_score ?? '—'}</div>
                  <div style={{
                    fontSize: 11, fontWeight: 700, color: colors.text,
                    background: 'rgba(0,0,0,0.08)', borderRadius: 4, padding: '2px 6px'
                  }}>{device.risk_level}</div>
                </div>
              </div>

              {/* Metrics */}
              <div style={{ marginTop: 12, fontSize: 12, color: '#374151', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 4 }}>
                <div>CPU: <b>{device.metrics?.cpu_percent?.toFixed(1)}%</b></div>
                <div>RAM: <b>{device.metrics?.memory_percent?.toFixed(1)}%</b></div>
                <div>Conns: <b>{device.metrics?.connection_count}</b></div>
                <div>Ports: <b>{device.metrics?.open_ports?.length}</b></div>
              </div>

              {/* Anomalies */}
              {device.anomalies?.length > 0 && (
                <div style={{ marginTop: 10 }}>
                  {device.anomalies.map(a => (
                    <span key={a} style={{
                      display: 'inline-block', marginRight: 4, marginBottom: 4,
                      background: '#fee2e2', color: '#991b1b',
                      borderRadius: 4, padding: '2px 7px', fontSize: 11, fontWeight: 600
                    }}>⚠ {a}</span>
                  ))}
                </div>
              )}

              {/* Status + Toggle */}
              <div style={{ marginTop: 12, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: 11, color: isActive ? '#059669' : '#9ca3af' }}>
                  {isActive ? '● Active' : '○ Stale'} · {new Date(device.last_seen).toLocaleTimeString()}
                </span>
                <button
                  onClick={() => toggleMode(device.device_id, device.mode)}
                  style={{
                    padding: '5px 12px', borderRadius: 6, border: 'none', cursor: 'pointer',
                    fontWeight: 600, fontSize: 12,
                    background: device.mode === 'malicious' ? '#ef4444' : '#10b981',
                    color: 'white',
                  }}
                >
                  {device.mode === 'malicious' ? '🔴 Malicious' : '🟢 Normal'}
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}