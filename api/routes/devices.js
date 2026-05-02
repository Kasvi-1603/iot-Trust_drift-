// api/routes/devices.js
const express = require('express');
const router = express.Router();

// Store latest telemetry per device (in-memory; swap for Redis/DB later)
const deviceRegistry = new Map();

// Import your existing trust engine scoring (adjust path as needed)
let scoreTelemetry;
try {
  scoreTelemetry = require('../../trust_engine/scorer');
} catch {
  // Fallback mock scorer if trust_engine isn't JS-bridged yet
  scoreTelemetry = (payload) => {
    const events = payload.metrics?.events || payload.events || [];
    const connCount = payload.metrics?.connection_count || 0;
    const bytesSent = payload.metrics?.bytes_sent || 0;
    const openPorts = (payload.metrics?.open_ports || []).length;

    let score = 100;
    score -= Math.min(30, events.length * 10);
    score -= Math.min(20, Math.floor(connCount / 15));
    score -= Math.min(20, openPorts * 2);
    score -= bytesSent > 5_000_000 ? 20 : 0;

    const risk = score > 75 ? 'LOW' : score > 45 ? 'MEDIUM' : score > 20 ? 'HIGH' : 'CRITICAL';
    return { trust_score: Math.max(0, score), risk_level: risk, anomalies: events.map(e => e.type) };
  };
}

// POST /api/devices/telemetry  — called by phone agents
router.post('/telemetry', (req, res) => {
  const payload = req.body;
  if (!payload?.device_id) return res.status(400).json({ error: 'Missing device_id' });

  const scored = scoreTelemetry(payload);
  const record = {
    ...payload,
    ...scored,
    last_seen: new Date().toISOString(),
  };

  deviceRegistry.set(payload.device_id, record);

  // Broadcast to all WebSocket clients
  if (req.app.locals.wss) {
    const msg = JSON.stringify({ type: 'DEVICE_UPDATE', data: record });
    req.app.locals.wss.clients.forEach(client => {
      if (client.readyState === 1) client.send(msg);
    });
  }

  res.json({ trust_score: record.trust_score, risk_level: record.risk_level });
});

// GET /api/devices  — dashboard polls or loads initial state
router.get('/', (req, res) => {
  res.json(Array.from(deviceRegistry.values()));
});

// POST /api/devices/:id/mode  — toggle normal/malicious from dashboard
router.post('/:id/mode', (req, res) => {
  const { id } = req.params;
  const { mode } = req.body;
  const device = deviceRegistry.get(id);
  if (!device) return res.status(404).json({ error: 'Device not found' });
  device.mode = mode;
  deviceRegistry.set(id, device);
  res.json({ ok: true, device_id: id, mode });
});

module.exports = { router, deviceRegistry };