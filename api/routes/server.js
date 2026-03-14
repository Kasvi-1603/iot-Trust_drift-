// At the top, add:
const http = require('http');
const { WebSocketServer } = require('ws');
const { router: devicesRouter } = require('./routes/devices');

// After you create your express app:
const server = http.createServer(app);
const wss = new WebSocketServer({ server });
app.locals.wss = wss;

wss.on('connection', (ws) => {
  console.log('[WS] Client connected');
  ws.on('close', () => console.log('[WS] Client disconnected'));
});

// Mount the new route (add alongside your existing routes):
app.use('/api/devices', devicesRouter);

// IMPORTANT: Change app.listen(...) to server.listen(...)
// Find: app.listen(PORT, ...)
// Replace with:
server.listen(PORT, '0.0.0.0', () => {   // 0.0.0.0 so phones can reach it
  console.log(`Server running on port ${PORT}`);
});
// In server.js add:
const cors = require('cors');
app.use(cors({
  origin: ['https://your-app.vercel.app', 'http://localhost:3000'],
}));