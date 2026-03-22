'use strict';
const express = require('express');
const http = require('http');
const WebSocket = require('ws')
const WebSocketServer = WebSocket.Server;
const Database = require('better-sqlite3');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const axios = require('axios');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });
const PORT = 3001;

const DB_PATH = path.join(__dirname, 'data', 'opswatch.db');
if (!fs.existsSync(path.join(__dirname, 'data'))) fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });

const db = new Database(DB_PATH);
db.exec(`
  CREATE TABLE IF NOT EXISTS checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT, service TEXT NOT NULL,
    port INTEGER NOT NULL, status TEXT NOT NULL, latency INTEGER,
    checked_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT, service TEXT NOT NULL,
    message TEXT NOT NULL, resolved INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

const SERVICES = [
  { name: 'Flask Gateway',   port: 5013,  path: '/health' },
  { name: 'ClawArivu',       port: 18789, path: '/api/health' },
  { name: 'Neural Brain',    port: 8200,  path: '/health' },
  { name: 'KaasAI',          port: 3000,  path: '/health' },
  { name: 'Valluvan',        port: 5000,  path: '/health' },
  { name: 'OpsShiftPro',     port: 4000,  path: '/api/health' },
  { name: 'Vault Browser',   port: 4100,  path: '/api/health' },
  { name: 'ArivuWatch',      port: 9000,  path: '/health' },
];

const ADMIN_HASH = crypto.createHash('sha256').update('admin:opswatch2026').digest('hex');
const sessions = new Set();

function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (sessions.has(token)) return next();
  res.status(401).json({ error: 'Unauthorized' });
}

app.use(express.json());
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

const distPath = path.join(__dirname, 'frontend', 'dist');
if (fs.existsSync(distPath)) app.use(express.static(distPath));

let lastStatus = [];

async function runChecks() {
  lastStatus = await Promise.all(SERVICES.map(async s => {
    const start = Date.now();
    try {
      await axios.get(`http://localhost:${s.port}${s.path}`, { timeout: 3000 });
      const latency = Date.now() - start;
      db.prepare('INSERT INTO checks (service, port, status, latency) VALUES (?, ?, ?, ?)').run(s.name, s.port, 'up', latency);
      return { ...s, status: 'up', latency };
    } catch {
      db.prepare('INSERT INTO checks (service, port, status, latency) VALUES (?, ?, ?, ?)').run(s.name, s.port, 'down', null);
      const existing = db.prepare("SELECT id FROM alerts WHERE service=? AND resolved=0").get(s.name);
      if (!existing) db.prepare('INSERT INTO alerts (service, message) VALUES (?, ?)').run(s.name, `${s.name} on port ${s.port} is DOWN`);
      return { ...s, status: 'down', latency: null };
    }
  }));
  const msg = JSON.stringify({ type: 'status', services: lastStatus, ts: Date.now() });
  wss.clients.forEach(c => { if (c.readyState === 1) c.send(msg); });
  db.prepare('DELETE FROM checks WHERE id NOT IN (SELECT id FROM checks ORDER BY id DESC LIMIT 1000)').run();
}

runChecks();
setInterval(runChecks, 30000);

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  const hash = crypto.createHash('sha256').update(`${username}:${password}`).digest('hex');
  if (hash !== ADMIN_HASH) return res.status(401).json({ error: 'Invalid credentials' });
  const token = crypto.randomBytes(32).toString('hex');
  sessions.add(token);
  res.json({ token });
});

app.get('/api/status', auth, (req, res) => res.json({ services: lastStatus, ts: Date.now() }));

app.get('/api/history', auth, (req, res) => {
  const service = req.query.service;
  const rows = service
    ? db.prepare('SELECT * FROM checks WHERE service=? ORDER BY checked_at DESC LIMIT 100').all(service)
    : db.prepare('SELECT * FROM checks ORDER BY checked_at DESC LIMIT 200').all();
  res.json({ history: rows });
});

app.get('/api/alerts', auth, (req, res) => res.json({ alerts: db.prepare('SELECT * FROM alerts ORDER BY created_at DESC LIMIT 50').all() }));
app.put('/api/alerts/:id/resolve', auth, (req, res) => { db.prepare('UPDATE alerts SET resolved=1 WHERE id=?').run(req.params.id); res.json({ success: true }); });

app.get('/api/uptime', auth, (req, res) => {
  const uptimes = SERVICES.map(s => {
    const total = db.prepare('SELECT COUNT(*) as c FROM checks WHERE service=?').get(s.name).c;
    const up = db.prepare("SELECT COUNT(*) as c FROM checks WHERE service=? AND status='up'").get(s.name).c;
    return { service: s.name, port: s.port, uptime: total > 0 ? ((up/total)*100).toFixed(1) : 100 };
  });
  res.json({ uptimes });
});

app.get('/health', (req, res) => res.json({ status: 'ok', service: 'opswatch', port: PORT }));

app.get('*splat', (req, res) => {
  if (fs.existsSync(path.join(distPath, 'index.html')))
    return res.sendFile(path.join(distPath, 'index.html'));
  res.json({ service: 'OpsWatch Unified', status: 'running', port: PORT });
});

wss.on('connection', ws => ws.send(JSON.stringify({ type: 'status', services: lastStatus, ts: Date.now() })));

server.listen(PORT, '0.0.0.0', () => console.log(`OpsWatch running on port ${PORT}`));