const path = require('path');
const fs = require('fs');

// Configure env BEFORE any app imports
const TEST_DB = path.join(__dirname, '..', '..', 'data', 'test-opswatch.db');
process.env.DB_PATH = TEST_DB;
process.env.JWT_SECRET = 'test-secret';

const request = require('supertest');
const bcrypt = require('bcryptjs');

let app, server, db;
let adminToken, viewerToken;

beforeAll(async () => {
  // Clean previous test db
  if (fs.existsSync(TEST_DB)) fs.unlinkSync(TEST_DB);

  // Import app (triggers db init)
  const mod = require('../src/index');
  app = mod.app;
  server = mod.server;
  db = mod.db;

  // Seed users
  const hash = bcrypt.hashSync('testpass123', 10);
  db.prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)').run(
    'admin',
    hash,
    'admin'
  );
  db.prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)').run(
    'viewer',
    hash,
    'viewer'
  );

  // Get tokens
  const adminRes = await request(app)
    .post('/api/auth/login')
    .send({ username: 'admin', password: 'testpass123' });
  adminToken = adminRes.body.token;

  const viewerRes = await request(app)
    .post('/api/auth/login')
    .send({ username: 'viewer', password: 'testpass123' });
  viewerToken = viewerRes.body.token;
});

afterAll(() => {
  if (server && server.listening) server.close();
  const { closeDb } = require('../src/db');
  closeDb();
  if (fs.existsSync(TEST_DB)) fs.unlinkSync(TEST_DB);
});

// ── Auth Tests ──────────────────────────────────────────

describe('Auth', () => {
  test('POST /api/auth/login — success with valid credentials', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'admin', password: 'testpass123' });
    expect(res.status).toBe(200);
    expect(res.body.token).toBeDefined();
    expect(res.body.user.username).toBe('admin');
    expect(res.body.user.role).toBe('admin');
  });

  test('POST /api/auth/login — fail with wrong password', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'admin', password: 'wrongpassword' });
    expect(res.status).toBe(401);
    expect(res.body.error).toBeDefined();
  });

  test('POST /api/auth/login — fail with nonexistent user', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'nobody', password: 'whatever' });
    expect(res.status).toBe(401);
  });

  test('POST /api/auth/login — fail with missing fields', async () => {
    const res = await request(app).post('/api/auth/login').send({});
    expect(res.status).toBe(400);
    expect(res.body.errors).toBeDefined();
  });

  test('GET /api/auth/me — returns current user', async () => {
    const res = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.user.username).toBe('admin');
  });

  test('GET /api/auth/me — rejects request without token', async () => {
    const res = await request(app).get('/api/auth/me');
    expect(res.status).toBe(401);
  });

  test('GET /api/auth/me — rejects invalid token', async () => {
    const res = await request(app)
      .get('/api/auth/me')
      .set('Authorization', 'Bearer invalidtoken');
    expect(res.status).toBe(401);
  });
});

// ── Services Tests ──────────────────────────────────────

describe('Services', () => {
  test('POST /api/services — admin can add service', async () => {
    const res = await request(app)
      .post('/api/services')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ name: 'Test Service', host: 'localhost', port: 8080, health_path: '/health' });
    expect(res.status).toBe(201);
    expect(res.body.service).toBeDefined();
    expect(res.body.service.name).toBe('Test Service');
    expect(res.body.service.url).toBe('http://localhost:8080/health');
  });

  test('POST /api/services — viewer cannot add service', async () => {
    const res = await request(app)
      .post('/api/services')
      .set('Authorization', `Bearer ${viewerToken}`)
      .send({ name: 'Blocked', host: 'localhost', port: 9090, health_path: '/health' });
    expect(res.status).toBe(403);
  });

  test('POST /api/services — rejects invalid input', async () => {
    const res = await request(app)
      .post('/api/services')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ name: '' });
    expect(res.status).toBe(400);
  });

  test('GET /api/services — lists services', async () => {
    const res = await request(app)
      .get('/api/services')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.services)).toBe(true);
    expect(res.body.services.length).toBeGreaterThanOrEqual(1);
  });

  test('DELETE /api/services/:id — admin can delete service', async () => {
    // Create a service to delete
    const createRes = await request(app)
      .post('/api/services')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ name: 'To Delete', host: 'localhost', port: 7777, health_path: '/ping' });
    const id = createRes.body.service.id;

    const res = await request(app)
      .delete(`/api/services/${id}`)
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.message).toBe('Service deleted');
  });

  test('DELETE /api/services/999 — returns 404 for missing service', async () => {
    const res = await request(app)
      .delete('/api/services/999')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(404);
  });
});

// ── Status Tests ────────────────────────────────────────

describe('Status', () => {
  test('GET /api/status — returns array of results', async () => {
    const res = await request(app)
      .get('/api/status')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.results)).toBe(true);
  });

  test('GET /api/status/history — returns history array', async () => {
    const res = await request(app)
      .get('/api/status/history')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.history)).toBe(true);
  });
});

// ── Alerts Tests ────────────────────────────────────────

describe('Alerts', () => {
  let alertId;

  test('POST /api/alerts — create alert', async () => {
    const res = await request(app)
      .post('/api/alerts')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ title: 'CPU High', severity: 'critical', service_name: 'Test Service' });
    expect(res.status).toBe(201);
    expect(res.body.alert).toBeDefined();
    expect(res.body.alert.title).toBe('CPU High');
    alertId = res.body.alert.id;
  });

  test('POST /api/alerts — rejects invalid severity', async () => {
    const res = await request(app)
      .post('/api/alerts')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ title: 'Bad', severity: 'extreme', service_name: 'Test Service' });
    expect(res.status).toBe(400);
  });

  test('GET /api/alerts — lists alerts', async () => {
    const res = await request(app)
      .get('/api/alerts')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.alerts)).toBe(true);
    expect(res.body.alerts.length).toBeGreaterThanOrEqual(1);
  });

  test('PATCH /api/alerts/:id/acknowledge — acknowledges alert', async () => {
    const res = await request(app)
      .patch(`/api/alerts/${alertId}/acknowledge`)
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.alert.is_acknowledged).toBe(1);
  });

  test('PATCH /api/alerts/999/acknowledge — 404 for missing alert', async () => {
    const res = await request(app)
      .patch('/api/alerts/999/acknowledge')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(404);
  });
});

// ── Incidents Tests ────────────────────────────────────

describe('Incidents', () => {
  let incidentId;

  test('POST /api/incidents — create incident', async () => {
    const res = await request(app)
      .post('/api/incidents')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ title: 'DB Outage', severity: 'critical', description: 'Primary DB unreachable' });
    expect(res.status).toBe(201);
    expect(res.body.incident).toBeDefined();
    expect(res.body.incident.title).toBe('DB Outage');
    expect(res.body.incident.status).toBe('open');
    incidentId = res.body.incident.id;
  });

  test('POST /api/incidents — rejects invalid severity', async () => {
    const res = await request(app)
      .post('/api/incidents')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ title: 'Bad', severity: 'extreme' });
    expect(res.status).toBe(400);
  });

  test('GET /api/incidents — lists incidents', async () => {
    const res = await request(app)
      .get('/api/incidents')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.incidents)).toBe(true);
    expect(res.body.incidents.length).toBeGreaterThanOrEqual(1);
  });

  test('PATCH /api/incidents/:id — update status to investigating', async () => {
    const res = await request(app)
      .patch(`/api/incidents/${incidentId}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ status: 'investigating' });
    expect(res.status).toBe(200);
    expect(res.body.incident.status).toBe('investigating');
  });

  test('PATCH /api/incidents/:id — close incident', async () => {
    const res = await request(app)
      .patch(`/api/incidents/${incidentId}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ status: 'closed' });
    expect(res.status).toBe(200);
    expect(res.body.incident.status).toBe('closed');
    expect(res.body.incident.closed_at).toBeDefined();
  });

  test('PATCH /api/incidents/999 — 404 for missing incident', async () => {
    const res = await request(app)
      .patch('/api/incidents/999')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ status: 'closed' });
    expect(res.status).toBe(404);
  });
});

// ── Dashboard Tests ─────────────────────────────────────

describe('Dashboard', () => {
  test('GET /api/dashboard/stats — returns stats object', async () => {
    const res = await request(app)
      .get('/api/dashboard/stats')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(res.status).toBe(200);
    expect(res.body.stats).toBeDefined();
    expect(typeof res.body.stats.total_services).toBe('number');
    expect(typeof res.body.stats.up).toBe('number');
    expect(typeof res.body.stats.down).toBe('number');
    expect(typeof res.body.stats.active_alerts).toBe('number');
  });
});

// ── Health Endpoint ─────────────────────────────────────

describe('Health', () => {
  test('GET /api/health — no auth required, returns ok', async () => {
    const res = await request(app).get('/api/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
  });
});

// ── Protected Routes Reject Unauthenticated ─────────────

describe('Protected routes reject unauthenticated', () => {
  test('GET /api/services — 401 without token', async () => {
    const res = await request(app).get('/api/services');
    expect(res.status).toBe(401);
  });

  test('GET /api/status — 401 without token', async () => {
    const res = await request(app).get('/api/status');
    expect(res.status).toBe(401);
  });

  test('GET /api/alerts — 401 without token', async () => {
    const res = await request(app).get('/api/alerts');
    expect(res.status).toBe(401);
  });

  test('GET /api/dashboard/stats — 401 without token', async () => {
    const res = await request(app).get('/api/dashboard/stats');
    expect(res.status).toBe(401);
  });
});
