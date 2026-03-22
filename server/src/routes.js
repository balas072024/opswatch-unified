const express = require('express');
const { body, param, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const axios = require('axios');
const { generateToken, authMiddleware, adminOnly } = require('./auth');

function createRoutes(db) {
  const router = express.Router();

  // Helper: return validation errors
  function validate(req, res, next) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  }

  // ──────────────────────────────────────────────
  // Health (no auth)
  // ──────────────────────────────────────────────
  router.get('/health', (_req, res) => {
    res.json({ status: 'ok' });
  });

  // ──────────────────────────────────────────────
  // Auth
  // ──────────────────────────────────────────────
  router.post(
    '/auth/login',
    [
      body('username').isString().notEmpty().withMessage('Username is required'),
      body('password').isString().notEmpty().withMessage('Password is required'),
    ],
    validate,
    (req, res) => {
      const { username, password } = req.body;
      const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
      if (!user) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const valid = bcrypt.compareSync(password, user.password_hash);
      if (!valid) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const token = generateToken(user);
      return res.json({
        token,
        user: { id: user.id, username: user.username, role: user.role },
      });
    }
  );

  router.get('/auth/me', authMiddleware, (req, res) => {
    const user = db.prepare('SELECT id, username, role, created_at FROM users WHERE id = ?').get(req.user.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ user });
  });

  // ──────────────────────────────────────────────
  // Services
  // ──────────────────────────────────────────────
  router.get('/services', authMiddleware, (_req, res) => {
    const services = db.prepare('SELECT * FROM monitored_services ORDER BY created_at DESC').all();
    res.json({ services });
  });

  router.post(
    '/services',
    authMiddleware,
    adminOnly,
    [
      body('name').isString().notEmpty().withMessage('Name is required'),
      body('host').isString().notEmpty().withMessage('Host is required'),
      body('port').isInt({ min: 1, max: 65535 }).withMessage('Valid port is required'),
      body('health_path').isString().notEmpty().withMessage('Health path is required'),
    ],
    validate,
    (req, res) => {
      const { name, host, port, health_path } = req.body;
      const url = `http://${host}:${port}${health_path}`;

      const result = db
        .prepare(
          'INSERT INTO monitored_services (name, url, description, expected_status) VALUES (?, ?, ?, 200)'
        )
        .run(name, url, `${host}:${port}`);

      const service = db.prepare('SELECT * FROM monitored_services WHERE id = ?').get(result.lastInsertRowid);
      res.status(201).json({ service });
    }
  );

  router.delete(
    '/services/:id',
    authMiddleware,
    adminOnly,
    [param('id').isInt().withMessage('Valid service ID is required')],
    validate,
    (req, res) => {
      const { id } = req.params;
      const service = db.prepare('SELECT * FROM monitored_services WHERE id = ?').get(id);
      if (!service) {
        return res.status(404).json({ error: 'Service not found' });
      }
      db.prepare('DELETE FROM monitored_services WHERE id = ?').run(id);
      res.json({ message: 'Service deleted' });
    }
  );

  // ──────────────────────────────────────────────
  // Status — check all services health
  // ──────────────────────────────────────────────
  router.get('/status', authMiddleware, async (_req, res) => {
    const services = db.prepare('SELECT * FROM monitored_services WHERE is_active = 1').all();
    const results = [];

    for (const svc of services) {
      let status = 'down';
      let responseTime = null;
      let statusCode = null;
      let errorMessage = null;

      const start = Date.now();
      try {
        const resp = await axios.get(svc.url, { timeout: 3000 });
        responseTime = Date.now() - start;
        statusCode = resp.status;
        status = resp.status === svc.expected_status ? 'up' : 'degraded';
      } catch (err) {
        responseTime = Date.now() - start;
        errorMessage = err.message;
        if (err.response) {
          statusCode = err.response.status;
          status = 'degraded';
        }
      }

      db.prepare(
        'INSERT INTO health_checks (service_id, status, response_time_ms, status_code, error_message) VALUES (?, ?, ?, ?, ?)'
      ).run(svc.id, status, responseTime, statusCode, errorMessage);

      results.push({
        service_id: svc.id,
        name: svc.name,
        status,
        response_time_ms: responseTime,
        status_code: statusCode,
        error_message: errorMessage,
      });
    }

    res.json({ results });
  });

  router.get('/status/history', authMiddleware, (_req, res) => {
    const history = db
      .prepare(
        `SELECT hc.*, ms.name AS service_name
         FROM health_checks hc
         LEFT JOIN monitored_services ms ON hc.service_id = ms.id
         ORDER BY hc.checked_at DESC
         LIMIT 200`
      )
      .all();
    res.json({ history });
  });

  // ──────────────────────────────────────────────
  // Alerts
  // ──────────────────────────────────────────────
  router.get('/alerts', authMiddleware, (_req, res) => {
    const alerts = db
      .prepare(
        `SELECT a.*, ms.name AS service_name
         FROM alerts a
         LEFT JOIN monitored_services ms ON a.service_id = ms.id
         ORDER BY a.created_at DESC`
      )
      .all();
    res.json({ alerts });
  });

  router.post(
    '/alerts',
    authMiddleware,
    [
      body('title').isString().notEmpty().withMessage('Title is required'),
      body('severity')
        .isIn(['critical', 'warning', 'info'])
        .withMessage('Severity must be critical, warning, or info'),
      body('service_name').isString().notEmpty().withMessage('Service name is required'),
    ],
    validate,
    (req, res) => {
      const { title, severity, service_name } = req.body;
      const service = db.prepare('SELECT id FROM monitored_services WHERE name = ?').get(service_name);
      const serviceId = service ? service.id : null;

      const result = db
        .prepare(
          'INSERT INTO alerts (service_id, severity, title, message) VALUES (?, ?, ?, ?)'
        )
        .run(serviceId, severity, title, title);

      const alert = db.prepare('SELECT * FROM alerts WHERE id = ?').get(result.lastInsertRowid);
      res.status(201).json({ alert });
    }
  );

  router.patch(
    '/alerts/:id/acknowledge',
    authMiddleware,
    [param('id').isInt().withMessage('Valid alert ID is required')],
    validate,
    (req, res) => {
      const { id } = req.params;
      const alert = db.prepare('SELECT * FROM alerts WHERE id = ?').get(id);
      if (!alert) {
        return res.status(404).json({ error: 'Alert not found' });
      }

      db.prepare(
        "UPDATE alerts SET is_acknowledged = 1, acknowledged_by = ?, acknowledged_at = datetime('now') WHERE id = ?"
      ).run(req.user.id, id);

      const updated = db.prepare('SELECT * FROM alerts WHERE id = ?').get(id);
      res.json({ alert: updated });
    }
  );

  // ──────────────────────────────────────────────
  // Incidents
  // ──────────────────────────────────────────────
  router.get('/incidents', authMiddleware, (_req, res) => {
    const incidents = db
      .prepare(
        `SELECT i.*, ms.name AS service_name
         FROM incidents i
         LEFT JOIN monitored_services ms ON i.service_id = ms.id
         ORDER BY i.opened_at DESC`
      )
      .all();
    res.json({ incidents });
  });

  router.post(
    '/incidents',
    authMiddleware,
    [
      body('title').isString().notEmpty().withMessage('Title is required'),
      body('severity')
        .isIn(['critical', 'major', 'minor'])
        .withMessage('Severity must be critical, major, or minor'),
      body('description').optional().isString(),
      body('service_id').optional().isInt(),
    ],
    validate,
    (req, res) => {
      const { title, severity, description, service_id } = req.body;

      if (service_id) {
        const svc = db.prepare('SELECT id FROM monitored_services WHERE id = ?').get(service_id);
        if (!svc) {
          return res.status(404).json({ error: 'Service not found' });
        }
      }

      const result = db
        .prepare(
          'INSERT INTO incidents (service_id, title, description, severity, opened_by) VALUES (?, ?, ?, ?, ?)'
        )
        .run(service_id || null, title, description || '', severity, req.user.id);

      const incident = db.prepare('SELECT * FROM incidents WHERE id = ?').get(result.lastInsertRowid);
      res.status(201).json({ incident });
    }
  );

  router.patch(
    '/incidents/:id',
    authMiddleware,
    [
      param('id').isInt().withMessage('Valid incident ID is required'),
      body('status')
        .isIn(['open', 'investigating', 'resolved', 'closed'])
        .withMessage('Invalid status'),
    ],
    validate,
    (req, res) => {
      const { id } = req.params;
      const incident = db.prepare('SELECT * FROM incidents WHERE id = ?').get(id);
      if (!incident) {
        return res.status(404).json({ error: 'Incident not found' });
      }

      const newStatus = req.body.status;
      if (newStatus === 'closed' || newStatus === 'resolved') {
        db.prepare(
          "UPDATE incidents SET status = ?, closed_by = ?, closed_at = datetime('now') WHERE id = ?"
        ).run(newStatus, req.user.id, id);
      } else {
        db.prepare('UPDATE incidents SET status = ? WHERE id = ?').run(newStatus, id);
      }

      const updated = db.prepare('SELECT * FROM incidents WHERE id = ?').get(id);
      res.json({ incident: updated });
    }
  );

  // ──────────────────────────────────────────────
  // Dashboard
  // ──────────────────────────────────────────────
  router.get('/dashboard/stats', authMiddleware, (_req, res) => {
    const totalServices = db.prepare('SELECT COUNT(*) AS count FROM monitored_services').get().count;

    // Get the latest health check per service
    const upCount = db
      .prepare(
        `SELECT COUNT(*) AS count FROM (
          SELECT hc.status FROM health_checks hc
          INNER JOIN (
            SELECT service_id, MAX(checked_at) AS max_checked
            FROM health_checks GROUP BY service_id
          ) latest ON hc.service_id = latest.service_id AND hc.checked_at = latest.max_checked
          WHERE hc.status = 'up'
        )`
      )
      .get().count;

    const downCount = db
      .prepare(
        `SELECT COUNT(*) AS count FROM (
          SELECT hc.status FROM health_checks hc
          INNER JOIN (
            SELECT service_id, MAX(checked_at) AS max_checked
            FROM health_checks GROUP BY service_id
          ) latest ON hc.service_id = latest.service_id AND hc.checked_at = latest.max_checked
          WHERE hc.status = 'down'
        )`
      )
      .get().count;

    const alertCount = db.prepare('SELECT COUNT(*) AS count FROM alerts WHERE is_acknowledged = 0').get().count;
    const openIncidents = db.prepare("SELECT COUNT(*) AS count FROM incidents WHERE status IN ('open', 'investigating')").get().count;

    // Average latency from latest checks
    const latencyRow = db
      .prepare(
        `SELECT AVG(hc.response_time_ms) AS avg_latency FROM health_checks hc
         INNER JOIN (
           SELECT service_id, MAX(checked_at) AS max_checked
           FROM health_checks GROUP BY service_id
         ) latest ON hc.service_id = latest.service_id AND hc.checked_at = latest.max_checked
         WHERE hc.response_time_ms IS NOT NULL`
      )
      .get();
    const avgLatency = latencyRow && latencyRow.avg_latency ? Math.round(latencyRow.avg_latency) : 0;

    res.json({
      stats: {
        total_services: totalServices,
        up: upCount,
        down: downCount,
        active_alerts: alertCount,
        open_incidents: openIncidents,
        avg_latency_ms: avgLatency,
      },
    });
  });

  return router;
}

module.exports = createRoutes;
