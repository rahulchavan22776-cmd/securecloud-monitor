/**
 * SecureCloud Monitor - Administrator & SOC Management API Routes
 * Enforces requireAuth and requireAdmin across all endpoints
 */

const express = require('express');
const router = express.Router();
const { query } = require('../db');
const { requireAuth, requireAdmin, logActivity } = require('../middleware/auth');
const securityEngine = require('../services/securityEngine');

// Enforce authentication and administrator role on all routes
router.use(requireAuth, requireAdmin);

/**
 * GET /api/admin/metrics
 * Comprehensive SOC overview metrics & calculated Security Posture Score
 */
router.get('/metrics', async (req, res) => {
  try {
    // 1. Alerts counts
    const [alertCounts] = await query(`
      SELECT 
        COUNT(*) as total_alerts,
        SUM(CASE WHEN status = 'OPEN' THEN 1 ELSE 0 END) as open_alerts,
        SUM(CASE WHEN status = 'ACKNOWLEDGED' THEN 1 ELSE 0 END) as acknowledged_alerts,
        SUM(CASE WHEN status = 'RESOLVED' THEN 1 ELSE 0 END) as resolved_alerts,
        SUM(CASE WHEN status = 'OPEN' AND severity = 'CRITICAL' THEN 1 ELSE 0 END) as open_critical,
        SUM(CASE WHEN status = 'OPEN' AND severity = 'HIGH' THEN 1 ELSE 0 END) as open_high,
        SUM(CASE WHEN status = 'OPEN' AND severity = 'MEDIUM' THEN 1 ELSE 0 END) as open_medium,
        SUM(CASE WHEN status = 'OPEN' AND severity = 'LOW' THEN 1 ELSE 0 END) as open_low
      FROM security_alerts
    `);

    // 2. Incident counts
    const [incidentCounts] = await query(`
      SELECT 
        COUNT(*) as total_incidents,
        SUM(CASE WHEN status = 'OPEN' THEN 1 ELSE 0 END) as open_incidents,
        SUM(CASE WHEN status = 'INVESTIGATING' THEN 1 ELSE 0 END) as investigating_incidents,
        SUM(CASE WHEN status = 'RESOLVED' THEN 1 ELSE 0 END) as resolved_incidents
      FROM security_incidents
    `);

    // 3. Cloud resource counts
    const [resourceCounts] = await query(`
      SELECT 
        COUNT(*) as total_resources,
        SUM(CASE WHEN status = 'SECURE' OR status = 'ACTIVE' THEN 1 ELSE 0 END) as secure_resources,
        SUM(CASE WHEN status = 'VULNERABLE' OR status = 'CRITICAL' THEN 1 ELSE 0 END) as vulnerable_resources
      FROM cloud_resources
    `);

    // 4. System stats (users, files, active rules)
    const [userCount] = await query('SELECT COUNT(*) as count FROM users');
    const [fileCount] = await query('SELECT COUNT(*) as count FROM files');
    const [ruleCount] = await query('SELECT COUNT(*) as total_rules, SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END) as active_rules FROM security_rules');

    // 5. Recent Alerts (5 most recent)
    const [recentAlerts] = await query(`
      SELECT a.id, a.title, a.severity, a.status, a.created_at, r.rule_code, r.category
      FROM security_alerts a
      LEFT JOIN security_rules r ON a.rule_id = r.id
      ORDER BY a.created_at DESC
      LIMIT 5
    `);

    // 6. Recent Incidents (5 most recent)
    const [recentIncidents] = await query(`
      SELECT id, title, severity, status, created_at, investigation_notes
      FROM security_incidents
      ORDER BY created_at DESC
      LIMIT 5
    `);

    // 7. Calculate Dynamic Security Posture Score (0 - 100)
    const crit = parseInt(alertCounts[0].open_critical || 0, 10);
    const high = parseInt(alertCounts[0].open_high || 0, 10);
    const med = parseInt(alertCounts[0].open_medium || 0, 10);
    const low = parseInt(alertCounts[0].open_low || 0, 10);

    let score = 100 - (crit * 25) - (high * 15) - (med * 5) - (low * 2);
    if (score < 0) score = 0;
    if (score > 100) score = 100;

    let postureLevel = 'EXCELLENT';
    if (score < 50) postureLevel = 'CRITICAL';
    else if (score < 75) postureLevel = 'POOR';
    else if (score < 90) postureLevel = 'MODERATE';

    res.json({
      success: true,
      metrics: {
        securityScore: score,
        postureLevel,
        alerts: alertCounts[0],
        incidents: incidentCounts[0],
        resources: resourceCounts[0],
        usersCount: userCount[0].count,
        filesCount: fileCount[0].count,
        rules: ruleCount[0],
        recentAlerts,
        recentIncidents
      }
    });
  } catch (err) {
    console.error('[ADMIN METRICS ERROR]', err.message);
    res.status(500).json({ success: false, message: 'Failed to compute SOC metrics.' });
  }
});

/**
 * GET /api/admin/alerts
 * Fetch alerts with optional filtering
 */
router.get('/alerts', async (req, res) => {
  try {
    const { status, severity } = req.query;
    let sql = `
      SELECT a.*, r.rule_code, r.name as rule_name, r.category
      FROM security_alerts a
      LEFT JOIN security_rules r ON a.rule_id = r.id
      WHERE 1=1
    `;
    const params = [];

    if (status && status !== 'ALL') {
      sql += ' AND a.status = ?';
      params.push(status);
    }
    if (severity && severity !== 'ALL') {
      sql += ' AND a.severity = ?';
      params.push(severity);
    }

    sql += ' ORDER BY a.created_at DESC';

    const [alerts] = await query(sql, params);
    res.json({ success: true, alerts });
  } catch (err) {
    console.error('[GET ALERTS ERROR]', err.message);
    res.status(500).json({ success: false, message: 'Failed to fetch security alerts.' });
  }
});

/**
 * PUT /api/admin/alerts/:id
 * Update alert status (ACKNOWLEDGED / RESOLVED)
 */
router.put('/alerts/:id', async (req, res) => {
  try {
    const alertId = parseInt(req.params.id, 10);
    const { status } = req.body;

    if (!['OPEN', 'ACKNOWLEDGED', 'RESOLVED'].includes(status)) {
      return res.status(400).json({ success: false, message: 'Invalid status value.' });
    }

    const resolvedAt = status === 'RESOLVED' ? new Date() : null;

    const [result] = await query(
      'UPDATE security_alerts SET status = ?, resolved_at = ? WHERE id = ?',
      [status, resolvedAt, alertId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Alert not found.' });
    }

    await logActivity(
      req.user.id,
      'ALERT_STATUS_UPDATE',
      `Alert #${alertId} updated to status "${status}" by ${req.user.username}`,
      req.clientIp
    );

    res.json({ success: true, message: `Alert #${alertId} updated to ${status}.` });
  } catch (err) {
    console.error('[UPDATE ALERT ERROR]', err.message);
    res.status(500).json({ success: false, message: 'Failed to update alert.' });
  }
});

/**
 * POST /api/admin/alerts
 * Manually create an alert
 */
router.post('/alerts', async (req, res) => {
  try {
    const { rule_id, title, description, severity } = req.body;

    if (!title || !severity) {
      return res.status(400).json({ success: false, message: 'Title and severity are required.' });
    }

    const [result] = await query(
      'INSERT INTO security_alerts (rule_id, title, description, severity, status, created_at) VALUES (?, ?, ?, ?, "OPEN", NOW())',
      [rule_id || null, title, description || '', severity]
    );

    await logActivity(
      req.user.id,
      'ALERT_MANUAL_CREATE',
      `Manual alert created: [${severity}] ${title}`,
      req.clientIp
    );

    res.status(201).json({
      success: true,
      message: 'Security alert created successfully.',
      alertId: result.insertId
    });
  } catch (err) {
    console.error('[CREATE ALERT ERROR]', err.message);
    res.status(500).json({ success: false, message: 'Failed to create alert.' });
  }
});

/**
 * GET /api/admin/incidents
 * Fetch incidents with joined alert details
 */
router.get('/incidents', async (req, res) => {
  try {
    const { status, severity } = req.query;
    let sql = `
      SELECT i.*, a.title as alert_title, a.description as alert_desc
      FROM security_incidents i
      LEFT JOIN security_alerts a ON i.alert_id = a.id
      WHERE 1=1
    `;
    const params = [];

    if (status && status !== 'ALL') {
      sql += ' AND i.status = ?';
      params.push(status);
    }
    if (severity && severity !== 'ALL') {
      sql += ' AND i.severity = ?';
      params.push(severity);
    }

    sql += ' ORDER BY i.created_at DESC';

    const [incidents] = await query(sql, params);
    res.json({ success: true, incidents });
  } catch (err) {
    console.error('[GET INCIDENTS ERROR]', err.message);
    res.status(500).json({ success: false, message: 'Failed to fetch incidents.' });
  }
});

/**
 * PUT /api/admin/incidents/:id
 * Update incident status and append investigation notes
 */
router.put('/incidents/:id', async (req, res) => {
  try {
    const incidentId = parseInt(req.params.id, 10);
    const { status, investigation_notes } = req.body;

    if (status && !['OPEN', 'INVESTIGATING', 'RESOLVED'].includes(status)) {
      return res.status(400).json({ success: false, message: 'Invalid incident status.' });
    }

    const resolvedAt = status === 'RESOLVED' ? new Date() : null;

    let updateSql = 'UPDATE security_incidents SET ';
    const params = [];
    const updates = [];

    if (status) {
      updates.push('status = ?');
      params.push(status);
      if (status === 'RESOLVED') {
        updates.push('resolved_at = NOW()');
      }
    }

    if (investigation_notes !== undefined) {
      updates.push('investigation_notes = ?');
      params.push(investigation_notes);
    }

    if (updates.length === 0) {
      return res.status(400).json({ success: false, message: 'No update parameters provided.' });
    }

    updateSql += updates.join(', ') + ' WHERE id = ?';
    params.push(incidentId);

    const [result] = await query(updateSql, params);

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Incident not found.' });
    }

    await logActivity(
      req.user.id,
      'INCIDENT_UPDATE',
      `Incident #${incidentId} updated (${status || 'notes modified'}) by ${req.user.username}`,
      req.clientIp
    );

    res.json({ success: true, message: `Incident #${incidentId} updated successfully.` });
  } catch (err) {
    console.error('[UPDATE INCIDENT ERROR]', err.message);
    res.status(500).json({ success: false, message: 'Failed to update incident.' });
  }
});

/**
 * POST /api/admin/incidents
 * Create manual incident or escalate from alert
 */
router.post('/incidents', async (req, res) => {
  try {
    const { alert_id, title, description, severity, investigation_notes } = req.body;

    if (!title || !severity) {
      return res.status(400).json({ success: false, message: 'Title and severity are required.' });
    }

    const [result] = await query(
      `INSERT INTO security_incidents (alert_id, title, description, severity, status, investigation_notes, created_at)
       VALUES (?, ?, ?, ?, 'OPEN', ?, NOW())`,
      [alert_id || null, title, description || '', severity, investigation_notes || 'Manual incident created by SOC Analyst.']
    );

    await logActivity(
      req.user.id,
      'INCIDENT_CREATE',
      `Incident created: [${severity}] ${title}`,
      req.clientIp
    );

    res.status(201).json({
      success: true,
      message: 'Security incident registered successfully.',
      incidentId: result.insertId
    });
  } catch (err) {
    console.error('[CREATE INCIDENT ERROR]', err.message);
    res.status(500).json({ success: false, message: 'Failed to create incident.' });
  }
});

/**
 * GET /api/admin/rules
 * Fetch all security rules
 */
router.get('/rules', async (req, res) => {
  try {
    const [rules] = await query('SELECT * FROM security_rules ORDER BY id ASC');
    res.json({ success: true, rules });
  } catch (err) {
    console.error('[GET RULES ERROR]', err.message);
    res.status(500).json({ success: false, message: 'Failed to fetch rules.' });
  }
});

/**
 * PUT /api/admin/rules/:id
 * Toggle rule enabled or update configuration
 */
router.put('/rules/:id', async (req, res) => {
  try {
    const ruleId = parseInt(req.params.id, 10);
    const { enabled, severity, description } = req.body;

    const updates = [];
    const params = [];

    if (enabled !== undefined) {
      updates.push('enabled = ?');
      params.push(enabled ? 1 : 0);
    }
    if (severity) {
      updates.push('severity = ?');
      params.push(severity);
    }
    if (description !== undefined) {
      updates.push('description = ?');
      params.push(description);
    }

    if (updates.length === 0) {
      return res.status(400).json({ success: false, message: 'No fields to update.' });
    }

    const sql = `UPDATE security_rules SET ${updates.join(', ')} WHERE id = ?`;
    params.push(ruleId);

    const [result] = await query(sql, params);

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Rule not found.' });
    }

    await logActivity(
      req.user.id,
      'RULE_UPDATE',
      `Security rule #${ruleId} modified by ${req.user.username}`,
      req.clientIp
    );

    res.json({ success: true, message: `Rule #${ruleId} updated successfully.` });
  } catch (err) {
    console.error('[UPDATE RULE ERROR]', err.message);
    res.status(500).json({ success: false, message: 'Failed to update rule.' });
  }
});

/**
 * POST /api/admin/rules
 * Add a new custom security rule
 */
router.post('/rules', async (req, res) => {
  try {
    const { rule_code, name, description, severity, category } = req.body;

    if (!rule_code || !name || !severity) {
      return res.status(400).json({ success: false, message: 'Rule Code, Name, and Severity are required.' });
    }

    const [result] = await query(
      'INSERT INTO security_rules (rule_code, name, description, severity, enabled, category, created_at) VALUES (?, ?, ?, ?, 1, ?, NOW())',
      [rule_code.toUpperCase(), name, description || '', severity, category || 'Custom']
    );

    await logActivity(
      req.user.id,
      'RULE_CREATE',
      `Created custom security rule: ${rule_code}`,
      req.clientIp
    );

    res.status(201).json({
      success: true,
      message: 'Custom rule created successfully.',
      ruleId: result.insertId
    });
  } catch (err) {
    console.error('[CREATE RULE ERROR]', err.message);
    res.status(500).json({ success: false, message: 'Failed to create rule (Rule Code may already exist).' });
  }
});

/**
 * GET /api/admin/resources
 * Fetch simulated cloud resources
 */
router.get('/resources', async (req, res) => {
  try {
    const [resources] = await query('SELECT * FROM cloud_resources ORDER BY updated_at DESC');
    res.json({ success: true, resources });
  } catch (err) {
    console.error('[GET RESOURCES ERROR]', err.message);
    res.status(500).json({ success: false, message: 'Failed to fetch cloud resources.' });
  }
});

/**
 * POST /api/admin/resources
 * Add simulated cloud resource
 */
router.post('/resources', async (req, res) => {
  try {
    const { resource_type, resource_name, status, config_json } = req.body;

    if (!resource_type || !resource_name) {
      return res.status(400).json({ success: false, message: 'Resource type and name are required.' });
    }

    let jsonStr = '{}';
    if (typeof config_json === 'object') {
      jsonStr = JSON.stringify(config_json);
    } else if (typeof config_json === 'string' && config_json.trim()) {
      jsonStr = config_json;
    }

    const [result] = await query(
      'INSERT INTO cloud_resources (resource_type, resource_name, status, config_json) VALUES (?, ?, ?, ?)',
      [resource_type, resource_name, status || 'SECURE', jsonStr]
    );

    await logActivity(
      req.user.id,
      'RESOURCE_ADD',
      `Added simulated cloud resource: [${resource_type}] ${resource_name}`,
      req.clientIp
    );

    res.status(201).json({
      success: true,
      message: 'Cloud resource created.',
      resourceId: result.insertId
    });
  } catch (err) {
    console.error('[ADD RESOURCE ERROR]', err.message);
    res.status(500).json({ success: false, message: 'Failed to add cloud resource.' });
  }
});

/**
 * PUT /api/admin/resources/:id
 * Update simulated cloud resource
 */
router.put('/resources/:id', async (req, res) => {
  try {
    const resourceId = parseInt(req.params.id, 10);
    const { resource_type, resource_name, status, config_json } = req.body;

    let jsonStr = '{}';
    if (typeof config_json === 'object') {
      jsonStr = JSON.stringify(config_json);
    } else if (typeof config_json === 'string') {
      jsonStr = config_json;
    }

    const [result] = await query(
      'UPDATE cloud_resources SET resource_type = ?, resource_name = ?, status = ?, config_json = ? WHERE id = ?',
      [resource_type, resource_name, status, jsonStr, resourceId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Resource not found.' });
    }

    await logActivity(
      req.user.id,
      'RESOURCE_UPDATE',
      `Updated cloud resource #${resourceId} (${resource_name})`,
      req.clientIp
    );

    res.json({ success: true, message: 'Cloud resource updated.' });
  } catch (err) {
    console.error('[UPDATE RESOURCE ERROR]', err.message);
    res.status(500).json({ success: false, message: 'Failed to update resource.' });
  }
});

/**
 * DELETE /api/admin/resources/:id
 * Delete simulated cloud resource
 */
router.delete('/resources/:id', async (req, res) => {
  try {
    const resourceId = parseInt(req.params.id, 10);

    const [result] = await query('DELETE FROM cloud_resources WHERE id = ?', [resourceId]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Resource not found.' });
    }

    await logActivity(
      req.user.id,
      'RESOURCE_DELETE',
      `Removed cloud resource #${resourceId}`,
      req.clientIp
    );

    res.json({ success: true, message: 'Cloud resource removed.' });
  } catch (err) {
    console.error('[DELETE RESOURCE ERROR]', err.message);
    res.status(500).json({ success: false, message: 'Failed to delete resource.' });
  }
});

/**
 * GET /api/admin/audit-logs
 * System-wide audit trail with user enrichment
 */
router.get('/audit-logs', async (req, res) => {
  try {
    const { action, limit = 200 } = req.query;
    let sql = `
      SELECT al.*, u.username, u.email, u.role
      FROM activity_log al
      LEFT JOIN users u ON al.user_id = u.id
      WHERE 1=1
    `;
    const params = [];

    if (action && action !== 'ALL') {
      sql += ' AND al.action = ?';
      params.push(action);
    }

    sql += ' ORDER BY al.created_at DESC LIMIT ?';
    params.push(parseInt(limit, 10) || 200);

    const [logs] = await query(sql, params);
    res.json({ success: true, logs });
  } catch (err) {
    console.error('[GET AUDIT LOGS ERROR]', err.message);
    res.status(500).json({ success: false, message: 'Failed to fetch audit logs.' });
  }
});

/**
 * GET /api/admin/settings
 * Fetch all system configuration settings
 */
router.get('/settings', async (req, res) => {
  try {
    const [rows] = await query('SELECT setting_key, setting_value, updated_at FROM app_settings');
    const settingsObj = {};
    rows.forEach(r => {
      settingsObj[r.setting_key] = r.setting_value;
    });
    res.json({ success: true, settings: settingsObj, raw: rows });
  } catch (err) {
    console.error('[GET SETTINGS ERROR]', err.message);
    res.status(500).json({ success: false, message: 'Failed to fetch settings.' });
  }
});

/**
 * PUT /api/admin/settings
 * Update system thresholds and parameters
 */
router.put('/settings', async (req, res) => {
  try {
    const settings = req.body; // e.g. { failed_login_threshold: '5', cpu_alert_threshold: '80' }

    for (const [key, value] of Object.entries(settings)) {
      await query(
        `INSERT INTO app_settings (setting_key, setting_value)
         VALUES (?, ?)
         ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value), updated_at = NOW()`,
        [key, String(value)]
      );
    }

    await logActivity(
      req.user.id,
      'SETTINGS_UPDATE',
      `SOC Configuration parameters updated by ${req.user.username}`,
      req.clientIp
    );

    res.json({ success: true, message: 'SOC Settings updated successfully.' });
  } catch (err) {
    console.error('[UPDATE SETTINGS ERROR]', err.message);
    res.status(500).json({ success: false, message: 'Failed to update settings.' });
  }
});

/**
 * POST /api/admin/run-security-scan
 * Trigger real-time evaluation scan via security engine
 */
router.post('/run-security-scan', async (req, res) => {
  try {
    console.log(`[SOC SCAN] Manual scan initiated by administrator: ${req.user.username}`);
    const scanResults = await securityEngine.triggerManualRun();

    await logActivity(
      req.user.id,
      'MANUAL_SOC_SCAN',
      `Manual security scan initiated. Results: ${scanResults.alertsCreated} alerts, ${scanResults.incidentsCreated} incidents.`,
      req.clientIp
    );

    res.json({
      success: true,
      message: 'Security evaluation scan completed.',
      results: scanResults
    });
  } catch (err) {
    console.error('[RUN SCAN ERROR]', err.message);
    res.status(500).json({ success: false, message: 'Failed to execute security scan.' });
  }
});

module.exports = router;
