/**
 * SecureCloud Monitor - Security Evaluation Engine
 * Evaluates rules against simulated cloud infrastructure and activity logs
 */

const { query } = require('../db');
const { logActivity } = require('../middleware/auth');
const {
  getEC2CPUUtilization
} = require('./cloudwatchService');

class SecurityEngine {
  constructor() {
    this.schedulerTimer = null;
    this.isRunning = false;
  }

  /**
   * Helper to fetch threshold settings from app_settings
   */
  async getSetting(key, defaultValue) {
    try {
      const [rows] = await query('SELECT setting_value FROM app_settings WHERE setting_key = ?', [key]);
      if (rows.length > 0) {
        return rows[0].setting_value;
      }
    } catch (err) {
      console.warn(`[ENGINE] Failed to read setting ${key}:`, err.message);
    }
    return defaultValue;
  }

  /**
   * Main evaluation runner
 */
async checkRealEC2CPU(cpuRule, cpuThreshold, summary) {
  if (!cpuRule || !process.env.AWS_EC2_INSTANCE_ID) {
    return;
  }

  try {
    const metric = await getEC2CPUUtilization(
      process.env.AWS_EC2_INSTANCE_ID
    );

    if (!metric) {
      console.log('[CLOUDWATCH] No EC2 CPU datapoints available.');
      return;
    }

    const currentCpu = parseFloat(metric.average);

    console.log(
      `[CLOUDWATCH] EC2 CPU: ${currentCpu.toFixed(2)}%`
    );

    if (currentCpu >= cpuThreshold) {
      const title =
        `High EC2 CPU Utilization: ${metric.instanceId}`;

      const description =
        `EC2 instance "${metric.instanceId}" has CPU utilization of ` +
        `${currentCpu.toFixed(2)}% (Threshold: ${cpuThreshold}%).`;

      const alertResult = await this.createAlertIfNew(
        cpuRule.id,
        title,
        description,
        cpuRule.severity
      );

      if (alertResult.created) {
        summary.alertsCreated++;

        if (alertResult.incidentId) {
          summary.incidentsCreated++;
        }

        summary.details.push(
          `Alert created for EC2 CPU ${metric.instanceId}`
        );
      }
    }
  } catch (error) {
    console.error(
      '[CLOUDWATCH] EC2 CPU check failed:',
      error.message
    );
  }
}
  async evaluateAllRules() {
    if (this.isRunning) {
      console.log('[ENGINE] Evaluation already in progress. Skipping cycle.');
      return { status: 'in_progress' };
    }

    this.isRunning = true;
    const summary = {
      timestamp: new Date().toISOString(),
      rulesEvaluated: 0,
      alertsCreated: 0,
      incidentsCreated: 0,
      details: []
    };

    try {
      // 1. Fetch enabled security rules
      const [rules] = await query('SELECT * FROM security_rules WHERE enabled = 1');
      summary.rulesEvaluated = rules.length;

      // 2. Fetch thresholds
      const cpuThreshold = parseFloat(await this.getSetting('cpu_alert_threshold', '85'));
      const failedLoginThreshold = parseInt(await this.getSetting('failed_login_threshold', '5'), 10);

      // 3. Evaluate Rule: RULE_FAILED_LOGINS
      const failedLoginRule = rules.find(r => r.rule_code === 'RULE_FAILED_LOGINS');
      if (failedLoginRule) {
        const [failedAttempts] = await query(
          `SELECT ip_address, COUNT(*) as fail_count, MAX(created_at) as last_attempt
           FROM activity_log
           WHERE action = 'AUTH_FAILED_LOGIN'
             AND created_at >= NOW() - INTERVAL 15 MINUTE
           GROUP BY ip_address
           HAVING fail_count >= ?`,
          [failedLoginThreshold]
        );

        for (const row of failedAttempts) {
          const title = `Brute Force Login Attack (${row.fail_count} attempts from ${row.ip_address})`;
          const description = `Security Engine detected ${row.fail_count} failed login attempts in the past 15 minutes originating from IP ${row.ip_address}. Threshold: ${failedLoginThreshold}.`;
          
          const alertResult = await this.createAlertIfNew(failedLoginRule.id, title, description, failedLoginRule.severity);
          if (alertResult.created) {
            summary.alertsCreated++;
            if (alertResult.incidentId) summary.incidentsCreated++;
            summary.details.push(`Alert created for Brute Force from ${row.ip_address}`);
          }
        }
      }

// Real AWS EC2 CPU check
const cpuRule = rules.find(r => r.rule_code === 'RULE_EC2_CPU_HIGH');
await this.checkRealEC2CPU(cpuRule, cpuThreshold, summary);

      // 4. Evaluate Cloud Resources rules
      const [resources] = await query('SELECT * FROM cloud_resources');

      for (const res of resources) {
        let config = {};
        try {
          config = typeof res.config_json === 'string' ? JSON.parse(res.config_json) : (res.config_json || {});
        } catch (e) {
          config = {};
        }

        // Rule: Public S3 Buckets
        const s3Rule = rules.find(r => r.rule_code === 'RULE_S3_PUBLIC');
        if (s3Rule && (res.resource_type.includes('S3') || res.resource_type.includes('Bucket'))) {
          if (config.is_public === true || config.public_policy === 'public-read' || config.acl === 'public-read') {
            const title = `Public S3 Bucket Detected: ${res.resource_name}`;
            const description = `Storage bucket "${res.resource_name}" has public read/write permissions enabled. Policy: ${config.public_policy || 'public'}.`;
            const alertResult = await this.createAlertIfNew(s3Rule.id, title, description, s3Rule.severity);
            if (alertResult.created) {
              summary.alertsCreated++;
              if (alertResult.incidentId) summary.incidentsCreated++;
              summary.details.push(`Alert created for S3 Bucket ${res.resource_name}`);
            }
          }
        }

        // Rule: Unencrypted Database
        const dbRule = rules.find(r => r.rule_code === 'RULE_UNENCRYPTED_DB');
        if (dbRule && (res.resource_type.includes('RDS') || res.resource_type.includes('DB'))) {
          if (config.storage_encrypted === false) {
            const title = `Unencrypted Database Storage: ${res.resource_name}`;
            const description = `RDS database instance "${res.resource_name}" has storage encryption at rest disabled. Fails enterprise compliance policies.`;
            const alertResult = await this.createAlertIfNew(dbRule.id, title, description, dbRule.severity);
            if (alertResult.created) {
              summary.alertsCreated++;
              if (alertResult.incidentId) summary.incidentsCreated++;
              summary.details.push(`Alert created for Unencrypted RDS ${res.resource_name}`);
            }
          }
        }

        // Rule: Open Security Group Ingress
        const sgRule = rules.find(r => r.rule_code === 'RULE_OPEN_SECURITY_GROUP');
        if (sgRule && (res.resource_type.includes('SecurityGroup') || res.resource_type.includes('SG'))) {
          const openPorts = config.open_ports || [];
          const hasDangerousPorts = openPorts.includes(22) || openPorts.includes(3306) || openPorts.includes(8080);
          if (config.cidr_ingress === '0.0.0.0/0' && hasDangerousPorts) {
            const title = `Open Ingress to Sensitive Ports: ${res.resource_name}`;
            const description = `Security Group "${res.resource_name}" allows 0.0.0.0/0 ingress on restricted ports [${openPorts.join(', ')}].`;
            const alertResult = await this.createAlertIfNew(sgRule.id, title, description, sgRule.severity);
            if (alertResult.created) {
              summary.alertsCreated++;
              if (alertResult.incidentId) summary.incidentsCreated++;
              summary.details.push(`Alert created for Open SG ${res.resource_name}`);
            }
          }
        }
      }

      console.log(`[ENGINE] Scan finished. Evaluated ${summary.rulesEvaluated} rules. Generated ${summary.alertsCreated} alerts, ${summary.incidentsCreated} incidents.`);
    } catch (err) {
      console.error('[ENGINE ERROR] Rule evaluation failed:', err.message);
      summary.error = err.message;
    } finally {
      this.isRunning = false;
    }

    return summary;
  }

  /**
   * Deduplicate and create alert, with automatic incident escalation for CRITICAL/HIGH
   */
  async createAlertIfNew(ruleId, title, description, severity) {
    try {
      // Check if open or acknowledged alert with same title already exists
      const [existing] = await query(
        `SELECT id FROM security_alerts 
         WHERE title = ? AND status IN ('OPEN', 'ACKNOWLEDGED')`,
        [title]
      );

      if (existing.length > 0) {
        return { created: false, existingId: existing[0].id };
      }

      // Insert new alert
      const [res] = await query(
        `INSERT INTO security_alerts (rule_id, title, description, severity, status, created_at)
         VALUES (?, ?, ?, ?, 'OPEN', NOW())`,
        [ruleId, title, description, severity]
      );

      const alertId = res.insertId;
      let incidentId = null;

      // Auto-escalate CRITICAL and HIGH severity alerts to Incidents
      if (severity === 'CRITICAL' || severity === 'HIGH') {
        const incidentTitle = `${severity} ALERT ESCALATION: ${title}`;
        const autoNote = `[${new Date().toISOString()}] Automated SOC Engine Escalation:\nAlert #${alertId} escalated due to ${severity} severity.\nInitial Rule: ${ruleId || 'N/A'}.\nRecommended triage: Review resource configuration and revoke exposed access.`;

        const [incRes] = await query(
          `INSERT INTO security_incidents (alert_id, title, description, severity, status, investigation_notes, created_at)
           VALUES (?, ?, ?, ?, 'OPEN', ?, NOW())`,
          [alertId, incidentTitle, description, severity, autoNote]
        );
        incidentId = incRes.insertId;
      }

      // Log activity
      await logActivity(
        null,
        'SECURITY_ENGINE_ALERT',
        `Automated alert generated: [${severity}] ${title} (Alert #${alertId}${incidentId ? `, Incident #${incidentId}` : ''})`,
        '127.0.0.1'
      );

      return { created: true, alertId, incidentId };
    } catch (err) {
      console.error('[ENGINE] Error creating alert:', err.message);
      return { created: false, error: err.message };
    }
  }

  /**
   * Start recurring background scheduler
   */
  startScheduler(intervalMs = 60000) {
    if (this.schedulerTimer) {
      clearInterval(this.schedulerTimer);
    }
    console.log(`[ENGINE] Starting security evaluation scheduler (interval: ${intervalMs / 1000}s)...`);
    
    // Initial run after 5s startup delay
    setTimeout(() => {
      this.evaluateAllRules().catch(console.error);
    }, 5000);

    this.schedulerTimer = setInterval(() => {
      this.evaluateAllRules().catch(console.error);
    }, intervalMs);
  }

  /**
   * Manual trigger via API
   */
  async triggerManualRun() {
    return this.evaluateAllRules();
  }
}

// Export singleton instance
const securityEngine = new SecurityEngine();
module.exports = securityEngine;
