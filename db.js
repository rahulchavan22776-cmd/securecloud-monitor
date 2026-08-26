/**
 * SecureCloud Monitor - Database Connection & Initialization Module
 * Technology: mysql2/promise Connection Pool
 */

const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const dbConfig = {
  host: process.env.DB_HOST || '127.0.0.1',
  port: parseInt(process.env.DB_PORT, 10) || 3306,
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'securecloud_monitor',
  waitForConnections: true,
  connectionLimit: 15,
  queueLimit: 0,
  enableKeepAlive: true,
  keepAliveInitialDelay: 0,
  multipleStatements: true
};

// Global pool instance
let pool;

try {
  pool = mysql.createPool(dbConfig);
} catch (err) {
  console.error('CRITICAL: Failed to create MySQL pool instance:', err.message);
}

/**
 * Execute parameterized query with automatic connection management
 * @param {string} sql - SQL query with placeholder ?
 * @param {Array} params - Array of parameters
 * @returns {Promise<[Array, Object]>}
 */
async function query(sql, params = []) {
  if (!pool) {
    throw new Error('Database connection pool is not initialized. Ensure MySQL is running on XAMPP.');
  }
  return pool.query(sql, params);
}

/**
 * Acquire a connection from the pool for transactions
 */
async function getConnection() {
  if (!pool) {
    throw new Error('Database connection pool is not initialized.');
  }
  return pool.getConnection();
}

/**
 * Verify database connectivity and automatically bootstrap schema & default admin if missing
 */
async function initializeDatabase() {
  console.log('[DB] Checking MySQL connection and database schema...');

  let serverConn;
  try {
    // 1. Check connection to MySQL Server (independent of whether database exists)
    serverConn = await mysql.createConnection({
      host: dbConfig.host,
      port: dbConfig.port,
      user: dbConfig.user,
      password: dbConfig.password,
      multipleStatements: true
    });

    // Create database if not exists
    await serverConn.query(
      `CREATE DATABASE IF NOT EXISTS \`${dbConfig.database}\` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;`
    );
    await serverConn.end();

    // 2. Test pool connection to target database
    const conn = await pool.getConnection();
    console.log(`[DB] Successfully connected to MySQL database: ${dbConfig.database} @ ${dbConfig.host}:${dbConfig.port}`);

    // Check if tables exist
    const [tables] = await conn.query('SHOW TABLES LIKE "users"');
    if (tables.length === 0) {
      console.log('[DB] Tables missing. Bootstrapping database from schema.sql...');
      const schemaPath = path.join(__dirname, 'database', 'schema.sql');
      if (fs.existsSync(schemaPath)) {
        const schemaSql = fs.readFileSync(schemaPath, 'utf8');
        await conn.query(schemaSql);
        console.log('[DB] Database schema and initial seed data applied successfully.');
      }
    }

    // 3. Guarantee Admin Account with valid bcrypt hash for 'Admin@12345'
    const [adminRows] = await conn.query('SELECT id, password FROM users WHERE username = "admin"');
    const adminPasswordHash = await bcrypt.hash('Admin@12345', 10);

    if (adminRows.length === 0) {
      await conn.query(
        'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
        ['admin', 'admin@securecloud.local', adminPasswordHash, 'admin']
      );
      console.log('[DB] Seeded default administrator account: admin / Admin@12345');
    } else {
      // Ensure password hash matches bcrypt 'Admin@12345' if default was unhashed or corrupted
      const isMatch = await bcrypt.compare('Admin@12345', adminRows[0].password);
      if (!isMatch) {
        await conn.query('UPDATE users SET password = ? WHERE id = ?', [adminPasswordHash, adminRows[0].id]);
        console.log('[DB] Updated admin password hash to match default credentials.');
      }
    }

    conn.release();
    return true;
  } catch (err) {
    if (serverConn) {
      try { await serverConn.end(); } catch (e) {}
    }
    console.error('------------------------------------------------------------');
    console.error('[DB ERROR] Could not connect to MySQL database.');
    console.error(`Target: ${dbConfig.user}@${dbConfig.host}:${dbConfig.port}/${dbConfig.database}`);
    console.error('Details:', err.message);
    console.error('TIP: Make sure XAMPP MySQL module is started on port ' + dbConfig.port);
    console.error('------------------------------------------------------------');
    return false;
  }
}

module.exports = {
  pool,
  query,
  getConnection,
  initializeDatabase,
  dbConfig
};
