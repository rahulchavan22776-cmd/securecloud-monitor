/**
 * SecureCloud Monitor - Main Application Entrypoint
 * Framework: Express.js
 */

const express = require('express');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const { initializeDatabase, pool, dbConfig } = require('./db');
const securityEngine = require('./services/securityEngine');

// Import Route Handlers
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/user');
const adminRoutes = require('./routes/admin');

const app = express();
const PORT = process.env.PORT || 3000;

// Ensure upload storage directory exists
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// 1. Body Parsing Middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// 2. Session Configuration with MySQL Store & Fallback
let sessionStore;
try {
  sessionStore = new MySQLStore({
    clearExpired: true,
    checkExpirationInterval: 900000, // 15 mins
    expiration: 86400000,            // 1 day
    createDatabaseTable: true,
    schema: {
      tableName: 'sessions',
      columnNames: {
        session_id: 'session_id',
        expires: 'expires',
        data: 'data'
      }
    }
  }, pool);
} catch (err) {
  console.warn('[SESSION] MySQL session store initialization fallback to MemoryStore:', err.message);
}

app.use(session({
  key: 'securecloud_sid',
  secret: process.env.SESSION_SECRET || 'securecloud_monitor_secret_key_998877',
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24, // 24 hours
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production'
  }
}));

// 3. Security Headers Middleware
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

// 4. Serve Static Frontend Files
app.use(express.static(path.join(__dirname, 'public'), {
  extensions: ['html', 'htm']
}));

// 5. Mount API Routes
app.use('/api', authRoutes);
app.use('/api', userRoutes);
app.use('/api/admin', adminRoutes);

// 6. Root & Healthcheck
app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

// 7. Global Error Handler
app.use((err, req, res, next) => {
  console.error('[UNHANDLED ERROR]', err);
  const statusCode = err.status || 500;
  res.status(statusCode).json({
    success: false,
    message: err.message || 'Internal server error.'
  });
});

// 8. Server Bootstrap & Startup
async function startServer() {
  console.log('============================================================');
  console.log('       🛡️  SECURECLOUD MONITOR - SOC PLATFORM INITIALIZING   ');
  console.log('============================================================');

  // Initialize DB Connection and Schema
  const isDbReady = await initializeDatabase();

  app.listen(PORT, () => {
    console.log(`\n🚀 Server is running on: http://localhost:${PORT}`);
    console.log(`📡 SOC Dashboard Portal: http://localhost:${PORT}/admin-dashboard.html`);
    console.log(`👤 User Portal:          http://localhost:${PORT}/user-dashboard.html`);
    console.log(`🔑 Login Page:            http://localhost:${PORT}/login.html`);
    console.log(`------------------------------------------------------------`);
    console.log(`🔐 Default Admin Credentials:`);
    console.log(`   Username: admin`);
    console.log(`   Password: Admin@12345`);
    console.log(`------------------------------------------------------------`);

    if (isDbReady) {
      // Start background security rule evaluation engine (every 60s)
      securityEngine.startScheduler(60000);
    } else {
      console.warn('⚠️  Database not yet connected. Please start MySQL in XAMPP.');
    }
  });
}

startServer();

module.exports = app;
