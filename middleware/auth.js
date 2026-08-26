/**
 * SecureCloud Monitor - Authentication & Authorization Middleware
 */

const { query } = require('../db');

/**
 * Get client IP address helper
 */
function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    return forwarded.split(',')[0].trim();
  }
  return req.socket ? req.socket.remoteAddress : '127.0.0.1';
}

/**
 * Global audit log activity helper
 */
async function logActivity(userId, action, details, ipAddress = '127.0.0.1') {
  try {
    await query(
      'INSERT INTO activity_log (user_id, action, details, ip_address) VALUES (?, ?, ?, ?)',
      [userId || null, action, details || '', ipAddress]
    );
  } catch (err) {
    console.error('[ACTIVITY LOG ERROR]', err.message);
  }
}

/**
 * Middleware: Enforce active authenticated user session verified against DB
 */
async function requireAuth(req, res, next) {
  try {
    if (!req.session || !req.session.userId) {
      if (req.accepts('html') && !req.xhr && !req.path.startsWith('/api/')) {
        return res.redirect('/login.html');
      }
      return res.status(401).json({
        success: false,
        message: 'Authentication required. Please log in to access this resource.'
      });
    }

    // Verify session user directly against database to prevent stale session attacks
    const [users] = await query(
      'SELECT id, username, email, role, created_at FROM users WHERE id = ?',
      [req.session.userId]
    );

    if (users.length === 0) {
      // User was deleted or deactivated
      req.session.destroy(() => {});
      if (req.accepts('html') && !req.xhr && !req.path.startsWith('/api/')) {
        return res.redirect('/login.html');
      }
      return res.status(401).json({
        success: false,
        message: 'Session invalid. User account no longer exists.'
      });
    }

    req.user = users[0];
    req.clientIp = getClientIp(req);
    next();
  } catch (err) {
    console.error('[AUTH MIDDLEWARE ERROR]', err.message);
    res.status(500).json({
      success: false,
      message: 'Internal server error during authentication verification.'
    });
  }
}

/**
 * Middleware: Enforce Administrator role
 */
async function requireAdmin(req, res, next) {
  try {
    // requireAuth should be invoked first or we ensure req.user exists
    if (!req.user) {
      return requireAuth(req, res, () => {
        if (req.user && req.user.role === 'admin') {
          return next();
        }
        if (req.accepts('html') && !req.xhr && !req.path.startsWith('/api/')) {
          return res.redirect('/user-dashboard.html');
        }
        return res.status(403).json({
          success: false,
          message: 'Access denied: Administrator privileges required.'
        });
      });
    }

    if (req.user.role !== 'admin') {
      if (req.accepts('html') && !req.xhr && !req.path.startsWith('/api/')) {
        return res.redirect('/user-dashboard.html');
      }
      return res.status(403).json({
        success: false,
        message: 'Access denied: Administrator privileges required.'
      });
    }

    next();
  } catch (err) {
    console.error('[ADMIN AUTH ERROR]', err.message);
    res.status(500).json({
      success: false,
      message: 'Internal server error during authorization verification.'
    });
  }
}

module.exports = {
  requireAuth,
  requireAdmin,
  logActivity,
  getClientIp
};
