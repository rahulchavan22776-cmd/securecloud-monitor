/**
 * SecureCloud Monitor - Authentication API Routes
 */

const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const { query } = require('../db');
const { requireAuth, logActivity, getClientIp } = require('../middleware/auth');

/**
 * POST /api/register
 * Create a standard user account (role is strictly enforced as 'user')
 */
router.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const clientIp = getClientIp(req);

    // Validation
    if (!username || !email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Username, email, and password are required.'
      });
    }

    if (username.length < 3 || username.length > 50) {
      return res.status(400).json({
        success: false,
        message: 'Username must be between 3 and 50 characters.'
      });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        message: 'Please provide a valid email address.'
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 6 characters in length.'
      });
    }

    // Check for existing username or email
    const [existing] = await query(
      'SELECT id, username, email FROM users WHERE username = ? OR email = ?',
      [username, email]
    );

    if (existing.length > 0) {
      const match = existing[0];
      const field = match.username.toLowerCase() === username.toLowerCase() ? 'Username' : 'Email';
      return res.status(400).json({
        success: false,
        message: `${field} is already registered. Please choose another.`
      });
    }

    // Hash password with 10 salt rounds
    const hashedPassword = await bcrypt.hash(password, 10);

    // Strictly enforce role = 'user'
    const [result] = await query(
      'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, "user")',
      [username.trim(), email.trim().toLowerCase(), hashedPassword]
    );

    const newUserId = result.insertId;

    // Log registration activity
    await logActivity(
      newUserId,
      'USER_REGISTER',
      `User account created: ${username} (${email})`,
      clientIp
    );

    res.status(201).json({
      success: true,
      message: 'Account registered successfully! You can now log in.'
    });
  } catch (err) {
    console.error('[REGISTER ERROR]', err.message);
    res.status(500).json({
      success: false,
      message: 'Server error during registration. Please try again.'
    });
  }
});

/**
 * POST /api/login
 * Authenticate user, regenerate session, log security audit
 */
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const clientIp = getClientIp(req);

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: 'Username/Email and password are required.'
      });
    }

    // Lookup user by username OR email
    const [users] = await query(
      'SELECT id, username, email, password, role FROM users WHERE username = ? OR email = ?',
      [username.trim(), username.trim().toLowerCase()]
    );

    if (users.length === 0) {
      // Log failed login attempt for threat monitoring
      await logActivity(
        null,
        'AUTH_FAILED_LOGIN',
        `Failed login attempt for unknown user: ${username}`,
        clientIp
      );

      return res.status(401).json({
        success: false,
        message: 'Invalid credentials. Access denied.'
      });
    }

    const user = users[0];

    // Timing-safe password verification
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      // Log failed login attempt against user
      await logActivity(
        user.id,
        'AUTH_FAILED_LOGIN',
        `Failed password verification for user: ${user.username}`,
        clientIp
      );

      return res.status(401).json({
        success: false,
        message: 'Invalid credentials. Access denied.'
      });
    }

    // Regenerate session to prevent session fixation
    req.session.regenerate(async (err) => {
      if (err) {
        console.error('[SESSION REGEN ERROR]', err);
        return res.status(500).json({
          success: false,
          message: 'Failed to establish secure session.'
        });
      }

      req.session.userId = user.id;
      req.session.userRole = user.role;

      // Log successful login
      await logActivity(
        user.id,
        'AUTH_LOGIN_SUCCESS',
        `User ${user.username} successfully logged in as ${user.role}`,
        clientIp
      );

      res.json({
        success: true,
        message: 'Authentication successful.',
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          role: user.role
        }
      });
    });
  } catch (err) {
    console.error('[LOGIN ERROR]', err.message);
    res.status(500).json({
      success: false,
      message: 'Server error during login authentication.'
    });
  }
});

/**
 * POST /api/logout
 * Destroy session and clear authentication cookie
 */
router.post('/logout', async (req, res) => {
  try {
    const clientIp = getClientIp(req);
    const userId = req.session ? req.session.userId : null;

    if (userId) {
      await logActivity(
        userId,
        'AUTH_LOGOUT',
        'User logged out from session.',
        clientIp
      );
    }

    if (req.session) {
      req.session.destroy((err) => {
        if (err) {
          console.error('[LOGOUT ERROR]', err);
        }
        res.clearCookie('connect.sid');
        return res.json({
          success: true,
          message: 'Logged out successfully.'
        });
      });
    } else {
      res.json({
        success: true,
        message: 'Logged out successfully.'
      });
    }
  } catch (err) {
    console.error('[LOGOUT ERROR]', err.message);
    res.status(500).json({
      success: false,
      message: 'Error during logout process.'
    });
  }
});

/**
 * GET /api/me
 * Fetch authenticated user profile details
 */
router.get('/me', requireAuth, (req, res) => {
  res.json({
    success: true,
    user: {
      id: req.user.id,
      username: req.user.username,
      email: req.user.email,
      role: req.user.role,
      created_at: req.user.created_at
    }
  });
});

module.exports = router;
