/**
 * SecureCloud Monitor - User Dashboard & File Vault Routes
 * Strictly enforces user isolation (WHERE user_id = req.user.id)
 */

const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { query } = require('../db');
const { requireAuth, logActivity } = require('../middleware/auth');

// Apply requireAuth to all user routes
router.use(requireAuth);

// Ensure uploads folder exists
const uploadDir = path.join(__dirname, '..', 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Multer storage with cryptographically randomized filenames
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const randomHex = crypto.randomBytes(16).toString('hex');
    const safeExt = path.extname(file.originalname).toLowerCase();
    cb(null, `${randomHex}${safeExt}`);
  }
});

// Dangerous extensions blacklist
const FORBIDDEN_EXTENSIONS = [
  '.exe', '.bat', '.cmd', '.sh', '.bash', '.php', '.phtml',
  '.vbs', '.js', '.msi', '.dll', '.scr', '.ps1', '.jar', '.com'
];

// Multer upload instance with security validation
const upload = multer({
  storage: storage,
  limits: {
    fileSize: 50 * 1024 * 1024 // 50MB limit
  },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (FORBIDDEN_EXTENSIONS.includes(ext)) {
      return cb(new Error(`Security Alert: Upload of executable or script extension (${ext}) is blocked by policy.`));
    }
    cb(null, true);
  }
});

/**
 * POST /api/files
 * Securely upload a file to the user's encrypted vault
 */
router.post('/files', (req, res) => {
  upload.single('file')(req, res, async (err) => {
    if (err) {
      return res.status(400).json({
        success: false,
        message: err.message || 'File upload failed validation.'
      });
    }

    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: 'No file was provided in the upload request.'
      });
    }

    try {
      const filePath = req.file.path;

      // Calculate SHA-256 checksum for cryptographic integrity
      const fileBuffer = await fs.promises.readFile(filePath);
      const sha256Checksum = crypto.createHash('sha256').update(fileBuffer).digest('hex');

      // Insert file record into database
      const [result] = await query(
        `INSERT INTO files (user_id, original_name, stored_name, file_size, checksum, created_at)
         VALUES (?, ?, ?, ?, ?, NOW())`,
        [req.user.id, req.file.originalname, req.file.filename, req.file.size, sha256Checksum]
      );

      // Log activity
      await logActivity(
        req.user.id,
        'FILE_UPLOAD',
        `Uploaded file "${req.file.originalname}" (${(req.file.size / 1024).toFixed(1)} KB, SHA-256: ${sha256Checksum.substring(0, 12)}...)`,
        req.clientIp
      );

      res.status(201).json({
        success: true,
        message: 'File successfully uploaded and verified with SHA-256 integrity.',
        file: {
          id: result.insertId,
          original_name: req.file.originalname,
          file_size: req.file.size,
          checksum: sha256Checksum,
          created_at: new Date()
        }
      });
    } catch (dbErr) {
      // Clean up uploaded file if database insert fails
      if (req.file && fs.existsSync(req.file.path)) {
        await fs.promises.unlink(req.file.path).catch(() => {});
      }
      console.error('[FILE UPLOAD DB ERROR]', dbErr.message);
      res.status(500).json({
        success: false,
        message: 'Failed to record file metadata in database.'
      });
    }
  });
});

/**
 * GET /api/files
 * Fetch all files owned by authenticated user
 */
router.get('/files', async (req, res) => {
  try {
    const [files] = await query(
      `SELECT id, original_name, stored_name, file_size, checksum, created_at
       FROM files
       WHERE user_id = ?
       ORDER BY created_at DESC`,
      [req.user.id]
    );

    res.json({
      success: true,
      files
    });
  } catch (err) {
    console.error('[GET FILES ERROR]', err.message);
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve files.'
    });
  }
});

/**
 * GET /api/files/download/:id
 * Securely download file after verifying ownership
 */
router.get('/files/download/:id', async (req, res) => {
  try {
    const fileId = parseInt(req.params.id, 10);
    if (isNaN(fileId)) {
      return res.status(400).json({ success: false, message: 'Invalid file ID.' });
    }

    const [rows] = await query(
      'SELECT id, original_name, stored_name FROM files WHERE id = ? AND user_id = ?',
      [fileId, req.user.id]
    );

    if (rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'File not found or you do not have permission to access it.'
      });
    }

    const file = rows[0];
    const physicalPath = path.join(uploadDir, file.stored_name);

    if (!fs.existsSync(physicalPath)) {
      return res.status(404).json({
        success: false,
        message: 'Physical file not found on storage disk.'
      });
    }

    // Log download event
    await logActivity(
      req.user.id,
      'FILE_DOWNLOAD',
      `Downloaded file "${file.original_name}" (ID #${file.id})`,
      req.clientIp
    );

    res.download(physicalPath, file.original_name);
  } catch (err) {
    console.error('[DOWNLOAD FILE ERROR]', err.message);
    res.status(500).json({
      success: false,
      message: 'Error processing file download.'
    });
  }
});

/**
 * DELETE /api/files/:id
 * Remove file record and remove from disk
 */
router.delete('/files/:id', async (req, res) => {
  try {
    const fileId = parseInt(req.params.id, 10);
    if (isNaN(fileId)) {
      return res.status(400).json({ success: false, message: 'Invalid file ID.' });
    }

    const [rows] = await query(
      'SELECT id, original_name, stored_name FROM files WHERE id = ? AND user_id = ?',
      [fileId, req.user.id]
    );

    if (rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'File not found or permission denied.'
      });
    }

    const file = rows[0];
    const physicalPath = path.join(uploadDir, file.stored_name);

    // Delete record from DB
    await query('DELETE FROM files WHERE id = ? AND user_id = ?', [fileId, req.user.id]);

    // Delete physical file from disk
    if (fs.existsSync(physicalPath)) {
      await fs.promises.unlink(physicalPath).catch(err => {
        console.warn(`[FILE DELETE WARN] Failed to remove file from disk: ${err.message}`);
      });
    }

    // Log activity
    await logActivity(
      req.user.id,
      'FILE_DELETE',
      `Deleted file "${file.original_name}" (ID #${file.id})`,
      req.clientIp
    );

    res.json({
      success: true,
      message: `File "${file.original_name}" was permanently removed.`
    });
  } catch (err) {
    console.error('[DELETE FILE ERROR]', err.message);
    res.status(500).json({
      success: false,
      message: 'Error deleting file.'
    });
  }
});

/**
 * GET /api/activity
 * Get activity log for authenticated user
 */
router.get('/activity', async (req, res) => {
  try {
    const [activities] = await query(
      `SELECT id, action, details, ip_address, created_at
       FROM activity_log
       WHERE user_id = ?
       ORDER BY created_at DESC
       LIMIT 100`,
      [req.user.id]
    );

    res.json({
      success: true,
      activities
    });
  } catch (err) {
    console.error('[GET ACTIVITY ERROR]', err.message);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch activity logs.'
    });
  }
});

/**
 * GET /api/profile
 * Get user profile info and storage usage metrics
 */
router.get('/profile', async (req, res) => {
  try {
    const [fileStats] = await query(
      `SELECT COUNT(*) as total_files, COALESCE(SUM(file_size), 0) as total_bytes
       FROM files
       WHERE user_id = ?`,
      [req.user.id]
    );

    const [recentLogs] = await query(
      `SELECT action, details, created_at
       FROM activity_log
       WHERE user_id = ?
       ORDER BY created_at DESC
       LIMIT 5`,
      [req.user.id]
    );

    res.json({
      success: true,
      profile: {
        id: req.user.id,
        username: req.user.username,
        email: req.user.email,
        role: req.user.role,
        created_at: req.user.created_at,
        total_files: fileStats[0].total_files,
        total_bytes: fileStats[0].total_bytes,
        recent_activity: recentLogs
      }
    });
  } catch (err) {
    console.error('[GET PROFILE ERROR]', err.message);
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve profile data.'
    });
  }
});

/**
 * PUT /api/profile
 * Update profile details or password (strictly prevents role tampering)
 */
router.put('/profile', async (req, res) => {
  try {
    const { email, current_password, new_password } = req.body;

    // 1. If updating email
    if (email && email.trim() !== req.user.email) {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email.trim())) {
        return res.status(400).json({ success: false, message: 'Invalid email format.' });
      }

      // Check if email already taken
      const [existing] = await query(
        'SELECT id FROM users WHERE email = ? AND id != ?',
        [email.trim().toLowerCase(), req.user.id]
      );
      if (existing.length > 0) {
        return res.status(400).json({ success: false, message: 'This email is already in use.' });
      }

      await query('UPDATE users SET email = ? WHERE id = ?', [email.trim().toLowerCase(), req.user.id]);
      await logActivity(req.user.id, 'PROFILE_UPDATE', `Email changed to ${email.trim()}`, req.clientIp);
    }

    // 2. If updating password
    if (new_password) {
      if (!current_password) {
        return res.status(400).json({
          success: false,
          message: 'Current password is required to set a new password.'
        });
      }

      if (new_password.length < 6) {
        return res.status(400).json({
          success: false,
          message: 'New password must be at least 6 characters in length.'
        });
      }

      // Verify current password
      const [users] = await query('SELECT password FROM users WHERE id = ?', [req.user.id]);
      const valid = await bcrypt.compare(current_password, users[0].password);

      if (!valid) {
        return res.status(400).json({
          success: false,
          message: 'Current password does not match our records.'
        });
      }

      const newHash = await bcrypt.hash(new_password, 10);
      await query('UPDATE users SET password = ? WHERE id = ?', [newHash, req.user.id]);
      await logActivity(req.user.id, 'PASSWORD_CHANGE', 'User changed their password.', req.clientIp);
    }

    res.json({
      success: true,
      message: 'Profile updated successfully.'
    });
  } catch (err) {
    console.error('[UPDATE PROFILE ERROR]', err.message);
    res.status(500).json({
      success: false,
      message: 'Failed to update profile.'
    });
  }
});

module.exports = router;
