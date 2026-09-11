/**
 * SecureCloud Monitor - Client Application Logic
 * Vanilla JavaScript (ES6 Fetch API)
 */

// Global State
let currentUser = null;

// ==========================================================================
// Toast Notification Engine
// ==========================================================================
function showToast(message, type = 'info') {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    container.className = 'toast-container';
    document.body.appendChild(container);
  }

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  
  const iconMap = {
    success: '🛡️',
    error: '⚠️',
    warning: '⚡',
    info: 'ℹ️'
  };

  toast.innerHTML = `
    <span style="font-size: 16px;">${iconMap[type] || 'ℹ️'}</span>
    <span style="flex: 1; font-size: 13px;">${message}</span>
  `;

  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(100%)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// ==========================================================================
// Standardized API Client Wrapper
// ==========================================================================
async function apiRequest(url, options = {}) {
  const defaultHeaders = {
    'Accept': 'application/json'
  };

  // Only set Content-Type to JSON if body is NOT FormData
  if (!(options.body instanceof FormData)) {
    defaultHeaders['Content-Type'] = 'application/json';
  }

  options.headers = { ...defaultHeaders, ...(options.headers || {}) };

  try {
    const response = await fetch(url, options);
    const data = await response.json().catch(() => ({}));

    if (response.status === 401) {
      // Unauthenticated session
      if (!window.location.pathname.endsWith('login.html') &&
          !window.location.pathname.endsWith('register.html') &&
          !window.location.pathname.endsWith('index.html') &&
          window.location.pathname !== '/') {
        window.location.href = '/login.html';
      }
      return { success: false, status: 401, message: 'Session expired or unauthenticated.' };
    }

    if (!response.ok) {
      return {
        success: false,
        status: response.status,
        message: data.message || `Request failed with status ${response.status}`
      };
    }

    return { success: true, status: response.status, ...data };
  } catch (err) {
    console.error(`[API ERROR] ${url}:`, err);
    return {
      success: false,
      status: 0,
      message: 'Network error or backend service unreachable. Please ensure MySQL and Node.js are running.'
    };
  }
}

// ==========================================================================
// Authentication State Management & Sidebar Population
// ==========================================================================
async function checkAuth(requiredRole = null) {
  const res = await apiRequest('/api/me');
  if (!res.success) {
    currentUser = null;
    if (requiredRole) {
      window.location.href = '/login.html';
    }
    return null;
  }

  currentUser = res.user;

  // Enforce admin requirement if needed
  if (requiredRole === 'admin' && currentUser.role !== 'admin') {
    showToast('Access denied. Administrator privileges required.', 'error');
    window.location.href = '/user-dashboard.html';
    return null;
  }

  updateSidebarUser();
  return currentUser;
}

function updateSidebarUser() {
  const userNameEl = document.getElementById('sidebar-user-name');
  const userRoleEl = document.getElementById('sidebar-user-role');
  const userAvatarEl = document.getElementById('sidebar-user-avatar');

  if (currentUser && userNameEl) {
    userNameEl.textContent = currentUser.username;
    if (userAvatarEl) {
      userAvatarEl.textContent = currentUser.username.substring(0, 2).toUpperCase();
    }
    if (userRoleEl) {
      userRoleEl.textContent = currentUser.role;
      userRoleEl.className = `user-role-badge role-${currentUser.role}`;
    }
  }
}

async function handleLogout() {
  const res = await apiRequest('/api/logout', { method: 'POST' });
  if (res.success) {
    showToast('Logged out successfully.', 'success');
    setTimeout(() => {
      window.location.href = '/login.html';
    }, 500);
  } else {
    showToast(res.message, 'error');
  }
}

// Format utilities
function formatDate(dateStr) {
  if (!dateStr) return 'N/A';
  const d = new Date(dateStr);
  return d.toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  });
}

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// ==========================================================================
// Page Initializers
// ==========================================================================

/**
 * 1. Login Page
 */
function initLoginPage() {
  const loginForm = document.getElementById('login-form');
  if (!loginForm) return;

  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const submitBtn = loginForm.querySelector('button[type="submit"]');
    submitBtn.disabled = true;
    submitBtn.textContent = 'Authenticating...';

    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    const res = await apiRequest('/api/login', {
      method: 'POST',
      body: JSON.stringify({ username, password })
    });

    if (res.success) {
      showToast('Authentication verified. Welcome back!', 'success');
      setTimeout(() => {
        if (res.user.role === 'admin') {
          window.location.href = '/admin-dashboard.html';
        } else {
          window.location.href = '/user-dashboard.html';
        }
      }, 600);
    } else {
      showToast(res.message, 'error');
      submitBtn.disabled = false;
      submitBtn.textContent = 'Authenticate & Sign In';
    }
  });

  // Demo credential click to fill
  const demoFillBtn = document.getElementById('btn-fill-demo');
  if (demoFillBtn) {
    demoFillBtn.addEventListener('click', () => {
      document.getElementById('username').value = 'admin';
      document.getElementById('password').value = 'Admin@12345';
      showToast('Populated default SOC Admin credentials.', 'info');
    });
  }
}

/**
 * 2. Register Page
 */
function initRegisterPage() {
  const regForm = document.getElementById('register-form');
  if (!regForm) return;

  regForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const submitBtn = regForm.querySelector('button[type="submit"]');
    submitBtn.disabled = true;
    submitBtn.textContent = 'Creating Account...';

    const username = document.getElementById('reg-username').value;
    const email = document.getElementById('reg-email').value;
    const password = document.getElementById('reg-password').value;
    const confirmPassword = document.getElementById('reg-confirm-password').value;

    if (password !== confirmPassword) {
      showToast('Passwords do not match.', 'error');
      submitBtn.disabled = false;
      submitBtn.textContent = 'Create Security Account';
      return;
    }

    const res = await apiRequest('/api/register', {
      method: 'POST',
      body: JSON.stringify({ username, email, password })
    });

    if (res.success) {
      showToast(res.message, 'success');
      setTimeout(() => {
        window.location.href = '/login.html';
      }, 1000);
    } else {
      showToast(res.message, 'error');
      submitBtn.disabled = false;
      submitBtn.textContent = 'Create Security Account';
    }
  });
}

/**
 * 3. User Dashboard
 */
async function initUserDashboard() {
  await checkAuth('user');

  const profileRes = await apiRequest('/api/profile');
  if (profileRes.success) {
    const p = profileRes.profile;
    const userFilesCountEl = document.getElementById('user-files-count');
    const userStorageEl = document.getElementById('user-storage-size');
    const userUsernameEl = document.getElementById('user-welcome-name');

    if (userFilesCountEl) userFilesCountEl.textContent = p.total_files;
    if (userStorageEl) userStorageEl.textContent = formatBytes(p.total_bytes);
    if (userUsernameEl) userUsernameEl.textContent = p.username;

    // Populate recent activity
    const activityList = document.getElementById('user-recent-activity');
    if (activityList && p.recent_activity) {
      if (p.recent_activity.length === 0) {
        activityList.innerHTML = '<tr><td colspan="3" style="text-align: center; color: var(--text-muted);">No activity recorded yet.</td></tr>';
      } else {
        activityList.innerHTML = p.recent_activity.map(act => `
          <tr>
            <td><span class="badge badge-low">${act.action}</span></td>
            <td>${act.details}</td>
            <td style="color: var(--text-muted); font-size: 12px;">${formatDate(act.created_at)}</td>
          </tr>
        `).join('');
      }
    }
  }

  // Load recent files
  const filesRes = await apiRequest('/api/files');
  const recentFilesTable = document.getElementById('user-recent-files');
  if (filesRes.success && recentFilesTable) {
    const files = filesRes.files.slice(0, 5);
    if (files.length === 0) {
      recentFilesTable.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-muted);">No files stored in vault yet.</td></tr>';
    } else {
      recentFilesTable.innerHTML = files.map(f => `
        <tr>
          <td><strong>${f.original_name}</strong></td>
          <td>${formatBytes(f.file_size)}</td>
          <td><span class="checksum-tag">${f.checksum.substring(0, 16)}...</span></td>
          <td>
            <a href="/api/files/download/${f.id}" class="btn btn-outline btn-sm">Download</a>
          </td>
        </tr>
      `).join('');
    }
  }
}

/**
 * 4. Files Vault Page
 */
async function initFilesPage() {
  await checkAuth('user');

  const fileInput = document.getElementById('file-upload-input');
  const dropzone = document.getElementById('file-dropzone');
  const filesTableBody = document.getElementById('files-table-body');
  const totalFilesEl = document.getElementById('files-count-badge');

  async function loadFiles() {
    const res = await apiRequest('/api/files');
    if (!res.success) return;

    if (totalFilesEl) totalFilesEl.textContent = `${res.files.length} Files`;

    if (res.files.length === 0) {
      filesTableBody.innerHTML = `
        <tr>
          <td colspan="5" style="text-align: center; padding: 40px; color: var(--text-muted);">
            Your encrypted file vault is empty. Drag and drop a file above to upload.
          </td>
        </tr>
      `;
      return;
    }

    filesTableBody.innerHTML = res.files.map(f => `
      <tr>
        <td>
          <div style="display: flex; align-items: center; gap: 10px;">
            <span style="font-size: 20px;">📄</span>
            <div>
              <div style="font-weight: 600; color: var(--text-primary);">${f.original_name}</div>
              <div style="font-size: 11px; color: var(--text-muted);">Stored as: ${f.stored_name}</div>
            </div>
          </div>
        </td>
        <td>${formatBytes(f.file_size)}</td>
        <td>
          <span class="checksum-tag" title="Full SHA-256: ${f.checksum}">
            SHA-256: ${f.checksum.substring(0, 14)}...
          </span>
        </td>
        <td>${formatDate(f.created_at)}</td>
        <td>
          <div style="display: flex; gap: 8px;">
            <a href="/api/files/download/${f.id}" class="btn btn-outline btn-sm">Download</a>
            <button class="btn btn-danger btn-sm" onclick="deleteFile(${f.id}, '${f.original_name}')">Delete</button>
          </div>
        </td>
      </tr>
    `).join('');
  }

  // Upload handler
  async function uploadFile(file) {
    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);

    showToast(`Uploading and computing SHA-256 checksum for "${file.name}"...`, 'info');

    const res = await apiRequest('/api/files', {
      method: 'POST',
      body: formData
    });

    if (res.success) {
      showToast(res.message, 'success');
      loadFiles();
    } else {
      showToast(res.message, 'error');
    }
  }

  if (dropzone && fileInput) {
    dropzone.addEventListener('click', () => fileInput.click());

    fileInput.addEventListener('change', (e) => {
      if (e.target.files.length > 0) {
        uploadFile(e.target.files[0]);
        fileInput.value = '';
      }
    });

    dropzone.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropzone.classList.add('dragover');
    });

    dropzone.addEventListener('dragleave', () => {
      dropzone.classList.remove('dragover');
    });

    dropzone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropzone.classList.remove('dragover');
      if (e.dataTransfer.files.length > 0) {
        uploadFile(e.dataTransfer.files[0]);
      }
    });
  }

  window.deleteFile = async function(fileId, filename) {
    if (!confirm(`Are you sure you want to permanently delete "${filename}"?`)) return;

    const res = await apiRequest(`/api/files/${fileId}`, { method: 'DELETE' });
    if (res.success) {
      showToast(res.message, 'success');
      loadFiles();
    } else {
      showToast(res.message, 'error');
    }
  };

  loadFiles();
}

/**
 * 5. Activity Logs Page
 */
async function initActivityPage() {
  await checkAuth('user');
  const activityTable = document.getElementById('user-activity-table');
  const actionFilter = document.getElementById('activity-filter');

  let allActivities = [];

  async function loadActivity() {
    const res = await apiRequest('/api/activity');
    if (!res.success) return;
    allActivities = res.activities;
    renderActivities();
  }

  function renderActivities() {
    const filter = actionFilter ? actionFilter.value : 'ALL';
    const filtered = filter === 'ALL' ? allActivities : allActivities.filter(a => a.action === filter);

    if (filtered.length === 0) {
      activityTable.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-muted);">No activity records found.</td></tr>';
      return;
    }

    activityTable.innerHTML = filtered.map(a => `
      <tr>
        <td><span class="badge badge-low">${a.action}</span></td>
        <td>${a.details}</td>
        <td><code style="color: var(--cyber-cyan);">${a.ip_address}</code></td>
        <td style="color: var(--text-muted);">${formatDate(a.created_at)}</td>
      </tr>
    `).join('');
  }

  if (actionFilter) {
    actionFilter.addEventListener('change', renderActivities);
  }

  loadActivity();
}

/**
 * 6. Profile Page
 */
async function initProfilePage() {
  const user = await checkAuth('user');
  if (!user) return;

  const usernameField = document.getElementById('prof-username');
  const emailField = document.getElementById('prof-email');
  const roleField = document.getElementById('prof-role');
  const createdField = document.getElementById('prof-created');

  if (usernameField) usernameField.value = user.username;
  if (emailField) emailField.value = user.email;
  if (roleField) roleField.value = user.role.toUpperCase();
  if (createdField) createdField.value = formatDate(user.created_at);

  const profileForm = document.getElementById('profile-form');
  if (profileForm) {
    profileForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const newEmail = emailField.value;
      const curPassword = document.getElementById('prof-current-pass').value;
      const newPassword = document.getElementById('prof-new-pass').value;

      const payload = {};
      if (newEmail && newEmail !== user.email) payload.email = newEmail;
      if (newPassword) {
        payload.current_password = curPassword;
        payload.new_password = newPassword;
      }

      if (Object.keys(payload).length === 0) {
        showToast('No modifications made to save.', 'info');
        return;
      }

      const res = await apiRequest('/api/profile', {
        method: 'PUT',
        body: JSON.stringify(payload)
      });

      if (res.success) {
        showToast(res.message, 'success');
        document.getElementById('prof-current-pass').value = '';
        document.getElementById('prof-new-pass').value = '';
      } else {
        showToast(res.message, 'error');
      }
    });
  }
}

/**
 * 7. Admin Dashboard (SOC Command Center)
 */
async function initAdminDashboard() {
  await checkAuth('admin');

  const scanBtn = document.getElementById('btn-manual-scan');
  if (scanBtn) {
    scanBtn.addEventListener('click', async () => {
      scanBtn.disabled = true;
      scanBtn.innerHTML = '🛡️ Running Security Engine...';
      showToast('Initiating cloud security evaluation...', 'info');

      const res = await apiRequest('/api/admin/run-security-scan', { method: 'POST' });
      if (res.success) {
        showToast(`Scan complete: ${res.results.alertsCreated} alerts created, ${res.results.incidentsCreated} incidents escalated.`, 'success');
        loadMetrics();
      } else {
        showToast(res.message, 'error');
      }
      scanBtn.disabled = false;
      scanBtn.innerHTML = '⚡ Run Security Scan';
    });
  }

  async function loadMetrics() {
    const res = await apiRequest('/api/admin/metrics');
    if (!res.success) return;

    const m = res.metrics;

    // Security Score Gauge
    const scoreVal = document.getElementById('metric-score-value');
    const scoreLevel = document.getElementById('metric-score-level');
    const scoreCircle = document.getElementById('score-circle-svg');

    if (scoreVal) scoreVal.textContent = m.securityScore;
    if (scoreLevel) {
      scoreLevel.textContent = m.postureLevel;
      scoreLevel.className = `badge ${m.securityScore >= 80 ? 'badge-secure' : m.securityScore >= 50 ? 'badge-high' : 'badge-critical'}`;
    }

    if (scoreCircle) {
      const offset = 314 - (314 * m.securityScore) / 100;
      scoreCircle.style.strokeDashoffset = offset;
      scoreCircle.style.stroke = m.securityScore >= 80 ? '#10B981' : m.securityScore >= 50 ? '#F59E0B' : '#EF4444';
    }

    // Counts
    const elMap = {
      'metric-open-alerts': m.alerts.open_alerts,
      'metric-crit-alerts': m.alerts.open_critical,
      'metric-high-alerts': m.alerts.open_high,
      'metric-incidents': m.incidents.open_incidents + m.incidents.investigating_incidents,
      'metric-resources': m.resources.total_resources,
      'metric-vulnerable-res': m.resources.vulnerable_resources,
      'metric-total-users': m.usersCount,
      'metric-active-rules': `${m.rules.active_rules} / ${m.rules.total_rules}`
    };

    for (const [id, val] of Object.entries(elMap)) {
      const el = document.getElementById(id);
      if (el) el.textContent = val !== undefined ? val : 0;
    }

    // Real AWS EC2 CPU from CloudWatch
    const ec2CpuValue = document.getElementById('metric-ec2-cpu');
    const ec2CpuInstance = document.getElementById('metric-ec2-instance');
    const ec2CpuUpdated = document.getElementById('metric-ec2-cpu-updated');

    if (m.ec2Cpu) {
      if (ec2CpuValue) {
        ec2CpuValue.textContent = `${Number(m.ec2Cpu.average).toFixed(2)}%`;
      }

      if (ec2CpuInstance) {
        ec2CpuInstance.textContent = m.ec2Cpu.instanceId;
      }

      if (ec2CpuUpdated) {
        ec2CpuUpdated.textContent = `Updated: ${formatDate(m.ec2Cpu.timestamp)}`;
      }
    }

    // Recent Alerts
    const alertsTable = document.getElementById('soc-recent-alerts');
    if (alertsTable && m.recentAlerts) {
      if (m.recentAlerts.length === 0) {
        alertsTable.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-muted);">No alerts logged.</td></tr>';
      } else {
        alertsTable.innerHTML = m.recentAlerts.map(a => `
          <tr>
            <td><span class="badge badge-${a.severity.toLowerCase()}">${a.severity}</span></td>
            <td><strong>${a.title}</strong></td>
            <td><span class="badge badge-${a.status.toLowerCase()}">${a.status}</span></td>
            <td style="color: var(--text-muted); font-size: 12px;">${formatDate(a.created_at)}</td>
          </tr>
        `).join('');
      }
    }

    // Recent Incidents
    const incidentsTable = document.getElementById('soc-recent-incidents');
    if (incidentsTable && m.recentIncidents) {
      if (m.recentIncidents.length === 0) {
        incidentsTable.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-muted);">No open incidents.</td></tr>';
      } else {
        incidentsTable.innerHTML = m.recentIncidents.map(i => `
          <tr>
            <td><span class="badge badge-${i.severity.toLowerCase()}">${i.severity}</span></td>
            <td><strong>${i.title}</strong></td>
            <td><span class="badge badge-${i.status.toLowerCase()}">${i.status}</span></td>
            <td style="color: var(--text-muted); font-size: 12px;">${formatDate(i.created_at)}</td>
          </tr>
        `).join('');
      }
    }
  }

  loadMetrics();
}

/**
 * 8. Alerts Management Page
 */
async function initAlertsPage() {
  await checkAuth('admin');

  const alertsTable = document.getElementById('admin-alerts-table');
  const statusFilter = document.getElementById('alert-status-filter');
  const severityFilter = document.getElementById('alert-severity-filter');

  async function loadAlerts() {
    const status = statusFilter ? statusFilter.value : 'ALL';
    const severity = severityFilter ? severityFilter.value : 'ALL';

    const res = await apiRequest(`/api/admin/alerts?status=${status}&severity=${severity}`);
    if (!res.success) return;

    if (res.alerts.length === 0) {
      alertsTable.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 30px;">No alerts match filter criteria.</td></tr>';
      return;
    }

    alertsTable.innerHTML = res.alerts.map(a => `
      <tr>
        <td>#${a.id}</td>
        <td><span class="badge badge-${a.severity.toLowerCase()}">${a.severity}</span></td>
        <td>
          <div style="font-weight: 600; color: var(--text-primary);">${a.title}</div>
          <div style="font-size: 12px; color: var(--text-muted);">${a.description || ''}</div>
          ${a.rule_code ? `<span class="checksum-tag" style="margin-top: 4px; display: inline-block;">${a.rule_code} (${a.category})</span>` : ''}
        </td>
        <td><span class="badge badge-${a.status.toLowerCase()}">${a.status}</span></td>
        <td>${formatDate(a.created_at)}</td>
        <td>
          <div style="display: flex; gap: 6px;">
            ${a.status === 'OPEN' ? `<button class="btn btn-outline btn-sm" onclick="updateAlertStatus(${a.id}, 'ACKNOWLEDGED')">Acknowledge</button>` : ''}
            ${a.status !== 'RESOLVED' ? `<button class="btn btn-primary btn-sm" onclick="updateAlertStatus(${a.id}, 'RESOLVED')">Resolve</button>` : `<span style="color: var(--cyber-emerald); font-size: 12px;">✓ Resolved</span>`}
          </div>
        </td>
      </tr>
    `).join('');
  }

  window.updateAlertStatus = async function(id, newStatus) {
    const res = await apiRequest(`/api/admin/alerts/${id}`, {
      method: 'PUT',
      body: JSON.stringify({ status: newStatus })
    });
    if (res.success) {
      showToast(res.message, 'success');
      loadAlerts();
    } else {
      showToast(res.message, 'error');
    }
  };

  // Manual Alert Modal
  const createAlertForm = document.getElementById('create-alert-form');
  if (createAlertForm) {
    createAlertForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const title = document.getElementById('modal-alert-title').value;
      const severity = document.getElementById('modal-alert-severity').value;
      const description = document.getElementById('modal-alert-desc').value;

      const res = await apiRequest('/api/admin/alerts', {
        method: 'POST',
        body: JSON.stringify({ title, severity, description })
      });

      if (res.success) {
        showToast(res.message, 'success');
        closeModal('modal-create-alert');
        createAlertForm.reset();
        loadAlerts();
      } else {
        showToast(res.message, 'error');
      }
    });
  }

  if (statusFilter) statusFilter.addEventListener('change', loadAlerts);
  if (severityFilter) severityFilter.addEventListener('change', loadAlerts);

  loadAlerts();
}

/**
 * 9. Incidents Management Page
 */
async function initIncidentsPage() {
  await checkAuth('admin');

  const incidentsTable = document.getElementById('admin-incidents-table');
  const statusFilter = document.getElementById('incident-status-filter');

  async function loadIncidents() {
    const status = statusFilter ? statusFilter.value : 'ALL';
    const res = await apiRequest(`/api/admin/incidents?status=${status}`);
    if (!res.success) return;

    if (res.incidents.length === 0) {
      incidentsTable.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 30px;">No incidents recorded.</td></tr>';
      return;
    }

    incidentsTable.innerHTML = res.incidents.map(i => `
      <tr>
        <td>#${i.id}</td>
        <td><span class="badge badge-${i.severity.toLowerCase()}">${i.severity}</span></td>
        <td>
          <div style="font-weight: 600; color: var(--text-primary);">${i.title}</div>
          <div style="font-size: 12px; color: var(--text-muted);">${i.description || ''}</div>
        </td>
        <td><span class="badge badge-${i.status.toLowerCase()}">${i.status}</span></td>
        <td>
          <div style="font-size: 12px; max-width: 300px; white-space: pre-wrap; color: var(--text-secondary);">${i.investigation_notes || 'No notes.'}</div>
        </td>
        <td>
          <button class="btn btn-outline btn-sm" onclick="openIncidentModal(${i.id}, '${i.status}', \`${(i.investigation_notes || '').replace(/`/g, '\\`')}\`)">
            Triage & Notes
          </button>
        </td>
      </tr>
    `).join('');
  }

  window.openIncidentModal = function(id, currentStatus, notes) {
    document.getElementById('edit-incident-id').value = id;
    document.getElementById('edit-incident-status').value = currentStatus;
    document.getElementById('edit-incident-notes').value = notes;
    openModal('modal-edit-incident');
  };

  const editIncidentForm = document.getElementById('edit-incident-form');
  if (editIncidentForm) {
    editIncidentForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const id = document.getElementById('edit-incident-id').value;
      const status = document.getElementById('edit-incident-status').value;
      const investigation_notes = document.getElementById('edit-incident-notes').value;

      const res = await apiRequest(`/api/admin/incidents/${id}`, {
        method: 'PUT',
        body: JSON.stringify({ status, investigation_notes })
      });

      if (res.success) {
        showToast(res.message, 'success');
        closeModal('modal-edit-incident');
        loadIncidents();
      } else {
        showToast(res.message, 'error');
      }
    });
  }

  if (statusFilter) statusFilter.addEventListener('change', loadIncidents);
  loadIncidents();
}

/**
 * 10. Security Rules Management Page
 */
async function initRulesPage() {
  await checkAuth('admin');

  const rulesTable = document.getElementById('admin-rules-table');

  async function loadRules() {
    const res = await apiRequest('/api/admin/rules');
    if (!res.success) return;

    rulesTable.innerHTML = res.rules.map(r => `
      <tr>
        <td><code style="color: var(--cyber-cyan); font-weight: 600;">${r.rule_code}</code></td>
        <td>
          <div style="font-weight: 600; color: var(--text-primary);">${r.name}</div>
          <div style="font-size: 12px; color: var(--text-muted);">${r.description}</div>
        </td>
        <td><span class="badge badge-low">${r.category}</span></td>
        <td><span class="badge badge-${r.severity.toLowerCase()}">${r.severity}</span></td>
        <td>
          <label class="switch">
            <input type="checkbox" ${r.enabled ? 'checked' : ''} onchange="toggleRule(${r.id}, this.checked)">
            <span class="slider"></span>
          </label>
        </td>
      </tr>
    `).join('');
  }

  window.toggleRule = async function(ruleId, isEnabled) {
    const res = await apiRequest(`/api/admin/rules/${ruleId}`, {
      method: 'PUT',
      body: JSON.stringify({ enabled: isEnabled })
    });

    if (res.success) {
      showToast(res.message, 'success');
    } else {
      showToast(res.message, 'error');
      loadRules();
    }
  };

  const createRuleForm = document.getElementById('create-rule-form');
  if (createRuleForm) {
    createRuleForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const rule_code = document.getElementById('modal-rule-code').value;
      const name = document.getElementById('modal-rule-name').value;
      const category = document.getElementById('modal-rule-cat').value;
      const severity = document.getElementById('modal-rule-sev').value;
      const description = document.getElementById('modal-rule-desc').value;

      const res = await apiRequest('/api/admin/rules', {
        method: 'POST',
        body: JSON.stringify({ rule_code, name, category, severity, description })
      });

      if (res.success) {
        showToast(res.message, 'success');
        closeModal('modal-create-rule');
        createRuleForm.reset();
        loadRules();
      } else {
        showToast(res.message, 'error');
      }
    });
  }

  loadRules();
}

/**
 * 11. Cloud Resources Management Page
 */
async function initResourcesPage() {
  await checkAuth('admin');

  const resTable = document.getElementById('admin-resources-table');

  async function loadResources() {
    const res = await apiRequest('/api/admin/resources');
    if (!res.success) return;

    if (res.resources.length === 0) {
      resTable.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 30px;">No cloud resources configured.</td></tr>';
      return;
    }

    resTable.innerHTML = res.resources.map(r => {
      let configStr = '';
      try {
        configStr = JSON.stringify(typeof r.config_json === 'string' ? JSON.parse(r.config_json) : r.config_json, null, 2);
      } catch (e) {
        configStr = r.config_json;
      }

      return `
        <tr>
          <td><span class="badge badge-low">${r.resource_type}</span></td>
          <td><strong>${r.resource_name}</strong></td>
          <td><span class="badge badge-${r.status === 'SECURE' || r.status === 'ACTIVE' ? 'secure' : 'critical'}">${r.status}</span></td>
          <td>
            <pre style="background: rgba(0,0,0,0.4); padding: 8px; border-radius: 4px; font-size: 11px; max-height: 80px; overflow-y: auto;"><code>${configStr}</code></pre>
          </td>
          <td>
            <button class="btn btn-danger btn-sm" onclick="deleteResource(${r.id})">Delete</button>
          </td>
        </tr>
      `;
    }).join('');
  }

  window.deleteResource = async function(id) {
    if (!confirm('Are you sure you want to delete this simulated cloud resource?')) return;
    const res = await apiRequest(`/api/admin/resources/${id}`, { method: 'DELETE' });
    if (res.success) {
      showToast(res.message, 'success');
      loadResources();
    } else {
      showToast(res.message, 'error');
    }
  };

  const createResForm = document.getElementById('create-resource-form');
  if (createResForm) {
    createResForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const resource_type = document.getElementById('modal-res-type').value;
      const resource_name = document.getElementById('modal-res-name').value;
      const status = document.getElementById('modal-res-status').value;
      const config_json = document.getElementById('modal-res-config').value;

      const res = await apiRequest('/api/admin/resources', {
        method: 'POST',
        body: JSON.stringify({ resource_type, resource_name, status, config_json })
      });

      if (res.success) {
        showToast(res.message, 'success');
        closeModal('modal-create-resource');
        createResForm.reset();
        loadResources();
      } else {
        showToast(res.message, 'error');
      }
    });
  }

  loadResources();
}

/**
 * 12. Audit Logs Page
 */
async function initAuditLogsPage() {
  await checkAuth('admin');

  const auditTable = document.getElementById('admin-audit-table');
  const actionFilter = document.getElementById('audit-action-filter');
  const exportBtn = document.getElementById('btn-export-audit');

  let logsData = [];

  async function loadLogs() {
    const action = actionFilter ? actionFilter.value : 'ALL';
    const res = await apiRequest(`/api/admin/audit-logs?action=${action}`);
    if (!res.success) return;

    logsData = res.logs;

    if (logsData.length === 0) {
      auditTable.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 30px;">No audit log records found.</td></tr>';
      return;
    }

    auditTable.innerHTML = logsData.map(l => `
      <tr>
        <td><span class="badge badge-low">${l.action}</span></td>
        <td>${l.username ? `<strong>${l.username}</strong> (${l.role})` : '<span style="color: var(--text-muted);">SYSTEM / GUEST</span>'}</td>
        <td>${l.details}</td>
        <td><code style="color: var(--cyber-cyan);">${l.ip_address}</code></td>
        <td style="color: var(--text-muted);">${formatDate(l.created_at)}</td>
      </tr>
    `).join('');
  }

  if (actionFilter) actionFilter.addEventListener('change', loadLogs);

  if (exportBtn) {
    exportBtn.addEventListener('click', () => {
      if (logsData.length === 0) {
        showToast('No logs to export.', 'info');
        return;
      }

      let csv = 'ID,Action,User,Details,IP_Address,Timestamp\n';
      logsData.forEach(l => {
        const line = [
          l.id,
          `"${l.action}"`,
          `"${l.username || 'SYSTEM'}"`,
          `"${(l.details || '').replace(/"/g, '""')}"`,
          `"${l.ip_address}"`,
          `"${l.created_at}"`
        ].join(',');
        csv += line + '\n';
      });

      const blob = new Blob([csv], { type: 'text/csv' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `securecloud_audit_export_${Date.now()}.csv`;
      a.click();
      window.URL.revokeObjectURL(url);
      showToast('Audit log export generated.', 'success');
    });
  }

  loadLogs();
}

/**
 * 13. Admin Settings Page
 */
async function initAdminSettingsPage() {
  await checkAuth('admin');

  const settingsForm = document.getElementById('admin-settings-form');

  async function loadSettings() {
    const res = await apiRequest('/api/admin/settings');
    if (!res.success) return;

    const s = res.settings;
    if (document.getElementById('setting-login-threshold')) {
      document.getElementById('setting-login-threshold').value = s.failed_login_threshold || '5';
    }
    if (document.getElementById('setting-cpu-threshold')) {
      document.getElementById('setting-cpu-threshold').value = s.cpu_alert_threshold || '85';
    }
    if (document.getElementById('setting-scan-interval')) {
      document.getElementById('setting-scan-interval').value = s.scan_interval_seconds || '60';
    }
    if (document.getElementById('setting-soc-email')) {
      document.getElementById('setting-soc-email').value = s.soc_alert_notification_email || '';
    }
    if (document.getElementById('setting-banner-msg')) {
      document.getElementById('setting-banner-msg').value = s.system_banner_message || '';
    }
  }

  if (settingsForm) {
    settingsForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const payload = {
        failed_login_threshold: document.getElementById('setting-login-threshold').value,
        cpu_alert_threshold: document.getElementById('setting-cpu-threshold').value,
        scan_interval_seconds: document.getElementById('setting-scan-interval').value,
        soc_alert_notification_email: document.getElementById('setting-soc-email').value,
        system_banner_message: document.getElementById('setting-banner-msg').value
      };

      const res = await apiRequest('/api/admin/settings', {
        method: 'PUT',
        body: JSON.stringify(payload)
      });

      if (res.success) {
        showToast(res.message, 'success');
      } else {
        showToast(res.message, 'error');
      }
    });
  }

  loadSettings();
}

// Modal Dialog Helpers
function openModal(id) {
  const modal = document.getElementById(id);
  if (modal) modal.classList.add('active');
}

function closeModal(id) {
  const modal = document.getElementById(id);
  if (modal) modal.classList.remove('active');
}

// Attach Global Handlers
window.openModal = openModal;
window.closeModal = closeModal;
window.handleLogout = handleLogout;
