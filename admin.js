/**
 * admin.js
 * Complete Admin Dashboard interface and server-side handlers.
 * Includes authentication, session management, CSRF validation,
 * CRUD booking management, analytics, shortcuts, and CSV export.
 */

const express = require('express');
const crypto = require('crypto');
const router = express.Router();

// Configuration from environment variables
const ADMIN_USER = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASSWORD || 'HoustonRoofing2026!';
const SESSION_SECRET = process.env.SESSION_SECRET || 'houston-roofing-admin-secret-key-2026';
const COOKIE_NAME = 'hrc_admin_token';

// In-memory brute force protection
const loginAttempts = new Map(); // ip -> { count, lastAttempt }

function isRateLimited(ip) {
  const record = loginAttempts.get(ip);
  if (!record) return false;
  // Reset if more than 15 minutes have passed
  if (Date.now() - record.lastAttempt > 15 * 60 * 1000) {
    loginAttempts.delete(ip);
    return false;
  }
  return record.count >= 5;
}

function recordFailedAttempt(ip) {
  const record = loginAttempts.get(ip) || { count: 0, lastAttempt: Date.now() };
  record.count += 1;
  record.lastAttempt = Date.now();
  loginAttempts.set(ip, record);
}

function clearAttempts(ip) {
  loginAttempts.delete(ip);
}

// Session signing and verification
function createToken(payload) {
  const data = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto
    .createHmac('sha256', SESSION_SECRET)
    .update(data)
    .digest('base64url');
  return `${data}.${signature}`;
}

function verifyToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [data, signature] = parts;
  const expectedSig = crypto
    .createHmac('sha256', SESSION_SECRET)
    .update(data)
    .digest('base64url');

  try {
    const a = Buffer.from(signature);
    const b = Buffer.from(expectedSig);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return null;
    }
    const payload = JSON.parse(Buffer.from(data, 'base64url').toString('utf8'));
    if (payload.exp && payload.exp < Date.now()) {
      return null;
    }
    return payload;
  } catch (err) {
    return null;
  }
}

// Timing-safe string comparison
function safeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) {
    // Pad to same length to prevent timing leaks on length
    const dummy = Buffer.alloc(bufB.length);
    crypto.timingSafeEqual(bufB, dummy);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

// Authentication middleware
function requireAuth(req, res, next) {
  const token = req.cookies && req.cookies[COOKIE_NAME];
  const session = verifyToken(token);
  if (!session) {
    if (req.path.startsWith('/api/')) {
      return res.status(401).json({ error: 'Unauthorized: Session expired or invalid' });
    }
    return res.redirect('/admin/login');
  }
  req.adminSession = session;
  next();
}

// CSRF check for state-changing requests
function requireCsrf(req, res, next) {
  const csrfHeader = req.headers['x-csrf-token'];
  const csrfBody = req.body && req.body._csrf;
  const token = csrfHeader || csrfBody;
  if (!token || !req.adminSession || token !== req.adminSession.csrf) {
    return res.status(403).json({ error: 'Invalid or missing CSRF token' });
  }
  next();
}

// --- Routes ---

// Login Page GET
router.get('/login', (req, res) => {
  const token = req.cookies && req.cookies[COOKIE_NAME];
  if (verifyToken(token)) {
    return res.redirect('/admin');
  }
  res.send(renderLoginPage());
});

// Login POST
router.post('/login', (req, res) => {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  if (isRateLimited(ip)) {
    return res.status(429).json({
      error: 'Too many failed login attempts. Please wait 15 minutes before trying again.'
    });
  }

  const { username, password } = req.body || {};
  const validUser = safeCompare(username, ADMIN_USER);
  const validPass = safeCompare(password, ADMIN_PASS);

  if (!validUser || !validPass) {
    recordFailedAttempt(ip);
    return res.status(401).json({ error: 'Invalid administrator username or password.' });
  }

  clearAttempts(ip);

  // Issue session token
  const csrf = crypto.randomBytes(16).toString('hex');
  const payload = {
    user: username,
    csrf,
    exp: Date.now() + 24 * 60 * 60 * 1000 // 24 hours
  };
  const token = createToken(payload);

  const isProd = process.env.NODE_ENV === 'production';
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: isProd,
    sameSite: 'lax',
    path: '/',
    maxAge: 24 * 60 * 60 * 1000
  });

  res.json({ success: true, redirect: '/admin' });
});

// Logout POST
router.post('/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME, { path: '/' });
  res.redirect('/admin/login');
});

// Main Dashboard GET
router.get('/', requireAuth, (req, res) => {
  const dbService = req.app.locals.dbService;
  const dbStatus = dbService ? dbService.getStatus() : { type: 'fallback' };
  res.send(renderDashboardPage({ csrf: req.adminSession.csrf, dbStatus }));
});

// API: List Bookings
router.get('/api/bookings', requireAuth, async (req, res) => {
  try {
    const dbService = req.app.locals.dbService;
    const { search, status, service, sort } = req.query;
    const bookings = await dbService.getBookings({ search, status, service, sort });
    res.json({ success: true, bookings });
  } catch (err) {
    res.status(500).json({ error: 'Failed to retrieve bookings: ' + err.message });
  }
});

// API: Metrics
router.get('/api/metrics', requireAuth, async (req, res) => {
  try {
    const dbService = req.app.locals.dbService;
    const metrics = await dbService.getMetrics();
    res.json({ success: true, metrics });
  } catch (err) {
    res.status(500).json({ error: 'Failed to retrieve metrics' });
  }
});

// API: Create Booking (from Admin)
router.post('/api/bookings', requireAuth, requireCsrf, async (req, res) => {
  try {
    const dbService = req.app.locals.dbService;
    const { name, phone, email, address, serviceType, preferredDate, preferredTime, description, status, adminNotes } = req.body;

    if (!name || !phone || !address || !serviceType || !preferredDate) {
      return res.status(400).json({ error: 'Required fields: Name, Phone, Address, Service, and Date' });
    }

    const newBooking = await dbService.createBooking({
      name,
      phone,
      email,
      address,
      serviceType,
      preferredDate,
      preferredTime: preferredTime || 'Morning (8am - 12pm)',
      description: description || 'Created manually by administrator',
      status: status || 'Confirmed',
      adminNotes: adminNotes || 'Admin manual intake'
    });

    res.json({ success: true, booking: newBooking });
  } catch (err) {
    res.status(500).json({ error: 'Failed to create booking: ' + err.message });
  }
});

// API: Update Booking
router.put('/api/bookings/:id', requireAuth, requireCsrf, async (req, res) => {
  try {
    const dbService = req.app.locals.dbService;
    const { id } = req.params;
    const updateData = req.body;

    const updated = await dbService.updateBooking(id, updateData);
    if (!updated) {
      return res.status(404).json({ error: 'Booking not found' });
    }
    res.json({ success: true, booking: updated });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update booking: ' + err.message });
  }
});

// API: Delete Booking
router.delete('/api/bookings/:id', requireAuth, requireCsrf, async (req, res) => {
  try {
    const dbService = req.app.locals.dbService;
    const { id } = req.params;

    const deleted = await dbService.deleteBooking(id);
    if (!deleted) {
      return res.status(404).json({ error: 'Booking not found or already deleted' });
    }
    res.json({ success: true, message: 'Booking removed successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete booking: ' + err.message });
  }
});

// API: Export CSV
router.get('/api/export', requireAuth, async (req, res) => {
  try {
    const dbService = req.app.locals.dbService;
    const bookings = await dbService.getBookings({});

    const headers = ['Booking ID', 'Date Created', 'Customer Name', 'Phone', 'Email', 'Address', 'Service', 'Appointment Date', 'Time Window', 'Status', 'Notes'];
    const rows = bookings.map(b => [
      `"${b.bookingId || ''}"`,
      `"${b.createdAt || ''}"`,
      `"${(b.name || '').replace(/"/g, '""')}"`,
      `"${b.phone || ''}"`,
      `"${b.email || ''}"`,
      `"${(b.address || '').replace(/"/g, '""')}"`,
      `"${(b.serviceType || '').replace(/"/g, '""')}"`,
      `"${b.preferredDate || ''}"`,
      `"${b.preferredTime || ''}"`,
      `"${b.status || ''}"`,
      `"${(b.adminNotes || '').replace(/"/g, '""')}"`
    ]);

    const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\r\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="houston-roofing-bookings.csv"');
    res.send(csvContent);
  } catch (err) {
    res.status(500).send('Export failed');
  }
});

// --- HTML Renderers ---

function renderLoginPage() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Portal | Houston Roofing &amp; Construction</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: #0f172a;
      color: #f8fafc;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 1.5rem;
    }
    .login-container {
      width: 100%;
      max-width: 420px;
      background: rgba(30, 41, 59, 0.7);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 14px;
      padding: 2.25rem;
      box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5), 0 8px 10px -6px rgba(0, 0, 0, 0.4);
    }
    .brand-header {
      text-align: center;
      margin-bottom: 2rem;
    }
    .brand-logo {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      color: #f59e0b;
      font-weight: 700;
      font-size: 1.25rem;
      margin-bottom: 0.5rem;
      text-decoration: none;
    }
    .brand-title {
      font-size: 0.875rem;
      color: #94a3b8;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }
    .form-group {
      margin-bottom: 1.25rem;
    }
    label {
      display: block;
      font-size: 0.8125rem;
      font-weight: 600;
      color: #cbd5e1;
      margin-bottom: 0.375rem;
    }
    input {
      width: 100%;
      padding: 0.75rem 1rem;
      background: #0f172a;
      border: 1px solid #334155;
      border-radius: 8px;
      color: #ffffff;
      font-size: 0.9375rem;
      outline: none;
      transition: border-color 0.15s ease, box-shadow 0.15s ease;
    }
    input:focus {
      border-color: #f59e0b;
      box-shadow: 0 0 0 3px rgba(245, 158, 11, 0.2);
    }
    .btn-submit {
      width: 100%;
      padding: 0.8125rem;
      background: #f59e0b;
      color: #0f172a;
      border: none;
      border-radius: 8px;
      font-size: 0.9375rem;
      font-weight: 700;
      cursor: pointer;
      box-shadow: 0 4px 6px -1px rgba(245, 158, 11, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.3);
      transition: transform 0.1s ease, background 0.15s ease;
      margin-top: 0.5rem;
    }
    .btn-submit:hover {
      background: #d97706;
    }
    .btn-submit:active {
      transform: translateY(1px);
    }
    .btn-submit:disabled {
      opacity: 0.6;
      cursor: not-allowed;
    }
    .alert {
      padding: 0.75rem 1rem;
      border-radius: 6px;
      font-size: 0.8125rem;
      margin-bottom: 1.25rem;
      display: none;
    }
    .alert-error {
      background: rgba(239, 68, 68, 0.15);
      border: 1px solid rgba(239, 68, 68, 0.4);
      color: #fca5a5;
    }
    .login-footer {
      text-align: center;
      margin-top: 1.75rem;
      font-size: 0.75rem;
      color: #64748b;
    }
    .login-footer a {
      color: #f59e0b;
      text-decoration: none;
    }
    .login-footer a:hover {
      text-decoration: underline;
    }
  </style>
</head>
<body>
  <div class="login-container">
    <div class="brand-header">
      <a href="/" class="brand-logo">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>
        Houston Roofing
      </a>
      <div class="brand-title">Operations &amp; Booking Management</div>
    </div>

    <div id="alertBox" class="alert alert-error"></div>

    <form id="loginForm">
      <div class="form-group">
        <label for="username">Administrator Username</label>
        <input type="text" id="username" name="username" required autocomplete="username" placeholder="admin" autofocus>
      </div>
      <div class="form-group">
        <label for="password">Administrator Password</label>
        <input type="password" id="password" name="password" required autocomplete="current-password" placeholder="••••••••••••">
      </div>
      <button type="submit" id="submitBtn" class="btn-submit">Sign In to Dashboard</button>
    </form>

    <div class="login-footer">
      <div>Authorized personnel only. Sessions expire after 24 hours.</div>
      <div style="margin-top:0.75rem;"><a href="/">&larr; Return to Public Website</a></div>
    </div>
  </div>

  <script>
    const form = document.getElementById('loginForm');
    const alertBox = document.getElementById('alertBox');
    const submitBtn = document.getElementById('submitBtn');

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      alertBox.style.display = 'none';
      submitBtn.disabled = true;
      submitBtn.textContent = 'Verifying credentials...';

      const username = form.username.value.trim();
      const password = form.password.value;

      try {
        const res = await fetch('/admin/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password })
        });
        const data = await res.json();
        if (res.ok && data.success) {
          window.location.href = data.redirect || '/admin';
        } else {
          alertBox.textContent = data.error || 'Authentication failed. Please check credentials.';
          alertBox.style.display = 'block';
        }
      } catch (err) {
        alertBox.textContent = 'Network or server error. Please try again.';
        alertBox.style.display = 'block';
      } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Sign In to Dashboard';
      }
    });
  </script>
</body>
</html>`;
}

function renderDashboardPage({ csrf, dbStatus }) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Dashboard | Houston Roofing &amp; Construction</title>
  <style>
    :root {
      --bg-canvas: #f8fafc;
      --bg-surface: #ffffff;
      --bg-dark: #0f172a;
      --bg-slate: #1e293b;
      --border-color: #e2e8f0;
      --text-main: #0f172a;
      --text-muted: #64748b;
      --amber-500: #f59e0b;
      --amber-600: #d97706;
      --teal-600: #0d9488;
      --blue-600: #2563eb;
      --rose-600: #e11d48;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg-canvas);
      color: var(--text-main);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }

    /* Top Admin Bar (15% Glassmorphism) */
    .admin-header {
      background: rgba(15, 23, 42, 0.95);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      color: #ffffff;
      border-bottom: 1px solid rgba(255, 255, 255, 0.1);
      position: sticky;
      top: 0;
      z-index: 100;
    }
    .header-inner {
      max-width: 1400px;
      margin: 0 auto;
      padding: 0.875rem 1.5rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
      flex-wrap: wrap;
    }
    .brand-group {
      display: flex;
      align-items: center;
      gap: 1rem;
    }
    .brand-title {
      font-size: 1.125rem;
      font-weight: 700;
      color: #ffffff;
      display: flex;
      align-items: center;
      gap: 0.5rem;
      text-decoration: none;
    }
    .admin-pill {
      background: rgba(245, 158, 11, 0.2);
      color: var(--amber-500);
      font-size: 0.6875rem;
      font-weight: 700;
      padding: 2px 8px;
      border-radius: 4px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      border: 1px solid rgba(245, 158, 11, 0.3);
    }
    .db-status {
      display: inline-flex;
      align-items: center;
      gap: 0.375rem;
      font-size: 0.75rem;
      padding: 3px 8px;
      border-radius: 12px;
      background: rgba(255, 255, 255, 0.1);
      color: #94a3b8;
    }
    .status-dot {
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: #10b981;
    }
    .status-dot.fallback { background: #f59e0b; }
    .header-actions {
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }
    .btn-header {
      display: inline-flex;
      align-items: center;
      gap: 0.375rem;
      font-size: 0.8125rem;
      font-weight: 600;
      padding: 0.5rem 0.875rem;
      border-radius: 6px;
      text-decoration: none;
      cursor: pointer;
      transition: all 0.15s ease;
      border: none;
    }
    .btn-header-ghost {
      background: rgba(255, 255, 255, 0.1);
      color: #cbd5e1;
      border: 1px solid rgba(255, 255, 255, 0.15);
    }
    .btn-header-ghost:hover {
      background: rgba(255, 255, 255, 0.18);
      color: #ffffff;
    }
    .btn-header-danger {
      background: rgba(239, 68, 68, 0.2);
      color: #fca5a5;
      border: 1px solid rgba(239, 68, 68, 0.3);
    }
    .btn-header-danger:hover {
      background: rgba(239, 68, 68, 0.35);
      color: #ffffff;
    }

    /* Main Container */
    .main-wrap {
      max-width: 1400px;
      margin: 0 auto;
      padding: 1.75rem 1.5rem 4rem;
      width: 100%;
      flex: 1;
    }

    /* Metrics Grid (80% Soft Flat with balanced shadows) */
    .metrics-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 1rem;
      margin-bottom: 1.75rem;
    }
    .metric-card {
      background: var(--bg-surface);
      border: 1px solid var(--border-color);
      border-radius: 10px;
      padding: 1.25rem 1rem;
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
      cursor: pointer;
      transition: transform 0.15s ease, border-color 0.15s ease;
    }
    .metric-card:hover {
      transform: translateY(-2px);
      border-color: #cbd5e1;
    }
    .metric-card.active {
      border-color: var(--amber-500);
      background: #fffbeb;
    }
    .metric-label {
      font-size: 0.75rem;
      font-weight: 700;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 0.375rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .metric-value {
      font-size: 1.75rem;
      font-weight: 700;
      color: var(--text-main);
    }

    /* Controls Bar */
    .controls-bar {
      background: var(--bg-surface);
      border: 1px solid var(--border-color);
      border-radius: 10px;
      padding: 1rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
      margin-bottom: 1.25rem;
      flex-wrap: wrap;
    }
    .search-wrap {
      flex: 1;
      min-width: 240px;
      position: relative;
    }
    .search-input {
      width: 100%;
      padding: 0.625rem 0.875rem 0.625rem 2.25rem;
      border: 1px solid var(--border-color);
      border-radius: 6px;
      font-size: 0.875rem;
      outline: none;
      background: #f8fafc;
    }
    .search-input:focus {
      border-color: var(--amber-500);
      background: #ffffff;
    }
    .search-icon {
      position: absolute;
      left: 0.75rem;
      top: 50%;
      transform: translateY(-50%);
      color: #94a3b8;
    }
    .filters-group {
      display: flex;
      align-items: center;
      gap: 0.625rem;
      flex-wrap: wrap;
    }
    select {
      padding: 0.625rem 0.75rem;
      border: 1px solid var(--border-color);
      border-radius: 6px;
      font-size: 0.8125rem;
      color: var(--text-main);
      background: #ffffff;
      outline: none;
      cursor: pointer;
    }
    .btn-action {
      display: inline-flex;
      align-items: center;
      gap: 0.375rem;
      font-size: 0.8125rem;
      font-weight: 600;
      padding: 0.625rem 1rem;
      border-radius: 6px;
      cursor: pointer;
      text-decoration: none;
      border: none;
      transition: all 0.15s ease;
    }
    /* 5% Claymorphic Button */
    .btn-clay {
      background: var(--amber-500);
      color: #0f172a;
      box-shadow: 0 2px 4px rgba(245, 158, 11, 0.25), inset 0 1px 0 rgba(255, 255, 255, 0.4);
    }
    .btn-clay:hover {
      background: var(--amber-600);
    }
    .btn-outline {
      background: var(--bg-surface);
      border: 1px solid var(--border-color);
      color: var(--text-main);
    }
    .btn-outline:hover {
      background: #f1f5f9;
    }

    /* Bookings Table & Cards */
    .table-container {
      background: var(--bg-surface);
      border: 1px solid var(--border-color);
      border-radius: 10px;
      overflow: hidden;
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
    }
    table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
    }
    th {
      background: #f8fafc;
      padding: 0.875rem 1rem;
      font-size: 0.75rem;
      font-weight: 700;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      border-bottom: 1px solid var(--border-color);
    }
    td {
      padding: 1rem;
      border-bottom: 1px solid var(--border-color);
      font-size: 0.875rem;
      vertical-align: middle;
    }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: #fafafa; }

    /* Badges */
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 0.25rem;
      font-size: 0.75rem;
      font-weight: 700;
      padding: 3px 8px;
      border-radius: 12px;
      text-transform: capitalize;
    }
    .badge-pending { background: #fef3c7; color: #92400e; }
    .badge-confirmed { background: #e0f2fe; color: #075985; }
    .badge-in-progress { background: #fef9c3; color: #854d0e; }
    .badge-completed { background: #dcfce7; color: #166534; }
    .badge-cancelled { background: #fee2e2; color: #991b1b; }

    .contact-links {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      margin-top: 0.375rem;
    }
    .contact-btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 26px;
      height: 26px;
      border-radius: 50%;
      background: #f1f5f9;
      color: var(--text-muted);
      text-decoration: none;
      transition: background 0.15s ease, color 0.15s ease;
    }
    .contact-btn:hover { background: #e2e8f0; color: var(--text-main); }
    .contact-btn.wa:hover { background: #25D366; color: #ffffff; }
    .contact-btn.tel:hover { background: var(--blue-600); color: #ffffff; }

    .action-icons {
      display: flex;
      align-items: center;
      gap: 0.375rem;
    }
    .btn-icon {
      background: none;
      border: 1px solid var(--border-color);
      border-radius: 6px;
      padding: 5px 8px;
      font-size: 0.75rem;
      font-weight: 600;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 0.25rem;
      background: #ffffff;
      color: var(--text-main);
      transition: all 0.15s ease;
    }
    .btn-icon:hover { background: #f1f5f9; }
    .btn-icon.delete:hover { background: #fee2e2; border-color: #fca5a5; color: #991b1b; }

    /* Modal (15% Glassmorphism overlay) */
    .modal-overlay {
      position: fixed;
      inset: 0;
      background: rgba(15, 23, 42, 0.65);
      backdrop-filter: blur(4px);
      -webkit-backdrop-filter: blur(4px);
      display: none;
      align-items: center;
      justify-content: center;
      z-index: 1000;
      padding: 1.5rem;
    }
    .modal-overlay.open { display: flex; }
    .modal-content {
      background: #ffffff;
      border-radius: 12px;
      max-width: 600px;
      width: 100%;
      max-height: 90vh;
      overflow-y: auto;
      box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.3);
      padding: 1.75rem;
    }
    .modal-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1.25rem;
      padding-bottom: 0.875rem;
      border-bottom: 1px solid var(--border-color);
    }
    .modal-title { font-size: 1.125rem; font-weight: 700; color: var(--text-main); }
    .btn-close {
      background: none;
      border: none;
      font-size: 1.25rem;
      cursor: pointer;
      color: var(--text-muted);
    }
    .form-row {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 1rem;
      margin-bottom: 1rem;
    }
    .form-group-full { margin-bottom: 1rem; }
    .form-label {
      display: block;
      font-size: 0.8125rem;
      font-weight: 600;
      color: #334155;
      margin-bottom: 0.375rem;
    }
    .form-input, .form-textarea, .form-select {
      width: 100%;
      padding: 0.625rem 0.75rem;
      border: 1px solid var(--border-color);
      border-radius: 6px;
      font-size: 0.875rem;
      outline: none;
    }
    .form-textarea { resize: vertical; min-height: 80px; }
    .modal-footer {
      display: flex;
      justify-content: flex-end;
      gap: 0.75rem;
      margin-top: 1.5rem;
      padding-top: 1rem;
      border-top: 1px solid var(--border-color);
    }

    /* Toast Notification */
    #toast {
      position: fixed;
      bottom: 2rem;
      right: 2rem;
      padding: 0.75rem 1.25rem;
      border-radius: 8px;
      font-size: 0.875rem;
      font-weight: 600;
      color: #ffffff;
      background: #0f172a;
      box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3);
      display: none;
      z-index: 2000;
      animation: fadeIn 0.2s ease;
    }
    @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }

    @media (max-width: 900px) {
      .table-responsive { overflow-x: auto; }
      .form-row { grid-template-columns: 1fr; }
    }

    /* Wavy animations between switch for milliseconds only (440ms) */
    .wavy-switch-wrapper {
      position: relative;
    }
    .wavy-sweep-effect {
      position: absolute;
      inset: -6px;
      pointer-events: none;
      z-index: 60;
      opacity: 0;
      border-radius: 14px;
      overflow: hidden;
    }
    .wavy-sweep-effect.active {
      animation: waveSweepKeyframe 440ms cubic-bezier(0.2, 0.8, 0.2, 1) forwards;
    }
    @keyframes waveSweepKeyframe {
      0% {
        opacity: 0.95;
        clip-path: polygon(0 0, 0% 0, 0% 100%, 0% 100%);
        background: linear-gradient(105deg, rgba(245, 158, 11, 0.35) 0%, rgba(37, 99, 235, 0.45) 50%, rgba(245, 158, 11, 0.4) 100%);
        backdrop-filter: blur(4px);
        -webkit-backdrop-filter: blur(4px);
      }
      35% {
        opacity: 0.85;
        clip-path: polygon(0 0, 65% 0, 48% 100%, 0% 100%);
      }
      70% {
        opacity: 0.55;
        clip-path: polygon(35% 0, 100% 0, 85% 100%, 20% 100%);
      }
      100% {
        opacity: 0;
        clip-path: polygon(100% 0, 100% 0, 100% 100%, 100% 100%);
      }
    }

    .wavy-btn {
      position: relative;
      overflow: hidden;
      transition: all 0.2s ease;
    }
    .wavy-btn.waving::after {
      content: '';
      position: absolute;
      inset: -50%;
      background: radial-gradient(circle, rgba(245, 158, 11, 0.5) 10%, transparent 65%);
      animation: waveBtnRipple 420ms ease-out forwards;
      pointer-events: none;
    }
    @keyframes waveBtnRipple {
      0% { transform: scale(0.2); opacity: 0.95; border-radius: 50%; }
      50% { transform: scale(1.3); opacity: 0.5; border-radius: 40% 60% 60% 40% / 40% 50% 50% 60%; }
      100% { transform: scale(2.2); opacity: 0; }
    }

    /* View Switcher Bar */
    .view-switch-bar {
      display: inline-flex;
      background: #e2e8f0;
      padding: 3px;
      border-radius: 8px;
      gap: 3px;
    }
    .btn-switch-tab {
      display: inline-flex;
      align-items: center;
      gap: 0.375rem;
      font-size: 0.8125rem;
      font-weight: 600;
      padding: 0.45rem 0.875rem;
      border-radius: 6px;
      border: none;
      background: transparent;
      color: #475569;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .btn-switch-tab:hover {
      color: #0f172a;
    }
    .btn-switch-tab.active {
      background: #ffffff;
      color: #0f172a;
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
    }

    /* Visuals Dashboard Components */
    .visuals-dashboard {
      display: flex;
      flex-direction: column;
      gap: 1.5rem;
      margin-bottom: 2rem;
    }
    .visuals-grid-4 {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 1rem;
    }
    .visual-stat-card {
      background: var(--bg-surface);
      border: 1px solid var(--border-color);
      border-radius: 10px;
      padding: 1.25rem;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.04);
      position: relative;
      overflow: hidden;
    }
    .visual-stat-card::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      width: 4px;
      height: 100%;
      background: var(--amber-500);
    }
    .visual-stat-card.blue::before { background: var(--blue-600); }
    .visual-stat-card.teal::before { background: var(--teal-600); }
    .visual-stat-card.rose::before { background: var(--rose-600); }
    .visual-stat-label {
      font-size: 0.75rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
      margin-bottom: 0.375rem;
    }
    .visual-stat-val {
      font-size: 1.625rem;
      font-weight: 800;
      color: var(--text-main);
      margin-bottom: 0.25rem;
    }
    .visual-stat-sub {
      font-size: 0.75rem;
      color: #64748b;
      display: flex;
      align-items: center;
      gap: 0.375rem;
    }

    .visuals-grid-2 {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 1.5rem;
    }
    @media (max-width: 960px) {
      .visuals-grid-2 { grid-template-columns: 1fr; }
    }

    .chart-panel-card {
      background: var(--bg-surface);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 1.5rem;
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.04);
    }
    .chart-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1.25rem;
      padding-bottom: 0.75rem;
      border-bottom: 1px solid var(--border-color);
    }
    .chart-title {
      font-size: 0.9375rem;
      font-weight: 700;
      color: var(--text-main);
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .chart-badge {
      font-size: 0.6875rem;
      font-weight: 700;
      padding: 2px 8px;
      border-radius: 12px;
      background: #f1f5f9;
      color: #475569;
    }

    /* Pipeline funnel flow */
    .pipeline-flow {
      display: flex;
      flex-direction: column;
      gap: 0.875rem;
    }
    .pipeline-stage {
      display: flex;
      flex-direction: column;
      gap: 0.375rem;
    }
    .pipeline-stage-header {
      display: flex;
      justify-content: space-between;
      font-size: 0.8125rem;
      font-weight: 600;
    }
    .pipeline-progress-track {
      width: 100%;
      height: 10px;
      background: #f1f5f9;
      border-radius: 6px;
      overflow: hidden;
    }
    .pipeline-progress-fill {
      height: 100%;
      border-radius: 6px;
      transition: width 0.6s cubic-bezier(0.4, 0, 0.2, 1);
    }

    /* County bar items */
    .county-list {
      display: flex;
      flex-direction: column;
      gap: 0.875rem;
    }
    .county-item {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      font-size: 0.8125rem;
    }
    .county-name {
      width: 140px;
      font-weight: 600;
      color: var(--text-main);
    }
    .county-bar-track {
      flex: 1;
      height: 8px;
      background: #f1f5f9;
      border-radius: 4px;
      overflow: hidden;
    }
    .county-bar-fill {
      height: 100%;
      background: linear-gradient(90deg, #f59e0b, #ea580c);
      border-radius: 4px;
      transition: width 0.6s ease;
    }
    .county-count {
      font-weight: 700;
      color: #0f172a;
      width: 32px;
      text-align: right;
    }
  </style>
</head>
<body>
  <!-- Header -->
  <header class="admin-header">
    <div class="header-inner">
      <div class="brand-group">
        <a href="/" class="brand-title">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="var(--amber-500)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>
          Houston Roofing &amp; Construction
        </a>
        <span class="admin-pill">Admin Console</span>
        <div class="db-status">
          <span class="status-dot ${dbStatus.type === 'mongodb' ? '' : 'fallback'}"></span>
          <span>${dbStatus.type === 'mongodb' ? 'MongoDB Atlas' : 'In-Memory Store'}</span>
        </div>
      </div>
      <div class="header-actions">
        <a href="/" class="btn-header btn-header-ghost" target="_blank">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
          View Public Site
        </a>
        <form action="/admin/logout" method="POST" style="display:inline;">
          <input type="hidden" name="_csrf" value="${csrf}">
          <button type="submit" class="btn-header btn-header-danger">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
            Sign Out
          </button>
        </form>
      </div>
    </div>
  </header>

  <!-- Main View -->
  <main class="main-wrap">
    <!-- View Switcher with Wavy Animation (milliseconds only) -->
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1.5rem; flex-wrap:wrap; gap:1rem;">
      <div class="view-switch-bar">
        <button id="viewSwitchVisuals" class="btn-switch-tab wavy-btn active" onclick="switchAdminView('visuals', this)">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21.21 15.89A10 10 0 1 1 8 2.83"/><path d="M22 12A10 10 0 0 0 12 2v10z"/></svg>
          Visuals Dashboard
        </button>
        <button id="viewSwitchTable" class="btn-switch-tab wavy-btn" onclick="switchAdminView('table', this)">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>
          Bookings Data Table
        </button>
        <button id="viewSwitchBoth" class="btn-switch-tab wavy-btn" onclick="switchAdminView('both', this)">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><line x1="3" y1="9" x2="21" y2="9"/><line x1="9" y1="21" x2="9" y2="9"/></svg>
          Unified View
        </button>
      </div>

      <div style="display:flex; align-items:center; gap:0.5rem; font-size:0.75rem; color:#64748b;">
        <span style="display:inline-block; width:8px; height:8px; border-radius:50%; background:#10b981;"></span>
        <span>Real-time Operational Visuals</span>
      </div>
    </div>

    <!-- Wavy Switch Wrapper Container -->
    <div id="dashboardContentWrap" class="wavy-switch-wrapper">
      <div id="wavySweepElement" class="wavy-sweep-effect"></div>

      <!-- Metrics Grid (Quick Status Filter Pills) -->
      <div class="metrics-grid" id="metricsGrid">
        <div class="metric-card wavy-btn" onclick="filterByMetric('all', this)">
          <div class="metric-label">Total Bookings</div>
          <div class="metric-value" id="metricTotal">--</div>
        </div>
        <div class="metric-card wavy-btn" onclick="filterByMetric('Pending', this)">
          <div class="metric-label">Pending Reviews</div>
          <div class="metric-value" id="metricPending" style="color:var(--amber-600);">--</div>
        </div>
        <div class="metric-card wavy-btn" onclick="filterByMetric('Confirmed', this)">
          <div class="metric-label">Confirmed</div>
          <div class="metric-value" id="metricConfirmed" style="color:var(--blue-600);">--</div>
        </div>
        <div class="metric-card wavy-btn" onclick="filterByMetric('In Progress', this)">
          <div class="metric-label">In Progress</div>
          <div class="metric-value" id="metricInProgress" style="color:#ca8a04;">--</div>
        </div>
        <div class="metric-card wavy-btn" onclick="filterByMetric('Completed', this)">
          <div class="metric-label">Completed</div>
          <div class="metric-value" id="metricCompleted" style="color:var(--teal-600);">--</div>
        </div>
        <div class="metric-card wavy-btn" onclick="filterByMetric('Cancelled', this)">
          <div class="metric-label">Cancelled</div>
          <div class="metric-value" id="metricCancelled" style="color:var(--rose-600);">--</div>
        </div>
      </div>

      <!-- Visuals Dashboard Section -->
      <section id="visualsDashboard" class="visuals-dashboard">
        <!-- 4 Visual KPI Tiles -->
        <div class="visuals-grid-4">
          <div class="visual-stat-card">
            <div class="visual-stat-label">Projected Pipeline Value</div>
            <div class="visual-stat-val" id="visualPipelineVal">$0</div>
            <div class="visual-stat-sub">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#16a34a" stroke-width="2.5"><polyline points="23 6 13.5 15.5 8.5 10.5 1 18"/><polyline points="17 6 23 6 23 12"/></svg>
              <span>Calculated from active project scopes</span>
            </div>
          </div>
          <div class="visual-stat-card blue">
            <div class="visual-stat-label">Average Job Ticket</div>
            <div class="visual-stat-val" id="visualAvgTicket">$0</div>
            <div class="visual-stat-sub">
              <span>Standard vs. standing seam metal split</span>
            </div>
          </div>
          <div class="visual-stat-card teal">
            <div class="visual-stat-label">Intake Conversion Ratio</div>
            <div class="visual-stat-val" id="visualConversionRate">0%</div>
            <div class="visual-stat-sub">
              <span>Inquiry to confirmed inspection rate</span>
            </div>
          </div>
          <div class="visual-stat-card rose">
            <div class="visual-stat-label">Active Job Dispatch Queue</div>
            <div class="visual-stat-val" id="visualActiveQueue">0</div>
            <div class="visual-stat-sub">
              <span>Crews assigned in Greater Houston</span>
            </div>
          </div>
        </div>

        <!-- 2-Column Analytics: Service Donut + 7-Day Trend -->
        <div class="visuals-grid-2">
          <!-- Service Distribution Donut Chart -->
          <div class="chart-panel-card">
            <div class="chart-header">
              <h3 class="chart-title">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--amber-500)" stroke-width="2"><path d="M21.21 15.89A10 10 0 1 1 8 2.83"/><path d="M22 12A10 10 0 0 0 12 2v10z"/></svg>
                Service Category Distribution
              </h3>
              <span class="chart-badge" id="visualTotalServices">0 Total Jobs</span>
            </div>
            <div style="display:flex; align-items:center; justify-content:space-around; flex-wrap:wrap; gap:1.5rem;">
              <div style="position:relative; width:170px; height:170px;">
                <svg id="donutSvg" width="170" height="170" viewBox="0 0 42 42" style="transform: rotate(-90deg);"></svg>
                <div style="position:absolute; inset:0; display:flex; flex-direction:column; align-items:center; justify-content:center; text-align:center;">
                  <span style="font-size:1.375rem; font-weight:800; color:#0f172a;" id="donutCenterCount">0</span>
                  <span style="font-size:0.6875rem; color:#64748b; text-transform:uppercase;">Projects</span>
                </div>
              </div>
              <div id="serviceLegendList" style="flex:1; min-width:180px; display:flex; flex-direction:column; gap:0.5rem; font-size:0.8125rem;">
                <!-- Filled dynamically by JS -->
              </div>
            </div>
          </div>

          <!-- 7-Day Activity Bar Chart -->
          <div class="chart-panel-card">
            <div class="chart-header">
              <h3 class="chart-title">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--blue-600)" stroke-width="2"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>
                Weekly Intake Velocity (7 Days)
              </h3>
              <span class="chart-badge">Daily Velocity</span>
            </div>
            <div style="height:170px; display:flex; align-items:flex-end; gap:0.75rem; padding:0.5rem 0;" id="weeklyBarsContainer">
              <!-- Filled dynamically by JS -->
            </div>
          </div>
        </div>

        <!-- 2-Column Pipeline: Conversion Funnel + Regional Heatmap -->
        <div class="visuals-grid-2">
          <!-- Conversion Funnel -->
          <div class="chart-panel-card">
            <div class="chart-header">
              <h3 class="chart-title">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--teal-600)" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
                Project Lifecycle &amp; Conversion Funnel
              </h3>
              <span class="chart-badge">Status Flow</span>
            </div>
            <div class="pipeline-flow" id="pipelineFlowContainer">
              <!-- Filled dynamically by JS -->
            </div>
          </div>

          <!-- Regional County Progress Breakdown -->
          <div class="chart-panel-card">
            <div class="chart-header">
              <h3 class="chart-title">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--rose-600)" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="m4.93 4.93 4.24 4.24"/><path d="m14.83 9.17 4.24-4.24"/><path d="m14.83 14.83 4.24 4.24"/><path d="m9.17 14.83-4.24 4.24"/></svg>
                Greater Houston Regional Demand
              </h3>
              <span class="chart-badge">18 Counties</span>
            </div>
            <div class="county-list" id="countyListContainer">
              <!-- Filled dynamically by JS -->
            </div>
          </div>
        </div>
      </section>

      <!-- Bookings Table Section -->
      <section id="tableSectionWrap">
        <!-- Controls Bar -->
        <div class="controls-bar">
          <div class="search-wrap">
            <svg class="search-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            <input type="text" id="searchInput" class="search-input" placeholder="Search by name, phone, address, or ID...">
          </div>
          <div class="filters-group">
            <select id="statusFilter" onchange="loadBookings()">
              <option value="">All Statuses</option>
              <option value="Pending">Pending</option>
              <option value="Confirmed">Confirmed</option>
              <option value="In Progress">In Progress</option>
              <option value="Completed">Completed</option>
              <option value="Cancelled">Cancelled</option>
            </select>
            <select id="serviceFilter" onchange="loadBookings()">
              <option value="">All Services</option>
              <option value="Roof Inspection &amp; Estimate">Roof Inspection &amp; Estimate</option>
              <option value="Asphalt Shingle Replacement">Asphalt Shingle Replacement</option>
              <option value="Standing Seam Metal Roofing">Standing Seam Metal Roofing</option>
              <option value="Roof Repair &amp; Hail Assessments">Roof Repair &amp; Hail Assessments</option>
              <option value="Commercial Flat &amp; TPO Systems">Commercial Flat &amp; TPO Systems</option>
              <option value="Apartment &amp; HOA Communities">Apartment &amp; HOA Communities</option>
              <option value="Fiber Cement &amp; Siding">Fiber Cement &amp; Siding</option>
            </select>
            <select id="sortSelect" onchange="loadBookings()">
              <option value="newest">Newest First</option>
              <option value="oldest">Oldest First</option>
              <option value="appointment">Appointment Date</option>
            </select>
            <button class="btn-action btn-outline wavy-btn" onclick="exportCsv()">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
              Export CSV
            </button>
            <button class="btn-action btn-clay wavy-btn" onclick="openNewModal()">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
              New Booking
            </button>
          </div>
        </div>

        <!-- Bookings Table -->
        <div class="table-container table-responsive">
          <table>
            <thead>
              <tr>
                <th>Booking ID</th>
                <th>Customer</th>
                <th>Service Requested</th>
                <th>Appointment</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody id="bookingsTbody">
              <tr>
                <td colspan="6" style="text-align:center; padding: 3rem; color:#94a3b8;">Loading bookings...</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>
  </main>
            <th>Booking ID</th>
            <th>Customer</th>
            <th>Service Requested</th>
            <th>Appointment</th>
            <th>Status</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody id="bookingsTbody">
          <tr>
            <td colspan="6" style="text-align:center; padding: 3rem; color:#94a3b8;">Loading bookings...</td>
          </tr>
        </tbody>
      </table>
    </div>
  </main>

  <!-- View / Edit Details Modal -->
  <div id="detailsModal" class="modal-overlay">
    <div class="modal-content">
      <div class="modal-header">
        <h3 class="modal-title" id="detailsModalTitle">Booking Details</h3>
        <button class="btn-close" onclick="closeModal('detailsModal')">&times;</button>
      </div>
      <form id="detailsForm">
        <input type="hidden" id="editBookingId">
        <div class="form-row">
          <div>
            <label class="form-label">Customer Name</label>
            <input type="text" id="editName" class="form-input" required>
          </div>
          <div>
            <label class="form-label">Phone Number</label>
            <input type="text" id="editPhone" class="form-input" required>
          </div>
        </div>
        <div class="form-row">
          <div>
            <label class="form-label">Email Address</label>
            <input type="email" id="editEmail" class="form-input">
          </div>
          <div>
            <label class="form-label">Service Type</label>
            <select id="editService" class="form-select">
              <option value="Roof Inspection &amp; Estimate">Roof Inspection &amp; Estimate</option>
              <option value="Asphalt Shingle Replacement">Asphalt Shingle Replacement</option>
              <option value="Standing Seam Metal Roofing">Standing Seam Metal Roofing</option>
              <option value="Roof Repair &amp; Hail Assessments">Roof Repair &amp; Hail Assessments</option>
              <option value="Commercial Flat &amp; TPO Systems">Commercial Flat &amp; TPO Systems</option>
              <option value="Apartment &amp; HOA Communities">Apartment &amp; HOA Communities</option>
              <option value="Fiber Cement &amp; Siding">Fiber Cement &amp; Siding</option>
            </select>
          </div>
        </div>
        <div class="form-group-full">
          <label class="form-label">Property Address</label>
          <input type="text" id="editAddress" class="form-input" required>
        </div>
        <div class="form-row">
          <div>
            <label class="form-label">Preferred Date</label>
            <input type="date" id="editDate" class="form-input" required>
          </div>
          <div>
            <label class="form-label">Time Window</label>
            <select id="editTime" class="form-select">
              <option value="Morning (8am - 12pm)">Morning (8am - 12pm)</option>
              <option value="Afternoon (12pm - 4pm)">Afternoon (12pm - 4pm)</option>
              <option value="Evening (4pm - 7pm)">Evening (4pm - 7pm)</option>
            </select>
          </div>
        </div>
        <div class="form-row">
          <div>
            <label class="form-label">Status</label>
            <select id="editStatus" class="form-select">
              <option value="Pending">Pending</option>
              <option value="Confirmed">Confirmed</option>
              <option value="In Progress">In Progress</option>
              <option value="Completed">Completed</option>
              <option value="Cancelled">Cancelled</option>
            </select>
          </div>
          <div>
            <label class="form-label">Direct Customer Contacts</label>
            <div style="display:flex; gap:0.5rem; margin-top:0.25rem;" id="modalQuickLinks"></div>
          </div>
        </div>
        <div class="form-group-full">
          <label class="form-label">Customer Project Description</label>
          <div id="viewDescription" style="padding:0.75rem; background:#f8fafc; border:1px solid #e2e8f0; border-radius:6px; font-size:0.875rem; color:#475569; min-height:48px;"></div>
        </div>
        <div class="form-group-full">
          <label class="form-label">Staff Internal Notes &amp; Inspector Assignment</label>
          <textarea id="editNotes" class="form-textarea" placeholder="Add inspector name, drone inspection notes, quote tiers, or follow-up details..."></textarea>
        </div>
        <div class="modal-footer">
          <button type="button" class="btn-action btn-outline" onclick="closeModal('detailsModal')">Cancel</button>
          <button type="submit" class="btn-action btn-clay">Save Changes</button>
        </div>
      </form>
    </div>
  </div>

  <!-- New Booking Modal -->
  <div id="newModal" class="modal-overlay">
    <div class="modal-content">
      <div class="modal-header">
        <h3 class="modal-title">Create Manual Booking</h3>
        <button class="btn-close" onclick="closeModal('newModal')">&times;</button>
      </div>
      <form id="newBookingForm">
        <div class="form-row">
          <div>
            <label class="form-label">Customer Name *</label>
            <input type="text" id="newName" class="form-input" required placeholder="John Smith">
          </div>
          <div>
            <label class="form-label">Phone Number *</label>
            <input type="tel" id="newPhone" class="form-input" required placeholder="(832) 555-0199">
          </div>
        </div>
        <div class="form-row">
          <div>
            <label class="form-label">Email Address</label>
            <input type="email" id="newEmail" class="form-input" placeholder="john@example.com">
          </div>
          <div>
            <label class="form-label">Service Type *</label>
            <select id="newService" class="form-select" required>
              <option value="Roof Inspection &amp; Estimate">Roof Inspection &amp; Estimate</option>
              <option value="Asphalt Shingle Replacement">Asphalt Shingle Replacement</option>
              <option value="Standing Seam Metal Roofing">Standing Seam Metal Roofing</option>
              <option value="Roof Repair &amp; Hail Assessments">Roof Repair &amp; Hail Assessments</option>
              <option value="Commercial Flat &amp; TPO Systems">Commercial Flat &amp; TPO Systems</option>
              <option value="Apartment &amp; HOA Communities">Apartment &amp; HOA Communities</option>
              <option value="Fiber Cement &amp; Siding">Fiber Cement &amp; Siding</option>
            </select>
          </div>
        </div>
        <div class="form-group-full">
          <label class="form-label">Property Address *</label>
          <input type="text" id="newAddress" class="form-input" required placeholder="12345 Spring Cypress Rd, Houston, TX 77065">
        </div>
        <div class="form-row">
          <div>
            <label class="form-label">Preferred Date *</label>
            <input type="date" id="newDate" class="form-input" required>
          </div>
          <div>
            <label class="form-label">Time Window</label>
            <select id="newTime" class="form-select">
              <option value="Morning (8am - 12pm)">Morning (8am - 12pm)</option>
              <option value="Afternoon (12pm - 4pm)">Afternoon (12pm - 4pm)</option>
              <option value="Evening (4pm - 7pm)">Evening (4pm - 7pm)</option>
            </select>
          </div>
        </div>
        <div class="form-group-full">
          <label class="form-label">Project Description</label>
          <textarea id="newDescription" class="form-textarea" placeholder="Customer requirements, leak location, roof age..."></textarea>
        </div>
        <div class="form-group-full">
          <label class="form-label">Initial Status</label>
          <select id="newStatus" class="form-select">
            <option value="Confirmed">Confirmed</option>
            <option value="Pending">Pending</option>
            <option value="In Progress">In Progress</option>
          </select>
        </div>
        <div class="modal-footer">
          <button type="button" class="btn-action btn-outline" onclick="closeModal('newModal')">Cancel</button>
          <button type="submit" class="btn-action btn-clay">Create Booking</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Toast Notification -->
  <div id="toast"></div>

  <script>
    const csrfToken = '${csrf}';
    let currentBookings = [];

    // Helper: Toast
    function showToast(msg) {
      const t = document.getElementById('toast');
      t.textContent = msg;
      t.style.display = 'block';
      setTimeout(() => { t.style.display = 'none'; }, 3200);
    }

    // Load Metrics
    async function loadMetrics() {
      try {
        const res = await fetch('/admin/api/metrics');
        const data = await res.json();
        if (data.success && data.metrics) {
          const m = data.metrics;
          document.getElementById('metricTotal').textContent = m.total || 0;
          document.getElementById('metricPending').textContent = m.pending || 0;
          document.getElementById('metricConfirmed').textContent = m.confirmed || 0;
          document.getElementById('metricInProgress').textContent = m.inProgress || 0;
          document.getElementById('metricCompleted').textContent = m.completed || 0;
          document.getElementById('metricCancelled').textContent = m.cancelled || 0;
        }
      } catch (err) {
        console.error('Failed to load metrics:', err);
      }
    }

    // Load Bookings Table
    async function loadBookings() {
      const search = document.getElementById('searchInput').value.trim();
      const status = document.getElementById('statusFilter').value;
      const service = document.getElementById('serviceFilter').value;
      const sort = document.getElementById('sortSelect').value;

      const params = new URLSearchParams();
      if (search) params.append('search', search);
      if (status) params.append('status', status);
      if (service) params.append('service', service);
      if (sort) params.append('sort', sort);

      try {
        const res = await fetch('/admin/api/bookings?' + params.toString());
        const data = await res.json();
        if (data.success) {
          currentBookings = data.bookings || [];
          renderTable(currentBookings);
        }
      } catch (err) {
        document.getElementById('bookingsTbody').innerHTML = '<tr><td colspan="6" style="text-align:center; color:#ef4444; padding:2rem;">Failed to load bookings</td></tr>';
      }
    }

    function renderTable(bookings) {
      const tbody = document.getElementById('bookingsTbody');
      if (!bookings || bookings.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:3rem; color:#94a3b8;">No bookings found matching criteria.</td></tr>';
        return;
      }

      tbody.innerHTML = bookings.map(b => {
        const statusClass = 'badge-' + (b.status || 'pending').toLowerCase().replace(' ', '-');
        const cleanPhone = (b.phone || '').replace(/\\D/g, '');
        const waText = encodeURIComponent(\`Hello \${b.name}, this is Houston Roofing & Construction following up on your appointment request (\${b.bookingId}).\`);

        return \`
          <tr>
            <td>
              <strong style="color:#0f172a; font-size:0.875rem;">\${b.bookingId}</strong>
              <div style="font-size:0.75rem; color:#64748b; margin-top:2px;">\${b.createdAt ? new Date(b.createdAt).toLocaleDateString() : ''}</div>
            </td>
            <td>
              <div style="font-weight:600; color:#0f172a;">\${escapeHtml(b.name)}</div>
              <div style="font-size:0.75rem; color:#64748b;">\${escapeHtml(b.address)}</div>
              <div class="contact-links">
                <a href="tel:\${b.phone}" class="contact-btn tel" title="Call \${b.phone}">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"/></svg>
                </a>
                <a href="https://wa.me/\${cleanPhone}?text=\${waText}" target="_blank" class="contact-btn wa" title="WhatsApp Chat">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"/></svg>
                </a>
                <span style="font-size:0.8125rem; color:#475569;">\${escapeHtml(b.phone)}</span>
              </div>
            </td>
            <td>
              <span style="font-weight:500;">\${escapeHtml(b.serviceType)}</span>
            </td>
            <td>
              <div>\${b.preferredDate || 'TBD'}</div>
              <div style="font-size:0.75rem; color:#64748b;">\${b.preferredTime || ''}</div>
            </td>
            <td>
              <select onchange="quickUpdateStatus('\${b.bookingId || b._id}', this.value)" style="padding:3px 6px; font-size:0.75rem; font-weight:700; border-radius:6px; border:1px solid #cbd5e1;">
                <option value="Pending" \${b.status === 'Pending' ? 'selected' : ''}>Pending</option>
                <option value="Confirmed" \${b.status === 'Confirmed' ? 'selected' : ''}>Confirmed</option>
                <option value="In Progress" \${b.status === 'In Progress' ? 'selected' : ''}>In Progress</option>
                <option value="Completed" \${b.status === 'Completed' ? 'selected' : ''}>Completed</option>
                <option value="Cancelled" \${b.status === 'Cancelled' ? 'selected' : ''}>Cancelled</option>
              </select>
            </td>
            <td>
              <div class="action-icons">
                <button class="btn-icon" onclick="openDetails('\${b.bookingId || b._id}')" title="View details and notes">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                  Details
                </button>
                <button class="btn-icon delete" onclick="confirmDelete('\${b.bookingId || b._id}', '\${escapeHtml(b.name)}')" title="Delete booking">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                </button>
              </div>
            </td>
          </tr>
        \`;
      }).join('');
    }

    function escapeHtml(str) {
      if (!str) return '';
      return String(str).replace(/[&<>"']/g, m => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' })[m]);
    }

    // Wavy animations between switch for milliseconds only (440ms)
    function triggerWavySwitch(containerId, btn) {
      if (btn) {
        btn.classList.add('waving');
        setTimeout(() => btn.classList.remove('waving'), 420);
      }
      const sweep = document.getElementById('wavySweepElement');
      if (sweep) {
        sweep.classList.remove('active');
        void sweep.offsetWidth; // force browser layout reflow
        sweep.classList.add('active');
        setTimeout(() => sweep.classList.remove('active'), 440);
      }
    }

    // Switch between Visuals Dashboard and Bookings Table views with Wavy effect
    function switchAdminView(mode, btn) {
      triggerWavySwitch('dashboardContentWrap', btn);

      document.querySelectorAll('.btn-switch-tab').forEach(b => b.classList.remove('active'));
      if (btn) btn.classList.add('active');

      const visualsSection = document.getElementById('visualsDashboard');
      const tableSection = document.getElementById('tableSectionWrap');

      if (mode === 'visuals') {
        visualsSection.style.display = 'flex';
        tableSection.style.display = 'none';
      } else if (mode === 'table') {
        visualsSection.style.display = 'none';
        tableSection.style.display = 'block';
      } else {
        // Unified / Both
        visualsSection.style.display = 'flex';
        tableSection.style.display = 'block';
      }
    }

    // Metric card filter click with wavy ripple
    function filterByMetric(status, cardEl) {
      if (cardEl) {
        triggerWavySwitch('dashboardContentWrap', cardEl);
      }
      document.querySelectorAll('.metric-card').forEach(c => c.classList.remove('active'));
      if (cardEl) cardEl.classList.add('active');

      const statusSelect = document.getElementById('statusFilter');
      if (status === 'all') {
        statusSelect.value = '';
      } else {
        statusSelect.value = status;
      }
      loadBookings();
    }

    // Load Bookings Table & Update Visuals Dashboard
    async function loadBookings() {
      const search = document.getElementById('searchInput').value.trim();
      const status = document.getElementById('statusFilter').value;
      const service = document.getElementById('serviceFilter').value;
      const sort = document.getElementById('sortSelect').value;

      const params = new URLSearchParams();
      if (search) params.append('search', search);
      if (status) params.append('status', status);
      if (service) params.append('service', service);
      if (sort) params.append('sort', sort);

      try {
        const res = await fetch('/admin/api/bookings?' + params.toString());
        const data = await res.json();
        if (data.success) {
          currentBookings = data.bookings || [];
          renderTable(currentBookings);
          renderVisualsDashboard(currentBookings);
        }
      } catch (err) {
        document.getElementById('bookingsTbody').innerHTML = '<tr><td colspan="6" style="text-align:center; color:#ef4444; padding:2rem;">Failed to load bookings</td></tr>';
      }
    }

    // Render Visuals Dashboard Charts & Analytics
    function renderVisualsDashboard(bookings) {
      if (!bookings) bookings = [];
      const total = bookings.length;

      // 1. Compute Pipeline Value by scope
      const serviceValues = {
        'Asphalt Shingle Replacement': 13500,
        'Standing Seam Metal Roofing': 28500,
        'Commercial Flat & TPO Systems': 42000,
        'Roof Repair & Hail Assessments': 2400,
        'Fiber Cement & Siding': 12000,
        'Apartment & HOA Communities': 38000,
        'Roof Inspection & Estimate': 450
      };

      let totalPipeline = 0;
      let confirmedOrActive = 0;
      const serviceCounts = {};
      const countyCounts = {
        'Harris County': 0,
        'Montgomery County': 0,
        'Fort Bend County': 0,
        'Brazoria & Galveston': 0,
        'Surrounding Texas': 0
      };

      bookings.forEach(b => {
        const val = serviceValues[b.serviceType] || 8500;
        if (b.status !== 'Cancelled') {
          totalPipeline += val;
        }
        if (b.status === 'Confirmed' || b.status === 'In Progress') {
          confirmedOrActive++;
        }

        // Service count
        serviceCounts[b.serviceType] = (serviceCounts[b.serviceType] || 0) + 1;

        // County categorization
        const addr = (b.address || '').toLowerCase();
        if (addr.includes('harris') || addr.includes('cypress') || addr.includes('houston') || addr.includes('katy') || addr.includes('tomball')) {
          countyCounts['Harris County']++;
        } else if (addr.includes('woodlands') || addr.includes('montgomery') || addr.includes('conroe') || addr.includes('spring')) {
          countyCounts['Montgomery County']++;
        } else if (addr.includes('fort bend') || addr.includes('sugar land') || addr.includes('missouri city') || addr.includes('richmond')) {
          countyCounts['Fort Bend County']++;
        } else if (addr.includes('brazoria') || addr.includes('galveston') || addr.includes('pearland') || addr.includes('friendswood')) {
          countyCounts['Brazoria & Galveston']++;
        } else {
          countyCounts['Surrounding Texas']++;
        }
      });

      const avgTicket = total > 0 ? Math.round(totalPipeline / total) : 0;
      const nonPending = bookings.filter(b => b.status === 'Confirmed' || b.status === 'In Progress' || b.status === 'Completed').length;
      const conversionRate = total > 0 ? Math.round((nonPending / total) * 100) : 0;

      // Update KPI Tiles
      document.getElementById('visualPipelineVal').textContent = '$' + totalPipeline.toLocaleString();
      document.getElementById('visualAvgTicket').textContent = '$' + avgTicket.toLocaleString();
      document.getElementById('visualConversionRate').textContent = conversionRate + '%';
      document.getElementById('visualActiveQueue').textContent = confirmedOrActive + ' Active';
      document.getElementById('donutCenterCount').textContent = total;
      document.getElementById('visualTotalServices').textContent = total + ' Total Inquiries';

      // 2. Render SVG Donut Chart
      const donutSvg = document.getElementById('donutSvg');
      const legendList = document.getElementById('serviceLegendList');
      const serviceColors = {
        'Asphalt Shingle Replacement': '#f59e0b',
        'Standing Seam Metal Roofing': '#2563eb',
        'Commercial Flat & TPO Systems': '#8b5cf6',
        'Roof Repair & Hail Assessments': '#0d9488',
        'Apartment & HOA Communities': '#0284c7',
        'Fiber Cement & Siding': '#ea580c',
        'Roof Inspection & Estimate': '#64748b'
      };

      let donutHtml = '<circle cx="21" cy="21" r="15.9155" fill="none" stroke="#f1f5f9" stroke-width="6.5"></circle>';
      let legendHtml = '';
      let cumulativeOffset = 0;

      const servicesArray = Object.keys(serviceCounts);
      if (servicesArray.length === 0) {
        legendHtml = '<div style="color:#94a3b8; font-size:0.8125rem;">No bookings available</div>';
      } else {
        servicesArray.forEach(srv => {
          const count = serviceCounts[srv];
          const pct = Math.round((count / total) * 100);
          const color = serviceColors[srv] || '#94a3b8';
          const dash = pct;
          const gap = 100 - pct;

          donutHtml += \`
            <circle cx="21" cy="21" r="15.9155" fill="none"
              stroke="\${color}" stroke-width="6.5"
              stroke-dasharray="\${dash} \${gap}"
              stroke-dashoffset="\${-cumulativeOffset}">
            </circle>
          \`;
          cumulativeOffset += dash;

          legendHtml += \`
            <div style="display:flex; justify-content:space-between; align-items:center;">
              <div style="display:flex; align-items:center; gap:0.5rem; overflow:hidden;">
                <span style="width:10px; height:10px; border-radius:3px; background:\${color}; flex-shrink:0;"></span>
                <span style="white-space:nowrap; overflow:hidden; text-overflow:ellipsis; max-width:180px;">\${escapeHtml(srv)}</span>
              </div>
              <div style="font-weight:700; color:#0f172a; margin-left:0.5rem;">\${count} <span style="font-weight:400; color:#64748b; font-size:0.75rem;">(\${pct}%)</span></div>
            </div>
          \`;
        });
      }

      donutSvg.innerHTML = donutHtml;
      legendList.innerHTML = legendHtml;

      // 3. Render 7-Day Velocity Bar Chart
      const barsContainer = document.getElementById('weeklyBarsContainer');
      const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
      // Distribute counts over the 7 days
      const dayCounts = [0, 0, 0, 0, 0, 0, 0];
      bookings.forEach(b => {
        const d = b.createdAt ? new Date(b.createdAt).getDay() : 0;
        // Map 0 (Sun) -> 6, 1 (Mon) -> 0
        const index = d === 0 ? 6 : d - 1;
        dayCounts[index]++;
      });
      const maxDayCount = Math.max(...dayCounts, 1);

      let barsHtml = '';
      days.forEach((day, i) => {
        const count = dayCounts[i];
        const heightPct = Math.max(Math.round((count / maxDayCount) * 100), 8);
        const isPeak = count === maxDayCount && count > 0;
        const barColor = isPeak ? 'linear-gradient(180deg, #f59e0b 0%, #ea580c 100%)' : '#cbd5e1';

        barsHtml += \`
          <div style="flex:1; display:flex; flex-direction:column; align-items:center; height:100%; justify-content:flex-end;">
            <span style="font-size:0.6875rem; font-weight:700; color:\${isPeak ? '#b45309' : '#64748b'}; margin-bottom:4px;">\${count}</span>
            <div style="width:100%; max-width:28px; height:\${heightPct}%; background:\${barColor}; border-radius:4px 4px 0 0; transition:height 0.5s ease;"></div>
            <span style="font-size:0.6875rem; font-weight:600; color:#64748b; margin-top:6px;">\${day}</span>
          </div>
        \`;
      });
      barsContainer.innerHTML = barsHtml;

      // 4. Render Conversion Funnel
      const funnelContainer = document.getElementById('pipelineFlowContainer');
      const pendingCount = bookings.filter(b => b.status === 'Pending').length;
      const confirmedCount = bookings.filter(b => b.status === 'Confirmed').length;
      const inProgressCount = bookings.filter(b => b.status === 'In Progress').length;
      const completedCount = bookings.filter(b => b.status === 'Completed').length;

      const stages = [
        { label: 'Stage 1: Intake & Pending Review', count: pendingCount, color: 'linear-gradient(90deg, #f59e0b, #d97706)' },
        { label: 'Stage 2: Confirmed Field Inspections', count: confirmedCount, color: 'linear-gradient(90deg, #0284c7, #2563eb)' },
        { label: 'Stage 3: Production & Roofing In-Progress', count: inProgressCount, color: 'linear-gradient(90deg, #eab308, #ca8a04)' },
        { label: 'Stage 4: Completed & Warranty Sign-Off', count: completedCount, color: 'linear-gradient(90deg, #10b981, #059669)' }
      ];

      let funnelHtml = '';
      stages.forEach(st => {
        const pct = total > 0 ? Math.round((st.count / total) * 100) : 0;
        funnelHtml += \`
          <div class="pipeline-stage">
            <div class="pipeline-stage-header">
              <span>\${st.label}</span>
              <span style="color:#0f172a; font-weight:700;">\${st.count} jobs <span style="font-weight:400; color:#64748b;">(\${pct}%)</span></span>
            </div>
            <div class="pipeline-progress-track">
              <div class="pipeline-progress-fill" style="width:\${Math.max(pct, 4)}%; background:\${st.color};"></div>
            </div>
          </div>
        \`;
      });
      funnelContainer.innerHTML = funnelHtml;

      // 5. Render County Distribution
      const countyContainer = document.getElementById('countyListContainer');
      let countyHtml = '';
      const countyEntries = Object.entries(countyCounts);
      countyEntries.forEach(([name, count]) => {
        const pct = total > 0 ? Math.round((count / total) * 100) : 0;
        countyHtml += \`
          <div class="county-item">
            <span class="county-name">\${name}</span>
            <div class="county-bar-track">
              <div class="county-bar-fill" style="width:\${Math.max(pct, 3)}%;"></div>
            </div>
            <span class="county-count">\${count}</span>
          </div>
        \`;
      });
      countyContainer.innerHTML = countyHtml;
    }

    // Quick Update Status
    async function quickUpdateStatus(id, newStatus) {
      try {
        const res = await fetch(\`/admin/api/bookings/\${id}\`, {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
            'x-csrf-token': csrfToken
          },
          body: JSON.stringify({ status: newStatus })
        });
        const data = await res.json();
        if (res.ok && data.success) {
          showToast(\`Status updated to \${newStatus}\`);
          loadMetrics();
        } else {
          showToast('Failed to update status');
          loadBookings();
        }
      } catch (err) {
        showToast('Error updating status');
      }
    }

    // Modal Details
    function openDetails(id) {
      const b = currentBookings.find(item => (item.bookingId === id || item._id === id));
      if (!b) return;

      document.getElementById('editBookingId').value = b.bookingId || b._id;
      document.getElementById('detailsModalTitle').textContent = \`Booking \${b.bookingId}\`;
      document.getElementById('editName').value = b.name || '';
      document.getElementById('editPhone').value = b.phone || '';
      document.getElementById('editEmail').value = b.email || '';
      document.getElementById('editService').value = b.serviceType || '';
      document.getElementById('editAddress').value = b.address || '';
      document.getElementById('editDate').value = b.preferredDate || '';
      document.getElementById('editTime').value = b.preferredTime || 'Morning (8am - 12pm)';
      document.getElementById('editStatus').value = b.status || 'Pending';
      document.getElementById('viewDescription').textContent = b.description || 'No description provided';
      document.getElementById('editNotes').value = b.adminNotes || '';

      const cleanPhone = (b.phone || '').replace(/\\D/g, '');
      const waText = encodeURIComponent(\`Hello \${b.name}, Houston Roofing & Construction regarding \${b.bookingId}.\`);
      document.getElementById('modalQuickLinks').innerHTML = \`
        <a href="tel:\${b.phone}" class="btn-action btn-outline" style="padding:4px 8px; font-size:0.75rem;">Call</a>
        <a href="https://wa.me/\${cleanPhone}?text=\${waText}" target="_blank" class="btn-action btn-outline" style="padding:4px 8px; font-size:0.75rem;">WhatsApp</a>
        \${b.email ? \`<a href="mailto:\${b.email}" class="btn-action btn-outline" style="padding:4px 8px; font-size:0.75rem;">Email</a>\` : ''}
      \`;

      document.getElementById('detailsModal').classList.add('open');
    }

    document.getElementById('detailsForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const id = document.getElementById('editBookingId').value;
      const payload = {
        name: document.getElementById('editName').value.trim(),
        phone: document.getElementById('editPhone').value.trim(),
        email: document.getElementById('editEmail').value.trim(),
        serviceType: document.getElementById('editService').value,
        address: document.getElementById('editAddress').value.trim(),
        preferredDate: document.getElementById('editDate').value,
        preferredTime: document.getElementById('editTime').value,
        status: document.getElementById('editStatus').value,
        adminNotes: document.getElementById('editNotes').value.trim()
      };

      try {
        const res = await fetch(\`/admin/api/bookings/\${id}\`, {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
            'x-csrf-token': csrfToken
          },
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (res.ok && data.success) {
          showToast('Booking details updated successfully');
          closeModal('detailsModal');
          loadBookings();
          loadMetrics();
        } else {
          showToast(data.error || 'Failed to update details');
        }
      } catch (err) {
        showToast('Error saving changes');
      }
    });

    // New Booking Modal
    function openNewModal() {
      document.getElementById('newBookingForm').reset();
      // Set today's date + 1 day as default
      const tomorrow = new Date();
      tomorrow.setDate(tomorrow.getDate() + 1);
      document.getElementById('newDate').value = tomorrow.toISOString().split('T')[0];
      document.getElementById('newModal').classList.add('open');
    }

    document.getElementById('newBookingForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const payload = {
        name: document.getElementById('newName').value.trim(),
        phone: document.getElementById('newPhone').value.trim(),
        email: document.getElementById('newEmail').value.trim(),
        serviceType: document.getElementById('newService').value,
        address: document.getElementById('newAddress').value.trim(),
        preferredDate: document.getElementById('newDate').value,
        preferredTime: document.getElementById('newTime').value,
        description: document.getElementById('newDescription').value.trim(),
        status: document.getElementById('newStatus').value
      };

      try {
        const res = await fetch('/admin/api/bookings', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-csrf-token': csrfToken
          },
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (res.ok && data.success) {
          showToast('Booking created: ' + data.booking.bookingId);
          closeModal('newModal');
          loadBookings();
          loadMetrics();
        } else {
          showToast(data.error || 'Failed to create booking');
        }
      } catch (err) {
        showToast('Error creating booking');
      }
    });

    // Delete Booking
    async function confirmDelete(id, name) {
      if (!confirm(\`Are you sure you want to permanently delete booking \${id} for \${name}?\`)) {
        return;
      }
      try {
        const res = await fetch(\`/admin/api/bookings/\${id}\`, {
          method: 'DELETE',
          headers: { 'x-csrf-token': csrfToken }
        });
        const data = await res.json();
        if (res.ok && data.success) {
          showToast('Booking deleted');
          loadBookings();
          loadMetrics();
        } else {
          showToast(data.error || 'Failed to delete');
        }
      } catch (err) {
        showToast('Error deleting booking');
      }
    }

    // Modal Close
    function closeModal(id) {
      document.getElementById(id).classList.remove('open');
    }

    // Export CSV
    function exportCsv() {
      window.location.href = '/admin/api/export';
    }

    // Search debounce
    let searchTimer;
    document.getElementById('searchInput').addEventListener('input', () => {
      clearTimeout(searchTimer);
      searchTimer = setTimeout(loadBookings, 250);
    });

    // Init
    loadMetrics();
    loadBookings();
  </script>
</body>
</html>`;
}

module.exports = router;
