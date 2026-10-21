/**
 * index.js
 * Root Express application for Houston Roofing & Construction.
 * Handles public website, online booking system, customer status lookup,
 * resilient MongoDB Atlas integration with in-memory fallback, and admin mounting.
 * Exports app for Vercel Serverless and listens on PORT (default 3000) when executed directly.
 */

const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const adminRouter = require('./admin');

const app = express();

// Middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Security headers middleware
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// --- Resilient MongoDB Atlas Connection & Data Service ---

let mongoClient = null;
let mongoDb = null;
let connectionStatus = 'uninitialized';

// In-memory fallback data so website and bookings NEVER crash if MongoDB is not configured or offline
const fallbackStore = [
  {
    bookingId: 'HRC-2026-8812',
    name: 'Robert Vance',
    phone: '(832) 555-0143',
    email: 'rvance@cypress-properties.com',
    address: '14210 Spring Cypress Rd, Cypress, TX 77429',
    serviceType: 'Full Roof Replacement',
    preferredDate: '2026-10-24',
    preferredTime: 'Morning (8am - 12pm)',
    description: 'Hail damage assessment needed after recent spring squall. 2-story architectural shingles.',
    status: 'Pending',
    adminNotes: 'Assigned to Lead Inspector Marcus. Drone survey requested.',
    createdAt: new Date('2026-10-20T14:32:00Z').toISOString(),
    updatedAt: new Date('2026-10-20T14:32:00Z').toISOString()
  },
  {
    bookingId: 'HRC-2026-8794',
    name: 'Elena Morales',
    phone: '(713) 555-8392',
    email: 'elena.morales@katymail.net',
    address: '22804 Kingsland Blvd, Katy, TX 77450',
    serviceType: 'Standing Seam Metal Roofing',
    preferredDate: '2026-10-25',
    preferredTime: 'Afternoon (12pm - 4pm)',
    description: 'Interested in standing seam metal roofing quote for farmhouse renovation.',
    status: 'Confirmed',
    adminNotes: 'Customer requested bronze color samples.',
    createdAt: new Date('2026-10-19T09:15:00Z').toISOString(),
    updatedAt: new Date('2026-10-19T10:00:00Z').toISOString()
  },
  {
    bookingId: 'HRC-2026-8720',
    name: 'David Henderson',
    phone: '(281) 555-4421',
    email: 'david.h@woodlandsdev.com',
    address: '9595 Six Pines Dr, The Woodlands, TX 77380',
    serviceType: 'Commercial Flat & TPO Systems',
    preferredDate: '2026-10-22',
    preferredTime: 'Morning (8am - 12pm)',
    description: 'Commercial strip plaza roof leak near HVAC curb unit.',
    status: 'In Progress',
    adminNotes: 'Crew on site. Flashing patch in progress.',
    createdAt: new Date('2026-10-18T11:45:00Z').toISOString(),
    updatedAt: new Date('2026-10-21T08:00:00Z').toISOString()
  }
];

async function getDatabase() {
  const uri = process.env.MONGODB_URI;
  if (!uri || !uri.startsWith('mongodb')) {
    connectionStatus = 'fallback_memory';
    return null;
  }

  if (mongoDb) {
    return mongoDb;
  }

  try {
    const { MongoClient } = require('mongodb');
    if (!mongoClient) {
      mongoClient = new MongoClient(uri, {
        serverSelectionTimeoutMS: 3000,
        connectTimeoutMS: 4000
      });
      await mongoClient.connect();
    }
    mongoDb = mongoClient.db();
    connectionStatus = 'mongodb_connected';
    // Ensure collection & index
    try {
      const col = mongoDb.collection('bookings');
      await col.createIndex({ bookingId: 1 }, { unique: true });
      await col.createIndex({ phone: 1 });
      await col.createIndex({ createdAt: -1 });
    } catch (e) {
      // index exists or non-fatal
    }
    return mongoDb;
  } catch (err) {
    console.warn('[MongoDB] Connection unavailable, seamlessly using resilient in-memory store:', err.message);
    connectionStatus = 'fallback_memory';
    return null;
  }
}

// Data service helpers
const dbService = {
  getStatus: () => ({
    type: connectionStatus === 'mongodb_connected' ? 'mongodb' : 'fallback',
    status: connectionStatus
  }),

  getBookings: async ({ search, status, service, sort } = {}) => {
    const db = await getDatabase();
    if (db) {
      try {
        const col = db.collection('bookings');
        const query = {};
        if (status) query.status = status;
        if (service) query.serviceType = service;
        if (search) {
          const regex = new RegExp(search, 'i');
          query.$or = [
            { bookingId: regex },
            { name: regex },
            { phone: regex },
            { address: regex },
            { email: regex }
          ];
        }
        let sortObj = { createdAt: -1 };
        if (sort === 'oldest') sortObj = { createdAt: 1 };
        if (sort === 'appointment') sortObj = { preferredDate: 1 };

        return await col.find(query).sort(sortObj).toArray();
      } catch (err) {
        console.warn('[MongoDB query error, falling back to memory]:', err.message);
      }
    }

    // Fallback store filter
    let results = [...fallbackStore];
    if (status) {
      results = results.filter(b => b.status === status);
    }
    if (service) {
      results = results.filter(b => b.serviceType === service);
    }
    if (search) {
      const term = search.toLowerCase();
      results = results.filter(b =>
        (b.bookingId && b.bookingId.toLowerCase().includes(term)) ||
        (b.name && b.name.toLowerCase().includes(term)) ||
        (b.phone && b.phone.includes(term)) ||
        (b.address && b.address.toLowerCase().includes(term)) ||
        (b.email && b.email.toLowerCase().includes(term))
      );
    }

    if (sort === 'oldest') {
      results.sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
    } else if (sort === 'appointment') {
      results.sort((a, b) => (a.preferredDate || '').localeCompare(b.preferredDate || ''));
    } else {
      results.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    }
    return results;
  },

  getBookingById: async (id) => {
    const db = await getDatabase();
    if (db) {
      try {
        const col = db.collection('bookings');
        const res = await col.findOne({ $or: [{ bookingId: id }, { _id: id }] });
        if (res) return res;
      } catch (e) {}
    }
    return fallbackStore.find(b => b.bookingId === id || b._id === id) || null;
  },

  createBooking: async (bookingData) => {
    const randomHex = crypto.randomBytes(2).toString('hex').toUpperCase();
    const bookingId = `HRC-2026-${randomHex}`;
    const now = new Date().toISOString();

    const record = {
      bookingId,
      name: bookingData.name.trim(),
      phone: bookingData.phone.trim(),
      email: (bookingData.email || '').trim(),
      address: bookingData.address.trim(),
      serviceType: bookingData.serviceType,
      preferredDate: bookingData.preferredDate,
      preferredTime: bookingData.preferredTime || 'Morning (8am - 12pm)',
      description: (bookingData.description || '').trim(),
      status: bookingData.status || 'Pending',
      adminNotes: bookingData.adminNotes || '',
      createdAt: now,
      updatedAt: now
    };

    const db = await getDatabase();
    if (db) {
      try {
        const col = db.collection('bookings');
        const inserted = await col.insertOne(record);
        record._id = inserted.insertedId;
        return record;
      } catch (err) {
        console.warn('[MongoDB insert failed, storing in fallback]:', err.message);
      }
    }

    record._id = 'mem_' + Date.now();
    fallbackStore.unshift(record);
    return record;
  },

  updateBooking: async (id, updateData) => {
    const now = new Date().toISOString();
    const fields = { ...updateData, updatedAt: now };
    delete fields._id;
    delete fields.bookingId;

    const db = await getDatabase();
    if (db) {
      try {
        const col = db.collection('bookings');
        const res = await col.findOneAndUpdate(
          { $or: [{ bookingId: id }, { _id: id }] },
          { $set: fields },
          { returnDocument: 'after' }
        );
        if (res) return res;
      } catch (e) {}
    }

    const index = fallbackStore.findIndex(b => b.bookingId === id || b._id === id);
    if (index !== -1) {
      fallbackStore[index] = { ...fallbackStore[index], ...fields };
      return fallbackStore[index];
    }
    return null;
  },

  deleteBooking: async (id) => {
    const db = await getDatabase();
    if (db) {
      try {
        const col = db.collection('bookings');
        const res = await col.deleteOne({ $or: [{ bookingId: id }, { _id: id }] });
        if (res.deletedCount > 0) return true;
      } catch (e) {}
    }

    const index = fallbackStore.findIndex(b => b.bookingId === id || b._id === id);
    if (index !== -1) {
      fallbackStore.splice(index, 1);
      return true;
    }
    return false;
  },

  getMetrics: async () => {
    const bookings = await dbService.getBookings({});
    const total = bookings.length;
    const pending = bookings.filter(b => b.status === 'Pending').length;
    const confirmed = bookings.filter(b => b.status === 'Confirmed').length;
    const inProgress = bookings.filter(b => b.status === 'In Progress').length;
    const completed = bookings.filter(b => b.status === 'Completed').length;
    const cancelled = bookings.filter(b => b.status === 'Cancelled').length;

    return { total, pending, confirmed, inProgress, completed, cancelled };
  }
};

// Share dbService with admin router
app.locals.dbService = dbService;

// Mount Admin router at /admin
app.use('/admin', adminRouter);

// --- Public APIs ---

// Booking submission with server-side validation and duplicate suppression
app.post('/api/bookings', async (req, res) => {
  try {
    const { name, phone, email, address, serviceType, preferredDate, preferredTime, description } = req.body || {};

    // Validation
    if (!name || typeof name !== 'string' || name.trim().length < 2) {
      return res.status(400).json({ error: 'Please enter your full name (minimum 2 characters).' });
    }

    const cleanPhone = (phone || '').replace(/\D/g, '');
    if (cleanPhone.length < 10) {
      return res.status(400).json({ error: 'Please enter a valid 10-digit US phone number.' });
    }

    if (!address || typeof address !== 'string' || address.trim().length < 5) {
      return res.status(400).json({ error: 'Please provide a valid property address in Greater Houston.' });
    }

    if (!serviceType) {
      return res.status(400).json({ error: 'Please select a roofing service.' });
    }

    if (!preferredDate) {
      return res.status(400).json({ error: 'Please select your preferred date for inspection.' });
    }

    // Check duplicate bookings within the last 24 hours with exact same phone & address
    const existing = await dbService.getBookings({});
    const twentyFourHoursAgo = Date.now() - 24 * 60 * 60 * 1000;
    const duplicate = existing.find(b => {
      const bPhone = (b.phone || '').replace(/\D/g, '');
      const isRecent = new Date(b.createdAt).getTime() > twentyFourHoursAgo;
      return isRecent && bPhone === cleanPhone && b.address.toLowerCase() === address.trim().toLowerCase();
    });

    if (duplicate) {
      return res.json({
        success: true,
        isDuplicate: true,
        booking: duplicate,
        message: `An active booking (${duplicate.bookingId}) was recently submitted for this address. Our team is already processing it!`
      });
    }

    const newBooking = await dbService.createBooking({
      name,
      phone,
      email,
      address,
      serviceType,
      preferredDate,
      preferredTime,
      description
    });

    res.json({
      success: true,
      booking: newBooking,
      message: `Your free inspection request has been confirmed! Your Booking Reference ID is ${newBooking.bookingId}.`
    });
  } catch (err) {
    console.error('Booking submission error:', err);
    res.status(500).json({ error: 'An unexpected error occurred while booking. Please call (832) 237-3737.' });
  }
});

// Self-service customer status lookup
app.get('/api/bookings/lookup', async (req, res) => {
  const { id } = req.query;
  if (!id || typeof id !== 'string') {
    return res.status(400).json({ error: 'Please enter a valid Booking Reference ID (e.g., HRC-2026-XXXX).' });
  }

  const cleanId = id.trim().toUpperCase();
  const booking = await dbService.getBookingById(cleanId);
  if (!booking) {
    return res.status(404).json({ error: `No active booking found matching "${cleanId}". Please verify your reference number or call (832) 237-3737.` });
  }

  res.json({
    success: true,
    booking: {
      bookingId: booking.bookingId,
      name: booking.name,
      serviceType: booking.serviceType,
      preferredDate: booking.preferredDate,
      preferredTime: booking.preferredTime,
      status: booking.status,
      createdAt: booking.createdAt,
      adminNotes: booking.adminNotes ? 'Inspector assigned. Schedule on track.' : 'Awaiting team assignment'
    }
  });
});

// System Health API
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'Houston Roofing & Construction Platform',
    database: dbService.getStatus(),
    time: new Date().toISOString()
  });
});

// Render Main Public Website
app.get('/', (req, res) => {
  res.send(renderPublicWebsite());
});

// Fallback for unknown routes
app.use((req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'API endpoint not found' });
  }
  res.redirect('/');
});

// Start listener for standalone/dev server execution (port 3000)
const PORT = process.env.PORT || 3000;
if (require.main === module && !process.env.VERCEL) {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Houston Roofing & Construction platform running on http://0.0.0.0:${PORT}`);
  });
}

// Export for Vercel Serverless Function
module.exports = app;

// --- Public Website HTML, CSS & Client-Side Logic ---

function renderPublicWebsite() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Houston Roofing &amp; Construction | Roof Replacement, Repairs &amp; Inspections</title>
  <meta name="description" content="Houston's trusted roofing contractor. Free photo-documented roof inspections, tiered Good/Better/Best pricing, architectural shingles, and standing seam metal. Call (832) 237-3737.">
  <meta property="og:title" content="Houston Roofing &amp; Construction | Roof Replacement, Repairs &amp; Inspections">
  <meta property="og:description" content="Free photo-documented inspections, tiered pricing, and lifetime roofing across Greater Houston and 18 Texas counties.">
  <meta property="og:type" content="website">

  <!-- Schema.org Structured Data -->
  <script type="application/ld+json">
  {
    "@context": "https://schema.org",
    "@type": "RoofingContractor",
    "name": "Houston Roofing & Construction",
    "telephone": "+1-832-237-3737",
    "email": "info@houstonroofing.com",
    "address": {
      "@type": "PostalAddress",
      "streetAddress": "11330 West Rd",
      "addressLocality": "Houston",
      "addressRegion": "TX",
      "postalCode": "77065",
      "addressCountry": "US"
    },
    "openingHoursSpecification": [
      {
        "@type": "OpeningHoursSpecification",
        "dayOfWeek": ["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"],
        "opens": "07:00",
        "closes": "20:00"
      }
    ],
    "areaServed": [
      "Harris County, TX", "Montgomery County, TX", "Fort Bend County, TX",
      "Brazoria County, TX", "Galveston County, TX", "Waller County, TX",
      "Liberty County, TX", "Chambers County, TX"
    ]
  }
  </script>

  <style>
    /* 80:15:5 Design System Tokens */
    :root {
      --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      --font-serif: "Georgia", "Cambria", serif;

      /* Palette: warm off-white, charcoal, construction orange, deep blue */
      --color-canvas: #f8fafc;
      --color-surface: #ffffff;
      --color-surface-dark: #0f172a;
      --color-slate-800: #1e293b;
      --color-slate-600: #475569;
      --color-slate-400: #94a3b8;
      --color-border: #e2e8f0;

      --color-orange-500: #f59e0b;
      --color-orange-600: #d97706;
      --color-orange-deep: #ea580c;
      --color-blue-deep: #1e3a8a;
      --color-blue-dark: #0f2b5c;
      --color-teal-600: #0d9488;
      --color-teal-50: #f0fdfa;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    html { scroll-behavior: smooth; }
    body {
      font-family: var(--font-sans);
      background-color: var(--color-canvas);
      color: var(--color-slate-800);
      line-height: 1.5;
      -webkit-font-smoothing: antialiased;
    }

    .container {
      max-width: 1200px;
      margin: 0 auto;
      padding: 0 1.5rem;
    }

    /* Live Weather Alert Banner */
    .top-notice-bar {
      background: #78350f;
      color: #fef3c7;
      font-size: 0.8125rem;
      padding: 0.5rem 1rem;
      text-align: center;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 0.5rem;
    }

    /* 15% Glassmorphic Header */
    .site-header {
      position: sticky;
      top: 0;
      z-index: 999;
      background: rgba(15, 23, 42, 0.92);
      backdrop-filter: blur(14px);
      -webkit-backdrop-filter: blur(14px);
      border-bottom: 1px solid rgba(255, 255, 255, 0.08);
      padding: 0.875rem 0;
    }
    .nav-container {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1.5rem;
    }
    .brand-wordmark {
      display: inline-flex;
      flex-direction: column;
      text-decoration: none;
      color: #ffffff;
    }
    .brand-wordmark .title {
      font-size: 1.1875rem;
      font-weight: 800;
      letter-spacing: -0.01em;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .brand-wordmark .tagline {
      font-size: 0.6875rem;
      color: var(--color-orange-500);
      text-transform: uppercase;
      letter-spacing: 0.08em;
      margin-left: 1.75rem;
    }

    .nav-links {
      display: flex;
      align-items: center;
      list-style: none;
      gap: 1.25rem;
    }
    .nav-link {
      color: #cbd5e1;
      text-decoration: none;
      font-size: 0.875rem;
      font-weight: 500;
      transition: color 0.15s ease;
    }
    .nav-link:hover { color: #ffffff; }

    .nav-actions {
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }

    /* Buttons */
    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 0.5rem;
      font-size: 0.875rem;
      font-weight: 700;
      padding: 0.625rem 1.25rem;
      border-radius: 8px;
      text-decoration: none;
      cursor: pointer;
      transition: all 0.15s ease;
      border: 1px solid transparent;
    }
    /* 5% Claymorphic Primary CTA */
    .btn-clay-primary {
      background: var(--color-orange-500);
      color: #0f172a;
      box-shadow: 0 4px 6px -1px rgba(245, 158, 11, 0.35),
                  0 2px 4px -2px rgba(245, 158, 11, 0.3),
                  inset 0 1px 0 rgba(255, 255, 255, 0.4),
                  inset 0 -2px 0 rgba(180, 83, 9, 0.4);
    }
    .btn-clay-primary:hover {
      background: var(--color-orange-600);
      color: #ffffff;
    }
    .btn-clay-primary:active {
      transform: translateY(1px);
    }

    .btn-ghost-light {
      background: rgba(255, 255, 255, 0.1);
      border-color: rgba(255, 255, 255, 0.2);
      color: #ffffff;
      backdrop-filter: blur(6px);
    }
    .btn-ghost-light:hover {
      background: rgba(255, 255, 255, 0.2);
    }

    .btn-flat-secondary {
      background: #ffffff;
      border: 1px solid var(--color-border);
      color: var(--color-slate-800);
    }
    .btn-flat-secondary:hover {
      background: #f1f5f9;
      border-color: #cbd5e1;
    }

    .btn-whatsapp {
      background: #25D366;
      color: #ffffff;
    }
    .btn-whatsapp:hover {
      background: #20bd5a;
    }

    /* Hero Section (15% Glassmorphic overlays) */
    .hero-section {
      position: relative;
      background-color: var(--color-surface-dark);
      background-image: linear-gradient(135deg, rgba(15, 23, 42, 0.94) 0%, rgba(15, 43, 92, 0.88) 100%),
                        url('https://images.unsplash.com/photo-1513694203232-719a280e022f?auto=format&fit=crop&w=1920&q=80');
      background-size: cover;
      background-position: center;
      color: #ffffff;
      padding: 5.5rem 0 4.5rem;
      overflow: hidden;
    }
    .hero-content {
      position: relative;
      z-index: 2;
      max-width: 720px;
    }
    .hero-eyebrow {
      text-transform: uppercase;
      font-size: 0.8125rem;
      font-weight: 800;
      letter-spacing: 0.12em;
      color: var(--color-orange-500);
      margin-bottom: 0.75rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .hero-title {
      font-size: 2.75rem;
      line-height: 1.15;
      font-weight: 800;
      color: #ffffff;
      margin-bottom: 1.25rem;
      letter-spacing: -0.02em;
    }
    .hero-desc {
      font-size: 1.125rem;
      color: #cbd5e1;
      line-height: 1.6;
      margin-bottom: 2rem;
    }
    .hero-cta-group {
      display: flex;
      align-items: center;
      gap: 1rem;
      flex-wrap: wrap;
      margin-bottom: 2rem;
    }
    .hero-badges-list {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      font-size: 0.8125rem;
      color: #94a3b8;
      flex-wrap: wrap;
    }
    .hero-badges-list .sep { color: #475569; }

    /* Trust Strip */
    .trust-strip {
      background: #ffffff;
      border-bottom: 1px solid var(--color-border);
      padding: 1.25rem 0;
    }
    .trust-badges {
      display: flex;
      align-items: center;
      justify-content: space-around;
      gap: 1.5rem;
      flex-wrap: wrap;
    }
    .trust-badge-item {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      font-size: 0.875rem;
      font-weight: 600;
      color: var(--color-slate-800);
    }
    .trust-badge-item svg { color: var(--color-orange-500); }

    /* 80% Soft Flat Cards & Sections */
    .section-py { padding: 5rem 0; }
    .section-header {
      text-align: center;
      max-width: 640px;
      margin: 0 auto 3.5rem;
    }
    .section-eyebrow {
      text-transform: uppercase;
      font-size: 0.8125rem;
      font-weight: 800;
      color: var(--color-orange-600);
      letter-spacing: 0.08em;
      margin-bottom: 0.5rem;
    }
    .section-title {
      font-size: 2rem;
      font-weight: 800;
      color: var(--color-slate-800);
      letter-spacing: -0.01em;
      line-height: 1.25;
    }
    .section-desc {
      color: var(--color-slate-600);
      margin-top: 0.75rem;
      font-size: 1rem;
    }

    .card-flat {
      background: #ffffff;
      border: 1px solid var(--color-border);
      border-radius: 12px;
      padding: 1.75rem;
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.04);
      transition: transform 0.15s ease, box-shadow 0.15s ease;
    }
    .card-flat:hover {
      transform: translateY(-2px);
      box-shadow: 0 8px 16px -4px rgba(0, 0, 0, 0.06);
    }

    /* Process Steps Grid */
    .grid-4 {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 1.5rem;
    }
    .step-num {
      font-family: var(--font-serif);
      font-size: 2.25rem;
      font-weight: 700;
      color: var(--color-orange-500);
      line-height: 1;
    }

    /* Services Bento */
    .grid-3 {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 1.5rem;
    }

    /* Tiered Matrix */
    .tier-card {
      position: relative;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }
    .tier-card.featured {
      border: 2px solid var(--color-orange-500);
      box-shadow: 0 8px 24px -6px rgba(245, 158, 11, 0.2);
    }
    .featured-badge {
      position: absolute;
      top: -12px;
      right: 1.5rem;
      background: var(--color-orange-500);
      color: #0f172a;
      font-size: 0.6875rem;
      font-weight: 800;
      padding: 3px 10px;
      border-radius: 12px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }

    /* Project Gallery */
    .gallery-filter-tabs {
      display: flex;
      justify-content: center;
      gap: 0.5rem;
      margin-bottom: 2.5rem;
      flex-wrap: wrap;
    }
    .filter-tab {
      background: #ffffff;
      border: 1px solid var(--color-border);
      padding: 0.5rem 1rem;
      border-radius: 20px;
      font-size: 0.8125rem;
      font-weight: 600;
      color: var(--color-slate-600);
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .filter-tab.active, .filter-tab:hover {
      background: var(--color-slate-800);
      color: #ffffff;
      border-color: var(--color-slate-800);
    }
    .project-card {
      background: #ffffff;
      border: 1px solid var(--color-border);
      border-radius: 12px;
      overflow: hidden;
      display: flex;
      flex-direction: column;
    }
    .project-img {
      height: 200px;
      background-size: cover;
      background-position: center;
    }
    .project-body {
      padding: 1.25rem;
      flex: 1;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }

    /* Statistics Counter Strip */
    .stats-strip {
      background: var(--color-surface-dark);
      color: #ffffff;
      padding: 4rem 0;
    }
    .stat-num {
      font-family: var(--font-serif);
      font-size: 2.75rem;
      font-weight: 800;
      color: var(--color-orange-500);
      line-height: 1;
    }

    /* Booking System Section */
    .booking-section {
      background: #ffffff;
      border-top: 1px solid var(--color-border);
      border-bottom: 1px solid var(--color-border);
    }
    .booking-layout {
      display: grid;
      grid-template-columns: 1fr 1.35fr;
      gap: 3rem;
      align-items: flex-start;
    }
    .booking-form-box {
      background: var(--color-canvas);
      border: 1px solid var(--color-border);
      border-radius: 14px;
      padding: 2.25rem;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);
    }
    .form-grid-2 {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 1rem;
      margin-bottom: 1rem;
    }
    .form-group { margin-bottom: 1rem; }
    .form-label {
      display: block;
      font-size: 0.8125rem;
      font-weight: 700;
      color: var(--color-slate-800);
      margin-bottom: 0.375rem;
    }
    .form-control {
      width: 100%;
      padding: 0.6875rem 0.875rem;
      border: 1px solid var(--color-border);
      border-radius: 8px;
      font-size: 0.875rem;
      background: #ffffff;
      color: var(--color-slate-800);
      outline: none;
      transition: border-color 0.15s ease, box-shadow 0.15s ease;
    }
    .form-control:focus {
      border-color: var(--color-orange-500);
      box-shadow: 0 0 0 3px rgba(245, 158, 11, 0.2);
    }
    textarea.form-control { resize: vertical; min-height: 80px; }

    /* Success confirmation box */
    .booking-result {
      display: none;
      background: #ffffff;
      border: 2px solid #10b981;
      border-radius: 12px;
      padding: 2rem;
      text-align: center;
      animation: fadeIn 0.2s ease;
    }
    .ref-pill {
      display: inline-block;
      background: #f0fdf4;
      border: 1px dashed #10b981;
      color: #047857;
      font-size: 1.25rem;
      font-weight: 800;
      padding: 0.5rem 1.25rem;
      border-radius: 8px;
      margin: 1rem 0;
      letter-spacing: 0.05em;
    }

    /* FAQ Accordion */
    .faq-list {
      max-width: 800px;
      margin: 0 auto;
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
    }
    .faq-item {
      background: #ffffff;
      border: 1px solid var(--color-border);
      border-radius: 10px;
      overflow: hidden;
    }
    .faq-header {
      padding: 1.125rem 1.5rem;
      font-weight: 700;
      font-size: 0.9375rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      cursor: pointer;
      user-select: none;
    }
    .faq-body {
      padding: 0 1.5rem 1.25rem;
      font-size: 0.875rem;
      color: var(--color-slate-600);
      line-height: 1.6;
      display: none;
    }
    .faq-item.open .faq-body { display: block; }
    .faq-item.open .faq-chevron { transform: rotate(180deg); }
    .faq-chevron { transition: transform 0.2s ease; }

    /* Sticky Mobile Action Bar */
    .mobile-bar {
      display: none;
      position: fixed;
      bottom: 0;
      left: 0;
      right: 0;
      background: rgba(15, 23, 42, 0.95);
      backdrop-filter: blur(10px);
      padding: 0.75rem 1rem;
      z-index: 998;
      box-shadow: 0 -4px 10px rgba(0, 0, 0, 0.15);
      border-top: 1px solid rgba(255, 255, 255, 0.1);
    }
    .mobile-bar-inner {
      display: flex;
      gap: 0.75rem;
    }

    /* Site Footer */
    .site-footer {
      background: var(--color-surface-dark);
      color: #94a3b8;
      padding: 4.5rem 0 2rem;
      font-size: 0.875rem;
    }
    .footer-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 2.5rem;
      margin-bottom: 3rem;
    }
    .footer-title {
      color: #ffffff;
      font-size: 0.9375rem;
      font-weight: 700;
      margin-bottom: 1rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .footer-links {
      list-style: none;
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
    }
    .footer-links a {
      color: #94a3b8;
      text-decoration: none;
      transition: color 0.15s ease;
    }
    .footer-links a:hover { color: #ffffff; }

    /* Texas Statutory Disclosure */
    .compliance-box {
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 8px;
      padding: 1.25rem;
      font-size: 0.75rem;
      line-height: 1.6;
      color: #94a3b8;
      margin-bottom: 2.5rem;
    }
    .compliance-box strong { color: #cbd5e1; }

    @media (max-width: 900px) {
      .nav-links { display: none; }
      .hero-title { font-size: 2.125rem; }
      .booking-layout { grid-template-columns: 1fr; }
      .mobile-bar { display: block; }
      body { padding-bottom: 4rem; }
    }
  </style>
</head>
<body>

  <!-- Weather & Inspection Notice Strip -->
  <div class="top-notice-bar">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
    <span><strong>Greater Houston Storm Assessment Alert:</strong> Rapid inspection crews available today across Harris, Montgomery, Fort Bend, and Galveston counties.</span>
  </div>

  <!-- Main Navigation Header (15% Glassmorphism) -->
  <header class="site-header">
    <div class="container nav-container">
      <a href="/" class="brand-wordmark">
        <span class="title">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="var(--color-orange-500)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>
          Houston Roofing
        </span>
        <span class="tagline">&amp; Construction · Concept</span>
      </a>

      <nav aria-label="Primary Navigation">
        <ul class="nav-links">
          <li><a href="#services" class="nav-link">Services</a></li>
          <li><a href="#process" class="nav-link">Our Process</a></li>
          <li><a href="#pricing" class="nav-link">Tiered Options</a></li>
          <li><a href="#gallery" class="nav-link">Projects</a></li>
          <li><a href="#reviews" class="nav-link">Reviews</a></li>
          <li><a href="#tracker" class="nav-link">Track Booking</a></li>
          <li><a href="#faq" class="nav-link">FAQ</a></li>
        </ul>
      </nav>

      <div class="nav-actions">
        <a href="tel:+18322373737" class="btn btn-ghost-light" style="padding: 0.5rem 0.875rem;">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"/></svg>
          (832) 237-3737
        </a>
        <a href="#book" class="btn btn-clay-primary">Book Inspection</a>
      </div>
    </div>
  </header>

  <main>
    <!-- Hero Section -->
    <section class="hero-section">
      <div class="container hero-content">
        <div class="hero-eyebrow">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
          Houston Roofing, Done Honestly
        </div>
        <h1 class="hero-title">
          A roof you can trust.<br>A process you can see.
        </h1>
        <p class="hero-desc">
          Book a free inspection online, get photo-documented options with tiered Good/Better/Best pricing, and track your project live from start to final inspection.
        </p>

        <div class="hero-cta-group">
          <a href="#book" class="btn btn-clay-primary" style="font-size:1.0625rem; padding:0.875rem 2rem;">
            Book a Free Inspection
          </a>
          <a href="tel:+18322373737" class="btn btn-ghost-light" style="font-size:1.0625rem; padding:0.875rem 1.75rem;">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"/></svg>
            Call (832) 237-3737
          </a>
          <a href="https://wa.me/18322373737?text=Hello%20Houston%20Roofing,%20I%20would%20like%20to%20request%20an%20inspection" target="_blank" class="btn btn-whatsapp" style="font-size:1.0625rem; padding:0.875rem 1.5rem;">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"/></svg>
            WhatsApp Us
          </a>
        </div>

        <div class="hero-badges-list">
          <span>Mon–Sun 7am–8pm</span>
          <span class="sep">·</span>
          <span>No High-Pressure Sales</span>
          <span class="sep">·</span>
          <span>In-House Project Managers</span>
          <span class="sep">·</span>
          <span>11330 West Rd, Houston, TX</span>
        </div>
      </div>
    </section>

    <!-- Trust Credentials Strip -->
    <section class="trust-strip">
      <div class="container">
        <div class="trust-badges">
          <div class="trust-badge-item">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="var(--color-orange-500)" stroke="var(--color-orange-500)" stroke-width="1.5"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
            <span>4.9 on Google (~325 reviews)</span>
          </div>
          <div class="trust-badge-item">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            <span>BBB A+ Accredited</span>
          </div>
          <div class="trust-badge-item">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><circle cx="12" cy="8" r="6"/><polyline points="8.21 13.89 7 23 12 20 17 23 15.79 13.88"/></svg>
            <span>GAF Master Elite (Top 2%)</span>
          </div>
          <div class="trust-badge-item">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
            <span>RCAT Licensed Contractor</span>
          </div>
          <div class="trust-badge-item">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M17.7 7.7a2.5 2.5 0 1 1 1.8 4.3H2"/><path d="M9.6 4.6A2 2 0 1 1 11 8H2"/><path d="M12.6 19.4A2 2 0 1 0 14 16H2"/></svg>
            <span>FORTIFIED Roof Standard</span>
          </div>
        </div>
      </div>
    </section>

    <!-- 4-Step Process Section -->
    <section id="process" class="section-py" style="background-color: var(--color-canvas);">
      <div class="container">
        <div class="section-header">
          <p class="section-eyebrow">Our 4-Step Process</p>
          <h2 class="section-title">We inspect. We show you. You decide.</h2>
          <p class="section-desc">No high-pressure sales pitches. Our certified specialists document your roof's exact condition with high-resolution photos and diagnostic notes.</p>
        </div>

        <div class="grid-4">
          <div class="card-flat">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1rem;">
              <span class="step-num">01</span>
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--color-orange-500)" stroke-width="2.2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            </div>
            <h3 style="margin-bottom:0.5rem; font-size:1.125rem;">Inspect</h3>
            <p style="font-size:0.9375rem; color:var(--color-slate-600);">We examine the complete envelope: architectural shingles, underlayment, valley lines, flashing, chimney collars, and attic ventilation.</p>
          </div>

          <div class="card-flat">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1rem;">
              <span class="step-num">02</span>
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--color-orange-500)" stroke-width="2.2"><path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="4"/></svg>
            </div>
            <h3 style="margin-bottom:0.5rem; font-size:1.125rem;">Show</h3>
            <p style="font-size:0.9375rem; color:var(--color-slate-600);">You see what we see. We photograph every area of concern, hail strike, and wind crease so you have clear visual proof.</p>
          </div>

          <div class="card-flat">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1rem;">
              <span class="step-num">03</span>
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--color-orange-500)" stroke-width="2.2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
            </div>
            <h3 style="margin-bottom:0.5rem; font-size:1.125rem;">Explain</h3>
            <p style="font-size:0.9375rem; color:var(--color-slate-600);">We provide honest repair vs. replacement options with transparent Good, Better, and Best pricing tiers so you choose what fits your budget.</p>
          </div>

          <div class="card-flat">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1rem;">
              <span class="step-num">04</span>
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--color-orange-500)" stroke-width="2.2"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg>
            </div>
            <h3 style="margin-bottom:0.5rem; font-size:1.125rem;">Install</h3>
            <p style="font-size:0.9375rem; color:var(--color-slate-600);">Our dedicated on-site project manager oversees your crew from tear-off and weather barrier installation to triple magnetic nail sweeps.</p>
          </div>
        </div>
      </div>
    </section>

    <!-- Services Bento Section -->
    <section id="services" class="section-py" style="background-color: var(--color-surface);">
      <div class="container">
        <div style="display:flex; justify-content:space-between; align-items:flex-end; margin-bottom:3rem; flex-wrap:wrap; gap:1.5rem;">
          <div>
            <p class="section-eyebrow">Comprehensive Roofing &amp; Exteriors</p>
            <h2 class="section-title">Built for Houston Heat, Wind &amp; Storms</h2>
          </div>
          <a href="#book" class="btn btn-flat-secondary">Schedule an Inspection &rarr;</a>
        </div>

        <div class="grid-3">
          <!-- Service 1 -->
          <div class="card-flat" style="display:flex; flex-direction:column; justify-content:space-between;">
            <div>
              <div style="font-size:0.75rem; font-weight:700; color:var(--color-slate-400); text-transform:uppercase; margin-bottom:0.5rem;">Residential · 1–2 Day Install</div>
              <h3 style="font-size:1.25rem; margin-bottom:0.5rem;">Asphalt Shingle Replacement</h3>
              <p style="font-size:0.9375rem; color:var(--color-slate-600); margin-bottom:1.25rem;">
                Full tear-off and multi-layer installation using wind-rated architectural shingles engineered for intense Gulf Coast humidity and UV exposure.
              </p>
            </div>
            <div style="display:flex; justify-content:space-between; align-items:center; padding-top:1rem; border-top:1px solid var(--color-border);">
              <span style="font-size:0.8125rem; font-weight:700; color:var(--color-slate-800);">Tiered Good/Better/Best</span>
              <a href="#book" onclick="selectService('Asphalt Shingle Replacement')" style="font-size:0.875rem; font-weight:700; color:var(--color-orange-600); text-decoration:none;">Book &rarr;</a>
            </div>
          </div>

          <!-- Service 2 -->
          <div class="card-flat" style="display:flex; flex-direction:column; justify-content:space-between;">
            <div>
              <div style="font-size:0.75rem; font-weight:700; color:var(--color-slate-400); text-transform:uppercase; margin-bottom:0.5rem;">Residential &amp; Commercial · 50+ Year Life</div>
              <h3 style="font-size:1.25rem; margin-bottom:0.5rem;">Standing Seam Metal Roofing</h3>
              <p style="font-size:0.9375rem; color:var(--color-slate-600); margin-bottom:1.25rem;">
                Concealed-fastener 24-gauge standing seam metal roof systems providing supreme radiant heat reflection and class-leading hurricane wind uplift resistance.
              </p>
            </div>
            <div style="display:flex; justify-content:space-between; align-items:center; padding-top:1rem; border-top:1px solid var(--color-border);">
              <span style="font-size:0.8125rem; font-weight:700; color:var(--color-slate-800);">Energy-Reflective</span>
              <a href="#book" onclick="selectService('Standing Seam Metal Roofing')" style="font-size:0.875rem; font-weight:700; color:var(--color-orange-600); text-decoration:none;">Book &rarr;</a>
            </div>
          </div>

          <!-- Service 3 -->
          <div class="card-flat" style="display:flex; flex-direction:column; justify-content:space-between;">
            <div>
              <div style="font-size:0.75rem; font-weight:700; color:var(--color-slate-400); text-transform:uppercase; margin-bottom:0.5rem;">Emergency &amp; Storm Recovery</div>
              <h3 style="font-size:1.25rem; margin-bottom:0.5rem;">Roof Repair &amp; Hail Assessments</h3>
              <p style="font-size:0.9375rem; color:var(--color-slate-600); margin-bottom:1.25rem;">
                Fast leak tracing, pipe collar resealing, and objective hail impact inspections. We supply photographic proof and written diagnostic reports.
              </p>
            </div>
            <div style="display:flex; justify-content:space-between; align-items:center; padding-top:1rem; border-top:1px solid var(--color-border);">
              <span style="font-size:0.8125rem; font-weight:700; color:var(--color-slate-800);">Repair-First Mindset</span>
              <a href="#book" onclick="selectService('Roof Repair &amp; Hail Assessments')" style="font-size:0.875rem; font-weight:700; color:var(--color-orange-600); text-decoration:none;">Book &rarr;</a>
            </div>
          </div>

          <!-- Service 4 -->
          <div class="card-flat" style="display:flex; flex-direction:column; justify-content:space-between;">
            <div>
              <div style="font-size:0.75rem; font-weight:700; color:var(--color-slate-400); text-transform:uppercase; margin-bottom:0.5rem;">Commercial · TPO, PVC &amp; Mod-Bit</div>
              <h3 style="font-size:1.25rem; margin-bottom:0.5rem;">Commercial Flat &amp; Low-Slope</h3>
              <p style="font-size:0.9375rem; color:var(--color-slate-600); margin-bottom:1.25rem;">
                Single-ply white reflective TPO membranes, PVC, modified bitumen, and custom tapered insulation systems scheduled around commercial tenant hours.
              </p>
            </div>
            <div style="display:flex; justify-content:space-between; align-items:center; padding-top:1rem; border-top:1px solid var(--color-border);">
              <span style="font-size:0.8125rem; font-weight:700; color:var(--color-slate-800);">Business-Friendly</span>
              <a href="#book" onclick="selectService('Commercial Flat &amp; TPO Systems')" style="font-size:0.875rem; font-weight:700; color:var(--color-orange-600); text-decoration:none;">Book &rarr;</a>
            </div>
          </div>

          <!-- Service 5 -->
          <div class="card-flat" style="display:flex; flex-direction:column; justify-content:space-between;">
            <div>
              <div style="font-size:0.75rem; font-weight:700; color:var(--color-slate-400); text-transform:uppercase; margin-bottom:0.5rem;">Multi-Family · Phased Logistics</div>
              <h3 style="font-size:1.25rem; margin-bottom:0.5rem;">Apartment &amp; HOA Communities</h3>
              <p style="font-size:0.9375rem; color:var(--color-slate-600); margin-bottom:1.25rem;">
                Building-by-building phased replacements with dedicated on-site safety coordinators, resident parking notices, and board presentation packets.
              </p>
            </div>
            <div style="display:flex; justify-content:space-between; align-items:center; padding-top:1rem; border-top:1px solid var(--color-border);">
              <span style="font-size:0.8125rem; font-weight:700; color:var(--color-slate-800);">Resident-Aware</span>
              <a href="#book" onclick="selectService('Apartment &amp; HOA Communities')" style="font-size:0.875rem; font-weight:700; color:var(--color-orange-600); text-decoration:none;">Book &rarr;</a>
            </div>
          </div>

          <!-- Service 6 -->
          <div class="card-flat" style="display:flex; flex-direction:column; justify-content:space-between;">
            <div>
              <div style="font-size:0.75rem; font-weight:700; color:var(--color-slate-400); text-transform:uppercase; margin-bottom:0.5rem;">Exteriors · Hardie Siding &amp; Trim</div>
              <h3 style="font-size:1.25rem; margin-bottom:0.5rem;">Fiber Cement &amp; Siding</h3>
              <p style="font-size:0.9375rem; color:var(--color-slate-600); margin-bottom:1.25rem;">
                Rot-resistant fiber cement siding installed with integrated moisture barriers to defend framing studs against driving rain and Gulf Coast humidity.
              </p>
            </div>
            <div style="display:flex; justify-content:space-between; align-items:center; padding-top:1rem; border-top:1px solid var(--color-border);">
              <span style="font-size:0.8125rem; font-weight:700; color:var(--color-slate-800);">Moisture Barrier</span>
              <a href="#book" onclick="selectService('Fiber Cement &amp; Siding')" style="font-size:0.875rem; font-weight:700; color:var(--color-orange-600); text-decoration:none;">Book &rarr;</a>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- Tiered Good / Better / Best Matrix Section -->
    <section id="pricing" class="section-py" style="background-color: var(--color-canvas);">
      <div class="container">
        <div class="section-header">
          <p class="section-eyebrow">Tiered Transparency</p>
          <h2 class="section-title">Good / Better / Best Options</h2>
          <p class="section-desc">Every written proposal we deliver breaks down clear tiered options. You choose the exact warranty coverage, storm resilience, and budget that fits how long you plan to own the property.</p>
        </div>

        <div class="grid-3">
          <!-- Good Tier -->
          <div class="card-flat tier-card">
            <div>
              <span style="font-size:0.75rem; font-weight:800; color:var(--color-slate-400); text-transform:uppercase;">Tier 1</span>
              <h3 style="margin:0.25rem 0 0.5rem; font-size:1.25rem;">Good: Dependable</h3>
              <p style="font-size:0.875rem; color:var(--color-slate-600); margin-bottom:1.25rem;">
                Cost-conscious, code-compliant shingle system built for reliable protection against Houston heat.
              </p>
              <div style="background:#f1f5f9; padding:0.75rem; border-radius:6px; font-size:0.8125rem; margin-bottom:1.25rem;">
                <strong>Best For:</strong> Budget-conscious repairs, rental properties, or near-term sales.
              </div>
              <ul style="list-style:none; font-size:0.875rem; display:flex; flex-direction:column; gap:0.625rem; color:var(--color-slate-800);">
                <li style="display:flex; gap:0.5rem;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--color-teal-600)" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Architectural 3-tab / laminate shingles</li>
                <li style="display:flex; gap:0.5rem;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--color-teal-600)" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Standard synthetic underlayment</li>
                <li style="display:flex; gap:0.5rem;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--color-teal-600)" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Code-compliant ridge ventilation</li>
                <li style="display:flex; gap:0.5rem;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--color-teal-600)" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> 25-Year Standard Manufacturer Warranty</li>
              </ul>
            </div>
            <div style="margin-top:2rem;">
              <a href="#book" onclick="selectService('Asphalt Shingle Replacement')" class="btn btn-flat-secondary" style="width:100%;">Select Tier 1</a>
            </div>
          </div>

          <!-- Better Tier (Most Popular) -->
          <div class="card-flat tier-card featured">
            <div class="featured-badge">Most Popular in Houston</div>
            <div>
              <span style="font-size:0.75rem; font-weight:800; color:var(--color-orange-600); text-transform:uppercase;">Tier 2</span>
              <h3 style="margin:0.25rem 0 0.5rem; font-size:1.25rem;">Better: Upgraded Architectural</h3>
              <p style="font-size:0.875rem; color:var(--color-slate-600); margin-bottom:1.25rem;">
                Heavyweight impact-resistant architectural shingles with enhanced leak barrier shields at all valleys and eaves.
              </p>
              <div style="background:#fffbeb; padding:0.75rem; border-radius:6px; font-size:0.8125rem; margin-bottom:1.25rem; color:#92400e;">
                <strong>Best For:</strong> Most Houston homeowners wanting balanced long-term durability and storm peace of mind.
              </div>
              <ul style="list-style:none; font-size:0.875rem; display:flex; flex-direction:column; gap:0.625rem; color:var(--color-slate-800);">
                <li style="display:flex; gap:0.5rem;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--color-teal-600)" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> GAF Timberline HDZ / Owens Corning Duration</li>
                <li style="display:flex; gap:0.5rem;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--color-teal-600)" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Ice &amp; water leak barrier in all valleys &amp; penetrations</li>
                <li style="display:flex; gap:0.5rem;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--color-teal-600)" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Continuous high-airflow ridge vent system</li>
                <li style="display:flex; gap:0.5rem;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--color-teal-600)" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> GAF System Plus 50-Year Non-Prorated Warranty</li>
              </ul>
            </div>
            <div style="margin-top:2rem;">
              <a href="#book" onclick="selectService('Asphalt Shingle Replacement')" class="btn btn-clay-primary" style="width:100%;">Select Tier 2</a>
            </div>
          </div>

          <!-- Best Tier -->
          <div class="card-flat tier-card">
            <div>
              <span style="font-size:0.75rem; font-weight:800; color:var(--color-teal-600); text-transform:uppercase;">Tier 3</span>
              <h3 style="margin:0.25rem 0 0.5rem; font-size:1.25rem;">Best: Standing Seam Metal</h3>
              <p style="font-size:0.875rem; color:var(--color-slate-600); margin-bottom:1.25rem;">
                Commercial-grade 24-gauge standing seam metal panels with concealed clips engineered for hurricane wind uplift ratings.
              </p>
              <div style="background:var(--color-teal-50); padding:0.75rem; border-radius:6px; font-size:0.8125rem; margin-bottom:1.25rem; color:#0f766e;">
                <strong>Best For:</strong> Forever homes and property owners seeking maximum energy reflection and lifetime durability.
              </div>
              <ul style="list-style:none; font-size:0.875rem; display:flex; flex-direction:column; gap:0.625rem; color:var(--color-slate-800);">
                <li style="display:flex; gap:0.5rem;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--color-teal-600)" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> 24-Gauge Galvalume standing seam panels</li>
                <li style="display:flex; gap:0.5rem;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--color-teal-600)" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> High-temperature self-adhering underlayment</li>
                <li style="display:flex; gap:0.5rem;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--color-teal-600)" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Class 4 Hail Impact &amp; UL 580 Wind Uplift</li>
                <li style="display:flex; gap:0.5rem;"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--color-teal-600)" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> 50+ Year Expected Lifespan &amp; Energy Savings</li>
              </ul>
            </div>
            <div style="margin-top:2rem;">
              <a href="#book" onclick="selectService('Standing Seam Metal Roofing')" class="btn btn-flat-secondary" style="width:100%;">Select Tier 3</a>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- Project Gallery Showcase -->
    <section id="gallery" class="section-py" style="background-color: #ffffff;">
      <div class="container">
        <div class="section-header">
          <p class="section-eyebrow">Real Houston Workmanship</p>
          <h2 class="section-title">Recent Projects Across the Region</h2>
          <p class="section-desc">Take a closer look at our installations across Cypress, The Woodlands, Katy, and Greater Houston.</p>
        </div>

        <div class="gallery-filter-tabs">
          <button class="filter-tab active" onclick="filterGallery('all')">All Projects</button>
          <button class="filter-tab" onclick="filterGallery('residential')">Residential Shingles</button>
          <button class="filter-tab" onclick="filterGallery('metal')">Standing Seam Metal</button>
          <button class="filter-tab" onclick="filterGallery('commercial')">Commercial Flat</button>
          <button class="filter-tab" onclick="filterGallery('storm')">Storm Restoration</button>
        </div>

        <div class="grid-3" id="galleryGrid">
          <!-- Project 1 -->
          <div class="project-card" data-cat="residential">
            <div class="project-img" style="background-image: url('https://images.unsplash.com/photo-1590381105924-c72589b9ef3f?auto=format&fit=crop&w=800&q=80');"></div>
            <div class="project-body">
              <div>
                <span style="font-size:0.6875rem; font-weight:800; text-transform:uppercase; color:var(--color-orange-600); background:#fef3c7; padding:2px 8px; border-radius:4px;">Cypress, TX</span>
                <h3 style="font-size:1.125rem; margin:0.5rem 0 0.25rem;">Two-Story Architectural Shingle</h3>
                <p style="font-size:0.875rem; color:var(--color-slate-600);">Full tear-off, 38 squares GAF Timberline HDZ with upgraded continuous ridge ventilation.</p>
              </div>
              <div style="font-size:0.75rem; color:var(--color-slate-400); margin-top:1rem; border-top:1px solid var(--color-border); padding-top:0.75rem;">
                Completed in 2 Days · Full Clean-up
              </div>
            </div>
          </div>

          <!-- Project 2 -->
          <div class="project-card" data-cat="metal">
            <div class="project-img" style="background-image: url('https://images.unsplash.com/photo-1600585154340-be6161a56a0c?auto=format&fit=crop&w=800&q=80');"></div>
            <div class="project-body">
              <div>
                <span style="font-size:0.6875rem; font-weight:800; text-transform:uppercase; color:#0369a1; background:#e0f2fe; padding:2px 8px; border-radius:4px;">The Woodlands, TX</span>
                <h3 style="font-size:1.125rem; margin:0.5rem 0 0.25rem;">Standing Seam Metal Roof</h3>
                <p style="font-size:0.875rem; color:var(--color-slate-600);">Custom fabricated 24-gauge standing seam in Dark Bronze with high-temp underlayment.</p>
              </div>
              <div style="font-size:0.75rem; color:var(--color-slate-400); margin-top:1rem; border-top:1px solid var(--color-border); padding-top:0.75rem;">
                50-Year Class 4 Rating · Maximum Energy Savings
              </div>
            </div>
          </div>

          <!-- Project 3 -->
          <div class="project-card" data-cat="storm">
            <div class="project-img" style="background-image: url('https://images.unsplash.com/photo-1541888946425-d0fbb186156f?auto=format&fit=crop&w=800&q=80');"></div>
            <div class="project-body">
              <div>
                <span style="font-size:0.6875rem; font-weight:800; text-transform:uppercase; color:#92400e; background:#fef3c7; padding:2px 8px; border-radius:4px;">Katy, TX</span>
                <h3 style="font-size:1.125rem; margin:0.5rem 0 0.25rem;">Hail Damage Full Restoration</h3>
                <p style="font-size:0.875rem; color:var(--color-slate-600);">Complete hail impact replacement with detailed photographic documentation report.</p>
              </div>
              <div style="font-size:0.75rem; color:var(--color-slate-400); margin-top:1rem; border-top:1px solid var(--color-border); padding-top:0.75rem;">
                Full Decking Inspection · Upgraded Valley Shields
              </div>
            </div>
          </div>

          <!-- Project 4 -->
          <div class="project-card" data-cat="commercial">
            <div class="project-img" style="background-image: url('https://images.unsplash.com/photo-1486406146926-c627a92ad1ab?auto=format&fit=crop&w=800&q=80');"></div>
            <div class="project-body">
              <div>
                <span style="font-size:0.6875rem; font-weight:800; text-transform:uppercase; color:#15803d; background:#dcfce7; padding:2px 8px; border-radius:4px;">Sugar Land, TX</span>
                <h3 style="font-size:1.125rem; margin:0.5rem 0 0.25rem;">12,000 Sq Ft Commercial TPO</h3>
                <p style="font-size:0.875rem; color:var(--color-slate-600);">Mechanically attached 60-mil white reflective TPO low-slope roof over ISO board.</p>
              </div>
              <div style="font-size:0.75rem; color:var(--color-slate-400); margin-top:1rem; border-top:1px solid var(--color-border); padding-top:0.75rem;">
                Zero Tenant Interruption · 20-Year NDL Warranty
              </div>
            </div>
          </div>

          <!-- Project 5 -->
          <div class="project-card" data-cat="residential">
            <div class="project-img" style="background-image: url('https://images.unsplash.com/photo-1512917774080-9991f1c4c750?auto=format&fit=crop&w=800&q=80');"></div>
            <div class="project-body">
              <div>
                <span style="font-size:0.6875rem; font-weight:800; text-transform:uppercase; color:var(--color-orange-600); background:#fef3c7; padding:2px 8px; border-radius:4px;">Memorial, Houston</span>
                <h3 style="font-size:1.125rem; margin:0.5rem 0 0.25rem;">Executive Shingle &amp; Siding</h3>
                <p style="font-size:0.875rem; color:var(--color-slate-600);">Dual project: designer laminate roof install alongside moisture-barrier fiber cement siding.</p>
              </div>
              <div style="font-size:0.75rem; color:var(--color-slate-400); margin-top:1rem; border-top:1px solid var(--color-border); padding-top:0.75rem;">
                Integrated Weatherproofing · Custom Trim
              </div>
            </div>
          </div>

          <!-- Project 6 -->
          <div class="project-card" data-cat="storm">
            <div class="project-img" style="background-image: url('https://images.unsplash.com/photo-1503387762-592deb58ef4e?auto=format&fit=crop&w=800&q=80');"></div>
            <div class="project-body">
              <div>
                <span style="font-size:0.6875rem; font-weight:800; text-transform:uppercase; color:#92400e; background:#fef3c7; padding:2px 8px; border-radius:4px;">Pearland, TX</span>
                <h3 style="font-size:1.125rem; margin:0.5rem 0 0.25rem;">Emergency Leak &amp; Deck Repair</h3>
                <p style="font-size:0.875rem; color:var(--color-slate-600);">Same-day response for wind-blown shingle damage. Re-decked rotted plywood and sealed valleys.</p>
              </div>
              <div style="font-size:0.75rem; color:var(--color-slate-400); margin-top:1rem; border-top:1px solid var(--color-border); padding-top:0.75rem;">
                Same-Day Tarping · Lifetime Leak Guarantee
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- Real Statistics Counter Strip with Counting Effect -->
    <section class="stats-strip" id="statsSection">
      <div class="container">
        <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 2.5rem; text-align: center;">
          <div>
            <div class="stat-num" data-target="4.9" data-start="0.0" data-decimals="1" data-suffix="★">0.0★</div>
            <p style="font-size:0.875rem; color:#94a3b8; margin-top:0.5rem;">Google Rating (~325 Verified Reviews)</p>
          </div>
          <div>
            <div class="stat-num" data-target="2009" data-start="1980" data-decimals="0">1980</div>
            <p style="font-size:0.875rem; color:#94a3b8; margin-top:0.5rem;">Serving Greater Houston Since</p>
          </div>
          <div>
            <div class="stat-num" data-target="20" data-start="0" data-decimals="0" data-suffix="+ Yrs">0+ Yrs</div>
            <p style="font-size:0.875rem; color:#94a3b8; margin-top:0.5rem;">Leadership Construction Experience</p>
          </div>
          <div>
            <div class="stat-num" data-target="18" data-start="0" data-decimals="0">0</div>
            <p style="font-size:0.875rem; color:#94a3b8; margin-top:0.5rem;">Texas Counties Officially Served</p>
          </div>
        </div>
      </div>
    </section>

    <!-- Verified Customer Reviews Section -->
    <section id="reviews" class="section-py" style="background-color: var(--color-canvas);">
      <div class="container">
        <div class="section-header">
          <p class="section-eyebrow">Local Feedback</p>
          <h2 class="section-title">What Property Owners Experience</h2>
          <p class="section-desc">Real experiences from homeowners and property managers throughout our Texas service area.</p>
        </div>

        <div class="grid-3">
          <div class="card-flat">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.75rem;">
              <div style="color:var(--color-orange-500); display:flex; gap:2px;">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
              </div>
              <span style="font-size:0.6875rem; font-weight:700; color:#047857; background:#dcfce7; padding:2px 8px; border-radius:4px;">Verified Review</span>
            </div>
            <p style="font-style:italic; font-size:0.9375rem; margin-bottom:1rem; color:var(--color-slate-800);">
              "The project manager walked the roof with me, showed high-res photos on his tablet, and gave me three tiered options without pressure. Installation was spotless."
            </p>
            <div style="font-size:0.8125rem; font-weight:700; color:var(--color-slate-800);">Marcus T. <span style="font-weight:400; color:var(--color-slate-400);">· Cypress, TX</span></div>
          </div>

          <div class="card-flat">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.75rem;">
              <div style="color:var(--color-orange-500); display:flex; gap:2px;">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
              </div>
              <span style="font-size:0.6875rem; font-weight:700; color:#047857; background:#dcfce7; padding:2px 8px; border-radius:4px;">Verified Review</span>
            </div>
            <p style="font-style:italic; font-size:0.9375rem; margin-bottom:1rem; color:var(--color-slate-800);">
              "I thought I would have to replace the whole roof after the windstorm. Houston Roofing recommended targeted repairs and saved me thousands. Extremely honest team."
            </p>
            <div style="font-size:0.8125rem; font-weight:700; color:var(--color-slate-800);">Sarah B. <span style="font-weight:400; color:var(--color-slate-400);">· Spring, TX</span></div>
          </div>

          <div class="card-flat">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.75rem;">
              <div style="color:var(--color-orange-500); display:flex; gap:2px;">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
              </div>
              <span style="font-size:0.6875rem; font-weight:700; color:#047857; background:#dcfce7; padding:2px 8px; border-radius:4px;">Verified Review</span>
            </div>
            <p style="font-style:italic; font-size:0.9375rem; margin-bottom:1rem; color:var(--color-slate-800);">
              "Being able to book online and track my booking with a reference ID gave me total confidence. The standing seam metal roof looks incredible."
            </p>
            <div style="font-size:0.8125rem; font-weight:700; color:var(--color-slate-800);">Gregory K. <span style="font-weight:400; color:var(--color-slate-400);">· The Woodlands, TX</span></div>
          </div>
        </div>
      </div>
    </section>

    <!-- 18 Texas Counties Service Area Strip -->
    <section class="section-py" style="background-color: #ffffff; border-top:1px solid var(--color-border); border-bottom:1px solid var(--color-border);">
      <div class="container">
        <div style="text-align: center; max-width: 680px; margin: 0 auto 2rem;">
          <h3 style="font-size: 1.5rem; font-weight: 800; margin-bottom: 0.5rem;">Serving Greater Houston &amp; 18 Surrounding Texas Counties</h3>
          <p style="font-size: 0.9375rem; color:var(--color-slate-600);">
            Rapid inspection response teams dispatched from our Houston headquarters at 11330 West Rd.
          </p>
        </div>

        <div style="display:flex; flex-wrap:wrap; justify-content:center; gap:0.5rem; max-width:960px; margin:0 auto;">
          <span style="background:var(--color-canvas); border:1px solid var(--color-border); padding:0.4rem 0.875rem; border-radius:6px; font-size:0.8125rem; font-weight:700;">Harris County</span>
          <span style="background:var(--color-canvas); border:1px solid var(--color-border); padding:0.4rem 0.875rem; border-radius:6px; font-size:0.8125rem; font-weight:700;">Montgomery County</span>
          <span style="background:var(--color-canvas); border:1px solid var(--color-border); padding:0.4rem 0.875rem; border-radius:6px; font-size:0.8125rem; font-weight:700;">Fort Bend County</span>
          <span style="background:var(--color-canvas); border:1px solid var(--color-border); padding:0.4rem 0.875rem; border-radius:6px; font-size:0.8125rem; font-weight:700;">Brazoria County</span>
          <span style="background:var(--color-canvas); border:1px solid var(--color-border); padding:0.4rem 0.875rem; border-radius:6px; font-size:0.8125rem; font-weight:700;">Galveston County</span>
          <span style="background:var(--color-canvas); border:1px solid var(--color-border); padding:0.4rem 0.875rem; border-radius:6px; font-size:0.8125rem; font-weight:700;">Waller County</span>
          <span style="background:var(--color-canvas); border:1px solid var(--color-border); padding:0.4rem 0.875rem; border-radius:6px; font-size:0.8125rem; font-weight:700;">Liberty County</span>
          <span style="background:var(--color-canvas); border:1px solid var(--color-border); padding:0.4rem 0.875rem; border-radius:6px; font-size:0.8125rem; font-weight:700;">Chambers County</span>
          <span style="background:var(--color-canvas); border:1px solid var(--color-border); padding:0.4rem 0.875rem; border-radius:6px; font-size:0.8125rem; font-weight:700;">Brazos County</span>
          <span style="background:var(--color-canvas); border:1px solid var(--color-border); padding:0.4rem 0.875rem; border-radius:6px; font-size:0.8125rem; font-weight:700;">Walker County</span>
          <span style="background:var(--color-canvas); border:1px solid var(--color-border); padding:0.4rem 0.875rem; border-radius:6px; font-size:0.8125rem; font-weight:700;">Austin County</span>
          <span style="background:var(--color-canvas); border:1px solid var(--color-border); padding:0.4rem 0.875rem; border-radius:6px; font-size:0.8125rem; font-weight:700;">San Jacinto County</span>
          <span style="background:var(--color-canvas); border:1px solid var(--color-border); padding:0.4rem 0.875rem; border-radius:6px; font-size:0.8125rem; font-weight:700;">Grimes County</span>
          <span style="background:var(--color-canvas); border:1px solid var(--color-border); padding:0.4rem 0.875rem; border-radius:6px; font-size:0.8125rem; font-weight:700;">Wharton County</span>
          <span style="background:var(--color-canvas); border:1px solid var(--color-border); padding:0.4rem 0.875rem; border-radius:6px; font-size:0.8125rem; font-weight:700;">Colorado County</span>
          <span style="background:var(--color-canvas); border:1px solid var(--color-border); padding:0.4rem 0.875rem; border-radius:6px; font-size:0.8125rem; font-weight:700;">Washington County</span>
          <span style="background:var(--color-canvas); border:1px solid var(--color-border); padding:0.4rem 0.875rem; border-radius:6px; font-size:0.8125rem; font-weight:700;">Polk County</span>
          <span style="background:var(--color-canvas); border:1px solid var(--color-border); padding:0.4rem 0.875rem; border-radius:6px; font-size:0.8125rem; font-weight:700;">Matagorda County</span>
        </div>
      </div>
    </section>

    <!-- Online Booking System Section -->
    <section id="book" class="section-py booking-section">
      <div class="container">
        <div class="booking-layout">
          <div>
            <p class="section-eyebrow">Zero High-Pressure Sales</p>
            <h2 class="section-title" style="margin-bottom:1rem;">Book Your Free 100% Photo-Documented Inspection</h2>
            <p style="font-size:1rem; color:var(--color-slate-600); margin-bottom:1.5rem; line-height:1.6;">
              Select a date and time that fits your schedule. Our in-house specialist will inspect your complete roofing system, capture diagnostic photos, and explain your exact options.
            </p>

            <div style="display:flex; flex-direction:column; gap:1rem; margin-bottom:2rem;">
              <div style="display:flex; gap:0.75rem;">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--color-orange-500)" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                <div>
                  <strong style="font-size:0.9375rem; color:var(--color-slate-800);">No Obligation, 100% Free</strong>
                  <p style="font-size:0.8125rem; color:var(--color-slate-600);">We provide clear diagnostic findings whether you hire us or not.</p>
                </div>
              </div>
              <div style="display:flex; gap:0.75rem;">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--color-orange-500)" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                <div>
                  <strong style="font-size:0.9375rem; color:var(--color-slate-800);">Immediate Confirmation</strong>
                  <p style="font-size:0.8125rem; color:var(--color-slate-600);">Receive an instant Booking ID to track your inspection progress online.</p>
                </div>
              </div>
              <div style="display:flex; gap:0.75rem;">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--color-orange-500)" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                <div>
                  <strong style="font-size:0.9375rem; color:var(--color-slate-800);">Prefer to Call or WhatsApp?</strong>
                  <p style="font-size:0.8125rem; color:var(--color-slate-600);">Phone: <a href="tel:+18322373737" style="color:var(--color-orange-600); font-weight:700;">(832) 237-3737</a> · Mon–Sun 7am–8pm</p>
                </div>
              </div>
            </div>

            <!-- Self-Service Tracker shortcut -->
            <div id="tracker" style="background:#f1f5f9; padding:1.25rem; border-radius:10px; border:1px solid var(--color-border);">
              <h4 style="font-size:0.875rem; font-weight:700; margin-bottom:0.375rem; color:var(--color-slate-800);">Already Booked? Track Your Inspection</h4>
              <p style="font-size:0.8125rem; color:var(--color-slate-600); margin-bottom:0.75rem;">Enter your Booking Reference ID (e.g., HRC-2026-8812) to check schedule and inspector status.</p>
              <div style="display:flex; gap:0.5rem;">
                <input type="text" id="lookupIdInput" placeholder="HRC-2026-XXXX" style="padding:0.5rem 0.75rem; border:1px solid var(--color-border); border-radius:6px; font-size:0.8125rem; flex:1; text-transform:uppercase;">
                <button type="button" onclick="lookupBooking()" class="btn btn-flat-secondary" style="padding:0.5rem 0.875rem; font-size:0.8125rem;">Check Status</button>
              </div>
              <div id="lookupResultBox" style="margin-top:0.75rem; font-size:0.8125rem; display:none;"></div>
            </div>
          </div>

          <!-- The Booking Form -->
          <div class="booking-form-box">
            <form id="publicBookingForm">
              <div class="form-grid-2">
                <div>
                  <label class="form-label" for="custName">Your Full Name *</label>
                  <input type="text" id="custName" name="name" class="form-control" required placeholder="John Smith">
                </div>
                <div>
                  <label class="form-label" for="custPhone">Phone Number *</label>
                  <input type="tel" id="custPhone" name="phone" class="form-control" required placeholder="(832) 555-0199">
                </div>
              </div>

              <div class="form-grid-2">
                <div>
                  <label class="form-label" for="custEmail">Email Address (Optional)</label>
                  <input type="email" id="custEmail" name="email" class="form-control" placeholder="john@example.com">
                </div>
                <div>
                  <label class="form-label" for="custService">Service Requested *</label>
                  <select id="custService" name="serviceType" class="form-control" required>
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

              <div class="form-group">
                <label class="form-label" for="custAddress">Property Address *</label>
                <input type="text" id="custAddress" name="address" class="form-control" required placeholder="Street address, City, TX (e.g. 11330 West Rd, Houston, TX 77065)">
              </div>

              <div class="form-grid-2">
                <div>
                  <label class="form-label" for="custDate">Preferred Inspection Date *</label>
                  <input type="date" id="custDate" name="preferredDate" class="form-control" required>
                </div>
                <div>
                  <label class="form-label" for="custTime">Preferred Arrival Window</label>
                  <select id="custTime" name="preferredTime" class="form-control">
                    <option value="Morning (8am - 12pm)">Morning (8am - 12pm)</option>
                    <option value="Afternoon (12pm - 4pm)">Afternoon (12pm - 4pm)</option>
                    <option value="Evening (4pm - 7pm)">Evening (4pm - 7pm)</option>
                  </select>
                </div>
              </div>

              <div class="form-group">
                <label class="form-label" for="custDesc">Project Description / Roof Notes (Optional)</label>
                <textarea id="custDesc" name="description" class="form-control" placeholder="Tell us about active leaks, roof age, storm events, or specific concerns..."></textarea>
              </div>

              <div id="bookingErrorBox" style="display:none; padding:0.75rem; border-radius:6px; background:#fee2e2; border:1px solid #fca5a5; color:#991b1b; font-size:0.8125rem; margin-bottom:1rem;"></div>

              <button type="submit" id="bookSubmitBtn" class="btn btn-clay-primary" style="width:100%; font-size:1rem; padding:0.875rem;">
                Confirm &amp; Book Free Inspection
              </button>

              <p style="text-align:center; font-size:0.75rem; color:var(--color-slate-400); margin-top:0.75rem;">
                By booking, you agree to receive appointment reminders via phone or text. No spam, ever.
              </p>
            </form>

            <!-- Success Box -->
            <div id="bookingSuccessBox" class="booking-result">
              <div style="width:48px; height:48px; border-radius:50%; background:#dcfce7; color:#16a34a; display:inline-flex; align-items:center; justify-content:center; margin-bottom:1rem;">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg>
              </div>
              <h3 style="font-size:1.375rem; font-weight:800; color:var(--color-slate-800); margin-bottom:0.5rem;">Inspection Request Received!</h3>
              <p style="font-size:0.9375rem; color:var(--color-slate-600);" id="successMessageText">
                Your appointment has been logged in our schedule.
              </p>
              <div class="ref-pill" id="successRefPill">HRC-2026-XXXX</div>
              <div style="background:#f8fafc; border:1px solid var(--color-border); border-radius:8px; padding:1rem; text-align:left; font-size:0.875rem; margin-bottom:1.25rem;">
                <div><strong>Address:</strong> <span id="successAddress"></span></div>
                <div><strong>Service:</strong> <span id="successService"></span></div>
                <div><strong>Date &amp; Window:</strong> <span id="successDate"></span></div>
              </div>
              <div style="display:flex; justify-content:center; gap:0.75rem; flex-wrap:wrap;">
                <a id="successWhatsAppLink" href="#" target="_blank" class="btn btn-whatsapp">
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"/></svg>
                  Confirm on WhatsApp
                </a>
                <button type="button" onclick="resetBookingForm()" class="btn btn-flat-secondary">Book Another Inspection</button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- Comprehensive Roofing FAQ Accordion Section -->
    <section id="faq" class="section-py" style="background-color: var(--color-canvas);">
      <div class="container">
        <div class="section-header">
          <p class="section-eyebrow">Clear Answers</p>
          <h2 class="section-title">Frequently Asked Questions</h2>
          <p class="section-desc">Straightforward answers about our inspections, warranties, insurance laws, and installation timelines.</p>
        </div>

        <div class="faq-list">
          <div class="faq-item">
            <div class="faq-header" onclick="toggleFaq(this)">
              <span>How quickly can you inspect my roof after a Houston storm?</span>
              <svg class="faq-chevron" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"/></svg>
            </div>
            <div class="faq-body">
              We dispatch field specialists same-day or within 24 hours across Harris, Montgomery, Fort Bend, and all 18 Texas counties we serve. If an active leak requires immediate emergency tarping to prevent ceiling damage, we prioritize urgent stabilization immediately.
            </div>
          </div>

          <div class="faq-item">
            <div class="faq-header" onclick="toggleFaq(this)">
              <span>How does the tiered Good / Better / Best proposal work?</span>
              <svg class="faq-chevron" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"/></svg>
            </div>
            <div class="faq-body">
              Unlike contractors who present a single take-it-or-leave-it price, we present 3 transparent options with high-resolution photo documentation. You see standard architectural shingles (Tier 1: Good), upgraded heavy-duty laminate shingles with premium valley protection (Tier 2: Better), and custom standing seam metal roofing (Tier 3: Best). You decide what fits your budget and property plans.
            </div>
          </div>

          <div class="faq-item">
            <div class="faq-header" onclick="toggleFaq(this)">
              <span>Can you waive or absorb my insurance deductible?</span>
              <svg class="faq-chevron" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"/></svg>
            </div>
            <div class="faq-body">
              No. Under Texas law (Tex. Bus. &amp; Com. Code § 27.02 and TDI regulations enacted under HB 2102), it is illegal for any contractor to pay, rebate, waive, or promise to absorb an insurance deductible. Any contractor offering to "eat your deductible" is violating Texas law. We operate with complete statutory compliance and provide honest, photo-documented reports your insurer respects.
            </div>
          </div>

          <div class="faq-item">
            <div class="faq-header" onclick="toggleFaq(this)">
              <span>How long does a residential roof replacement take?</span>
              <svg class="faq-chevron" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"/></svg>
            </div>
            <div class="faq-body">
              Most standard residential asphalt shingle replacements in Greater Houston are fully completed in 1 to 2 days, weather permitting. Our dedicated in-house project manager remains on-site to verify proper installation, magnetic ground sweep for nails, and clean-up of your property.
            </div>
          </div>

          <div class="faq-item">
            <div class="faq-header" onclick="toggleFaq(this)">
              <span>What warranties are provided on new installations?</span>
              <svg class="faq-chevron" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"/></svg>
            </div>
            <div class="faq-body">
              As a certified GAF Master Elite contractor (a distinction held by fewer than 2% of roofers nationwide), we can provide GAF's highest-tier System Plus and Golden Pledge 50-year non-prorated manufacturer warranties, backed by our comprehensive in-house workmanship guarantee.
            </div>
          </div>
        </div>
      </div>
    </section>
  </main>

  <!-- Sticky Mobile Action Bar -->
  <aside class="mobile-bar">
    <div class="mobile-bar-inner">
      <a href="#book" class="btn btn-clay-primary" style="flex:1;">Book Inspection</a>
      <a href="tel:+18322373737" class="btn btn-ghost-light" style="flex:1;">Call (832) 237-3737</a>
    </div>
  </aside>

  <!-- Site Footer -->
  <footer class="site-footer">
    <div class="container">
      <div class="footer-grid">
        <div>
          <h4 class="footer-title">Houston Roofing &amp; Construction</h4>
          <p style="margin-bottom:0.75rem; line-height:1.6;">
            11330 West Rd, Houston, TX 77065<br>
            Phone: <a href="tel:+18322373737" style="color:#ffffff;">(832) 237-3737</a><br>
            WhatsApp: <a href="https://wa.me/18322373737" style="color:var(--color-orange-500);">(832) 237-3737</a><br>
            Email: <a href="mailto:info@houstonroofing.com" style="color:#ffffff;">info@houstonroofing.com</a><br>
            Hours: Monday – Sunday 7:00 AM – 8:00 PM
          </p>
          <p style="font-size:0.75rem; color:#64748b;">
            Accreditations: BBB A+ · GAF Master Elite · RCAT Licensed Contractor · FORTIFIED standard.
          </p>
        </div>

        <div>
          <h4 class="footer-title">Services</h4>
          <ul class="footer-links">
            <li><a href="#services">Asphalt Shingle Replacement</a></li>
            <li><a href="#services">Standing Seam Metal Roofing</a></li>
            <li><a href="#services">Roof Repair &amp; Hail Assessments</a></li>
            <li><a href="#services">Commercial Flat &amp; TPO Systems</a></li>
            <li><a href="#services">Apartment &amp; HOA Communities</a></li>
            <li><a href="#services">Fiber Cement &amp; Siding</a></li>
          </ul>
        </div>

        <div>
          <h4 class="footer-title">Customer Tools</h4>
          <ul class="footer-links">
            <li><a href="#book">Book a Free Inspection</a></li>
            <li><a href="#tracker">Track Your Booking Status</a></li>
            <li><a href="#pricing">Good / Better / Best Tiers</a></li>
            <li><a href="#gallery">Recent Project Showcase</a></li>
            <li><a href="#faq">Roofing FAQs</a></li>
            <li><a href="/admin">Staff Admin Portal</a></li>
          </ul>
        </div>

        <div>
          <h4 class="footer-title">Coverage Areas</h4>
          <ul class="footer-links">
            <li><span>Harris County (Houston, Cypress, Katy)</span></li>
            <li><span>Montgomery County (The Woodlands, Conroe)</span></li>
            <li><span>Fort Bend County (Sugar Land, Missouri City)</span></li>
            <li><span>Brazoria &amp; Galveston Counties</span></li>
            <li><span>+ 14 Surrounding Texas Counties</span></li>
          </ul>
        </div>
      </div>

      <!-- Statutory Compliance Disclosure Box (Texas Law) -->
      <div class="compliance-box">
        <strong>Texas Insurance Law Disclosure (Tex. Bus. &amp; Com. Code § 27.02):</strong> We are professional roofing contractors, not public insurance adjusters. We do not negotiate, settle, or manage insurance claims on your behalf. Per Texas Department of Insurance (TDI) statutes, contractors cannot waive, rebate, or absorb an insurance deductible. The property owner is legally responsible for payment of any insurance deductible.
      </div>

      <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:1rem; border-top:1px solid rgba(255, 255, 255, 0.1); padding-top:1.5rem; font-size:0.75rem;">
        <div>&copy; 2026 Houston Roofing &amp; Construction. All rights reserved.</div>
        <div>
          <a href="/admin" style="color:#64748b; text-decoration:none;">Admin Login</a>
        </div>
      </div>
    </div>
  </footer>

  <!-- Client-side Logic -->
  <script>
    // Set tomorrow as min date for booking
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    const dateInput = document.getElementById('custDate');
    if (dateInput) {
      dateInput.min = tomorrow.toISOString().split('T')[0];
      dateInput.value = tomorrow.toISOString().split('T')[0];
    }

    // Select service shortcut from cards
    function selectService(serviceName) {
      const select = document.getElementById('custService');
      if (select) {
        select.value = serviceName;
      }
    }

    // Public booking form submission
    const form = document.getElementById('publicBookingForm');
    const submitBtn = document.getElementById('bookSubmitBtn');
    const errorBox = document.getElementById('bookingErrorBox');
    const successBox = document.getElementById('bookingSuccessBox');

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      errorBox.style.display = 'none';
      submitBtn.disabled = true;
      submitBtn.textContent = 'Verifying appointment...';

      const payload = {
        name: form.name.value.trim(),
        phone: form.phone.value.trim(),
        email: form.email.value.trim(),
        serviceType: form.serviceType.value,
        address: form.address.value.trim(),
        preferredDate: form.preferredDate.value,
        preferredTime: form.preferredTime.value,
        description: form.description.value.trim()
      };

      try {
        const res = await fetch('/api/bookings', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const data = await res.json();

        if (res.ok && data.success) {
          const b = data.booking;
          form.style.display = 'none';
          successBox.style.display = 'block';

          document.getElementById('successRefPill').textContent = b.bookingId;
          document.getElementById('successMessageText').textContent = data.message;
          document.getElementById('successAddress').textContent = b.address;
          document.getElementById('successService').textContent = b.serviceType;
          document.getElementById('successDate').textContent = \`\${b.preferredDate} · \${b.preferredTime}\`;

          const cleanPhone = (b.phone || '').replace(/\\D/g, '');
          const waMsg = encodeURIComponent(\`Hello Houston Roofing, I booked inspection \${b.bookingId} for \${b.preferredDate}.\`);
          document.getElementById('successWhatsAppLink').href = \`https://wa.me/18322373737?text=\${waMsg}\`;

          // Scroll to confirmation
          successBox.scrollIntoView({ behavior: 'smooth', block: 'center' });
        } else {
          errorBox.textContent = data.error || 'Failed to submit booking. Please verify all fields.';
          errorBox.style.display = 'block';
        }
      } catch (err) {
        errorBox.textContent = 'Network or connection error. Please call (832) 237-3737 directly.';
        errorBox.style.display = 'block';
      } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Confirm & Book Free Inspection';
      }
    });

    function resetBookingForm() {
      form.reset();
      if (dateInput) dateInput.value = tomorrow.toISOString().split('T')[0];
      form.style.display = 'block';
      successBox.style.display = 'none';
    }

    // Customer Self-Service Booking Lookup
    async function lookupBooking() {
      const input = document.getElementById('lookupIdInput');
      const box = document.getElementById('lookupResultBox');
      const id = input.value.trim();
      if (!id) {
        box.style.display = 'block';
        box.innerHTML = '<span style="color:#ef4444;">Please enter your Booking ID (e.g., HRC-2026-8812).</span>';
        return;
      }

      box.style.display = 'block';
      box.innerHTML = '<span style="color:#64748b;">Checking appointment status...</span>';

      try {
        const res = await fetch('/api/bookings/lookup?id=' + encodeURIComponent(id));
        const data = await res.json();
        if (res.ok && data.success && data.booking) {
          const b = data.booking;
          box.innerHTML = \`
            <div style="background:#ffffff; border:1px solid #cbd5e1; border-radius:6px; padding:0.75rem; margin-top:0.5rem;">
              <div style="font-weight:700; color:#0f172a; margin-bottom:0.25rem;">\${b.bookingId} · <span style="color:#0284c7;">\${b.status}</span></div>
              <div style="color:#475569;">Customer: <strong>\${b.name}</strong></div>
              <div style="color:#475569;">Service: \${b.serviceType}</div>
              <div style="color:#475569;">Scheduled: \${b.preferredDate} (\${b.preferredTime})</div>
              <div style="font-size:0.75rem; color:#64748b; margin-top:0.25rem;">Update: \${b.adminNotes}</div>
            </div>
          \`;
        } else {
          box.innerHTML = \`<span style="color:#ef4444;">\${data.error || 'Booking reference not found.'}</span>\`;
        }
      } catch (err) {
        box.innerHTML = '<span style="color:#ef4444;">Error checking status. Please call (832) 237-3737.</span>';
      }
    }

    // FAQ Accordion toggle
    function toggleFaq(el) {
      const parent = el.parentElement;
      parent.classList.toggle('open');
    }

    // Gallery Filter Tabs
    function filterGallery(category) {
      document.querySelectorAll('.filter-tab').forEach(b => b.classList.remove('active'));
      event.target.classList.add('active');

      const cards = document.querySelectorAll('.project-card');
      cards.forEach(card => {
        if (category === 'all' || card.dataset.cat === category) {
          card.style.display = 'flex';
        } else {
          card.style.display = 'none';
        }
      });
    }

    // Animated Statistics Counter Effect on First Visit / View
    (function initStatCounters() {
      const statElements = document.querySelectorAll('.stat-num[data-target]');
      if (!statElements.length) return;

      const prefersReducedMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      if (prefersReducedMotion) {
        statElements.forEach(el => {
          const target = el.getAttribute('data-target');
          const suffix = el.getAttribute('data-suffix') || '';
          el.textContent = target + suffix;
        });
        return;
      }

      let animated = false;

      function runCounterAnimation() {
        if (animated) return;
        animated = true;

        statElements.forEach(el => {
          const target = parseFloat(el.getAttribute('data-target'));
          const startVal = parseFloat(el.getAttribute('data-start') || '0');
          const decimals = parseInt(el.getAttribute('data-decimals') || '0', 10);
          const suffix = el.getAttribute('data-suffix') || '';
          const duration = 1800; // 1.8 seconds duration for smooth effect
          const startTime = performance.now();

          function tick(now) {
            const elapsed = now - startTime;
            const progress = Math.min(elapsed / duration, 1);
            // Smooth ease-out cubic curve
            const ease = 1 - Math.pow(1 - progress, 3);
            const current = startVal + (target - startVal) * ease;

            el.textContent = (decimals > 0 ? current.toFixed(decimals) : Math.round(current)) + suffix;

            if (progress < 1) {
              requestAnimationFrame(tick);
            } else {
              el.textContent = (decimals > 0 ? target.toFixed(decimals) : target) + suffix;
            }
          }

          requestAnimationFrame(tick);
        });
      }

      // Trigger with IntersectionObserver when scrolled into view
      if ('IntersectionObserver' in window) {
        const statsSection = document.getElementById('statsSection') || document.querySelector('.stats-strip');
        if (statsSection) {
          const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
              if (entry.isIntersecting) {
                runCounterAnimation();
                observer.disconnect();
              }
            });
          }, { threshold: 0.2 });
          observer.observe(statsSection);
        } else {
          runCounterAnimation();
        }
      } else {
        runCounterAnimation();
      }
    })();
  </script>
</body>
</html>`;
}
