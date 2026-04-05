'use strict';
// ═══════════════════════════════════════════════════════════════
//  KOR DA — Production Backend v8
//  Pakistan's Verified Home Rental Platform
//  EasyPaisa: 03495620844  |  WhatsApp: +97471259576
// ═══════════════════════════════════════════════════════════════
//  Stack: Node.js + Express + Nodemailer (Resend or Gmail)
//  Security: Rate limiting · JWT · Input validation · Helmet
//  Email: Every form submission emails you immediately
// ═══════════════════════════════════════════════════════════════

require('dotenv').config();

const express     = require('express');
const cors        = require('cors');
const helmet      = require('helmet');
const rateLimit   = require('express-rate-limit');
const nodemailer  = require('nodemailer');
const path        = require('path');
const fs          = require('fs');
const crypto      = require('crypto');

// Optional — install if you want full auth
let jwt;
try { jwt = require('jsonwebtoken'); } catch (e) { jwt = null; }

const app  = express();
const PORT = process.env.PORT || 3001;

// ── Config ────────────────────────────────────────────────
const ADMIN_PASS     = process.env.ADMIN_PASS     || 'korda_admin_change_me_2025';
const JWT_SECRET     = process.env.JWT_SECRET     || crypto.randomBytes(64).toString('hex');
const NOTIFY_EMAIL   = process.env.NOTIFY_EMAIL   || process.env.GMAIL_USER;
const COMMISSION     = parseFloat(process.env.COMMISSION_RATE) || 0.08;
const FRONTEND_URL   = process.env.FRONTEND_URL   || 'https://korda.pk';

if (!process.env.ADMIN_PASS) console.warn('⚠  Set ADMIN_PASS in .env');
if (!process.env.GMAIL_USER) console.warn('⚠  Set GMAIL_USER + GMAIL_APP_PASS in .env for email');

// ── Rate limiters ─────────────────────────────────────────
function mkLimit(windowMs, max, msg) {
  return rateLimit({
    windowMs, max,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
      console.warn('[RATE-LIMIT]', req.ip, req.path);
      res.status(429).json({ ok: false, error: msg });
    },
  });
}
const generalLimit = mkLimit(60 * 1000,       100, 'Too many requests. Please slow down.');
const authLimit    = mkLimit(60 * 60 * 1000,   10, 'Too many auth attempts. Try again in 1 hour.');
const formLimit    = mkLimit(60 * 60 * 1000,   20, 'Too many submissions. Please try again later.');
const adminLimit   = mkLimit(60 * 60 * 1000,   60, 'Too many admin requests.');

// ── Auth ──────────────────────────────────────────────────
function genToken(payload, exp) {
  if (!jwt) return 'demo_' + crypto.randomBytes(16).toString('hex');
  return jwt.sign(payload, JWT_SECRET, { expiresIn: exp || '24h', issuer: 'korda.pk' });
}
function verifyToken(tok) {
  if (!jwt) return { role: 'user', demo: true };
  try { return jwt.verify(tok, JWT_SECRET, { issuer: 'korda.pk' }); }
  catch (e) { return null; }
}
function requireAuth(req, res, next) {
  const tok = (req.headers.authorization || '').replace('Bearer ', '');
  if (!tok) return res.status(401).json({ ok: false, error: 'Authentication required.' });
  const p = verifyToken(tok);
  if (!p) return res.status(401).json({ ok: false, error: 'Token invalid or expired.' });
  req.user = p;
  next();
}
function requireAdmin(req, res, next) {
  const tok = req.headers['x-admin-token'] || req.query.token;
  if (!tok || tok !== ADMIN_PASS) {
    console.warn('[SECURITY] Admin auth fail from', req.ip);
    return res.status(403).json({ ok: false, error: 'Access denied.' });
  }
  next();
}
function optAuth(req, res, next) {
  const tok = (req.headers.authorization || '').replace('Bearer ', '');
  if (tok) req.user = verifyToken(tok);
  next();
}

// ── Sanitization ──────────────────────────────────────────
function san(s, max) {
  max = max || 2000;
  return String(s || '').trim()
    .replace(/<[^>]*>/g, '')
    .replace(/javascript:/gi, '')
    .replace(/on\w+\s*=/gi, '')
    .slice(0, max);
}
function validCNIC(c) {
  const s = String(c || '').replace(/\s/g, '');
  return /^\d{5}-\d{7}-\d$/.test(s) ? s : null;
}
function validPhone(p) {
  const s = String(p || '').replace(/[\s\-\(\)]/g, '');
  return /^(\+92|0092|92)?0?3\d{9}$/.test(s) || /^\+?\d{10,13}$/.test(s);
}
function validEmail(e) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(e || ''));
}
function validPrice(n) {
  const v = parseInt(n);
  return !isNaN(v) && v >= 100 && v <= 10000000 ? v : null;
}

// ── File uploads ──────────────────────────────────────────
let multer;
try {
  multer = require('multer');
} catch (e) {
  console.warn('multer not installed — photo uploads disabled. Run: npm install multer');
}

const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

let upload = { array: () => (req, res, next) => next() };
if (multer) {
  const storage = multer.diskStorage({
    destination: (_, __, cb) => cb(null, uploadDir),
    filename: (_, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase().replace(/[^.a-z0-9]/g, '');
      cb(null, Date.now() + '-' + crypto.randomBytes(10).toString('hex') + ext);
    },
  });
  upload = multer({
    storage,
    limits: { fileSize: 10 * 1024 * 1024, files: 20 },
    fileFilter: (_, file, cb) => {
      ['image/jpeg', 'image/png', 'image/webp'].includes(file.mimetype)
        ? cb(null, true) : cb(new Error('Only JPEG/PNG/WebP allowed'));
    },
  });
}

// ── Middleware ────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: false,
  hsts: { maxAge: 31536000, includeSubDomains: true },
}));
app.use((req, res, next) => {
  res.removeHeader('X-Powered-By');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cors({
  origin: (origin, cb) => {
    const allowed = FRONTEND_URL.split(',').map(s => s.trim());
    if (!origin || allowed.includes('*') || allowed.some(a => origin.startsWith(a))) cb(null, true);
    else cb(new Error('CORS: not allowed'));
  },
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Admin-Token', 'X-Requested-With'],
  credentials: true,
}));

app.use('/uploads', express.static(uploadDir));
app.use(express.static(path.join(__dirname, '..')));
app.use('/api/', generalLimit);

// ── Email (Nodemailer via Gmail) ──────────────────────────
const mailer = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_APP_PASS,
  },
});

mailer.verify(err =>
  err
    ? console.error('❌ Email config error:', err.message, '— Set GMAIL_USER + GMAIL_APP_PASS in .env')
    : console.log('✅ Email ready:', process.env.GMAIL_USER)
);

async function sendEmail(to, subject, html, replyTo) {
  if (!process.env.GMAIL_USER) {
    console.log('[EMAIL SKIPPED — no config]', subject);
    return;
  }
  try {
    await mailer.sendMail({
      from: '"Kor Da" <' + process.env.GMAIL_USER + '>',
      to,
      subject,
      html,
      replyTo,
    });
  } catch (err) {
    console.error('[EMAIL ERROR]', err.message);
  }
}

// ── In-memory DB (replace with Supabase/MongoDB for scale) ─
const DB = {
  users:        [],
  applications: [],
  listings:     [],
  bookings:     [],
  waitlist:     [],
  reviews:      [],
  contacts:     [],
};

// ══════════════════════════════════════════════════════════
//  PUBLIC ROUTES
// ══════════════════════════════════════════════════════════

// Health check
app.get('/api/health', (req, res) => res.json({
  ok: true,
  service: 'Kor Da API v8',
  time: new Date().toISOString(),
  stats: {
    listings:  DB.listings.filter(l => l.status === 'approved').length,
    waitlist:  DB.waitlist.length,
    bookings:  DB.bookings.length,
    contacts:  DB.contacts.length,
  },
}));

// Get approved listings
app.get('/api/listings', optAuth, (req, res) => {
  const { city, category, minPrice, maxPrice, page, limit } = req.query;
  let list = DB.listings.filter(l => l.status === 'approved');
  if (city)     list = list.filter(l => (l.city || '').toLowerCase().includes(city.toLowerCase()));
  if (category && category !== 'all') list = list.filter(l => l.category === category);
  if (minPrice) list = list.filter(l => l.price >= Number(minPrice));
  if (maxPrice) list = list.filter(l => l.price <= Number(maxPrice));
  const p   = Math.max(1, parseInt(page) || 1);
  const lim = Math.min(50, Math.max(1, parseInt(limit) || 12));
  const paged = list.slice((p - 1) * lim, p * lim);
  res.json({ ok: true, listings: paged, total: list.length, page: p, pages: Math.ceil(list.length / lim) });
});

// Get single listing
app.get('/api/listings/:id', optAuth, (req, res) => {
  const l = DB.listings.find(x => x.id === req.params.id && x.status === 'approved');
  if (!l) return res.status(404).json({ ok: false, error: 'Listing not found.' });
  const safe = { ...l, host: { name: l.host?.name, cnicVerified: true } };
  res.json({ ok: true, listing: safe });
});

// ── WAITLIST ──────────────────────────────────────────────
app.post('/api/waitlist', formLimit, async (req, res) => {
  const raw = san(req.body.email || '', 200);
  if (!raw || !validEmail(raw))
    return res.status(400).json({ ok: false, error: 'Valid email required.' });

  const email = raw.toLowerCase().trim();
  if (DB.waitlist.find(w => w.email === email))
    return res.json({ ok: true, message: "You're already on the list!" });

  DB.waitlist.push({ email, createdAt: new Date() });

  // Notify you
  await sendEmail(
    NOTIFY_EMAIL,
    '📬 Kor Da Waitlist: ' + email,
    '<p>New signup: <strong>' + email + '</strong><br>Total: ' + DB.waitlist.length + '</p>'
  );

  // Confirm to user
  await sendEmail(
    email,
    "You're on the Kor Da waitlist 🏡",
    '<div style="font-family:Arial,sans-serif;max-width:520px">'
    + '<div style="background:#1C4D40;padding:24px;border-radius:8px 8px 0 0;text-align:center">'
    + '<h1 style="color:white;margin:0;font-family:Georgia,serif">Kor Da</h1>'
    + '<p style="color:rgba(255,255,255,.7);margin:6px 0 0;font-size:.85rem">\u0622\u067e \u06a9\u0627 \u06af\u06be\u0631 \u2014 \u06c1\u0631 \u062c\u06af\u06c1</p></div>'
    + '<div style="padding:28px;border:1px solid #eee;border-top:none;border-radius:0 0 8px 8px;background:#fdfaf5">'
    + '<h2 style="color:#1C4D40;font-family:Georgia,serif">You\'re on the list! 🎉</h2>'
    + '<p style="color:#6A6050;line-height:1.7">Thank you for joining the Kor Da waitlist. When we launch in Islamabad, you\'ll be among the first to know — and you\'ll get <strong style="color:#1C4D40">10% off your first booking</strong>.</p>'
    + '<p style="margin-top:18px"><a href="https://www.instagram.com/korda.pk" style="color:#1C4D40">Follow @korda.pk on Instagram</a> for updates.</p>'
    + '<p style="color:#C5BBAE;font-size:.8rem;margin-top:20px">Kor Da (Pvt.) Ltd. · Havelian, KPK, Pakistan</p></div></div>'
  );

  res.json({ ok: true, message: "You're on the list! Check your inbox." });
});

// ── CONTACT ───────────────────────────────────────────────
app.post('/api/contact', formLimit, async (req, res) => {
  const name    = san(req.body.name    || '', 100);
  const email   = san(req.body.email   || '', 200);
  const subject = san(req.body.subject || '', 200);
  const message = san(req.body.message || '', 3000);

  if (!name || !email || !message || message.length < 5)
    return res.status(400).json({ ok: false, error: 'Name, email, and message required.' });
  if (!validEmail(email))
    return res.status(400).json({ ok: false, error: 'Invalid email.' });

  DB.contacts.push({ name, email, subject, message, createdAt: new Date() });

  await sendEmail(
    NOTIFY_EMAIL,
    '📩 Contact from ' + name + ': ' + (subject || 'General'),
    '<p><strong>' + name + '</strong> | <a href="mailto:' + email + '">' + email + '</a></p>'
    + (subject ? '<p><strong>' + subject + '</strong></p>' : '')
    + '<hr><p>' + message.replace(/\n/g, '<br>') + '</p>',
    email
  );

  res.json({ ok: true, message: "Message sent! We'll reply within 2 hours." });
});

// ── HOST APPLICATION ──────────────────────────────────────
app.post('/api/host', formLimit, upload.array('photos', 20), async (req, res) => {
  const { name, phone, cnic, city, type, beds, price, address, description, category, email, maxGuests } = req.body;

  if (!name || !phone || !cnic || !city || !address)
    return res.status(400).json({ ok: false, error: 'Please fill all required fields.' });
  if (!validPhone(san(phone, 20)))
    return res.status(400).json({ ok: false, error: 'Invalid Pakistani mobile number.' });
  const cnicClean = validCNIC(cnic);
  if (!cnicClean)
    return res.status(400).json({ ok: false, error: 'CNIC format: 00000-0000000-0' });
  const priceVal = validPrice(price);
  if (!priceVal)
    return res.status(400).json({ ok: false, error: 'Price must be PKR 100 to 10,000,000.' });

  const appId = 'APP-' + Date.now() + '-' + crypto.randomBytes(4).toString('hex').toUpperCase();
  const appData = {
    id: appId,
    status: 'pending',
    createdAt: new Date(),
    host: {
      name: san(name, 100),
      phone: san(phone, 20),
      cnic: cnicClean,
      email: san(email || '', 200),
    },
    property: {
      city:        san(city, 100),
      type:        san(type || '', 100),
      beds:        san(beds || '', 50),
      price:       priceVal,
      maxGuests:   parseInt(maxGuests) || 4,
      address:     san(address, 500),
      description: san(description || '', 2000),
      category:    san(category || '', 100),
      photos:      (req.files || []).map(f => f.filename),
      amenities:   Array.isArray(req.body.amenities)
                     ? req.body.amenities.map(a => san(a, 50))
                     : (req.body.amenities ? [san(req.body.amenities, 50)] : []),
    },
  };
  DB.applications.push(appData);

  // Email you with full application details
  const waLink = 'https://wa.me/' + san(phone, 20).replace(/\D/g, '');
  await sendEmail(
    NOTIFY_EMAIL,
    '🏡 HOST APPLICATION [' + appId + '] — ' + san(name) + ' · ' + san(city),
    '<div style="font-family:Arial,sans-serif;max-width:600px">'
    + '<div style="background:#1C4D40;padding:20px;border-radius:8px 8px 0 0">'
    + '<h2 style="color:white;margin:0">New Host Application</h2>'
    + '<p style="color:rgba(255,255,255,.7);margin:4px 0 0;font-size:.85rem">ID: ' + appId + '</p></div>'
    + '<div style="padding:24px;border:1px solid #eee;border-top:none;border-radius:0 0 8px 8px;background:#fdfaf5">'
    + '<table style="border-collapse:collapse;width:100%;font-size:.9rem">'
    + '<tr><td style="padding:6px 0;color:#666;width:120px">Name</td><td><strong>' + san(name) + '</strong></td></tr>'
    + '<tr><td style="padding:6px 0;color:#666">WhatsApp</td><td><a href="' + waLink + '">' + san(phone) + '</a></td></tr>'
    + '<tr><td style="padding:6px 0;color:#666">CNIC</td><td><code>' + cnicClean + '</code></td></tr>'
    + '<tr><td style="padding:6px 0;color:#666">City/Area</td><td>' + san(city) + '</td></tr>'
    + '<tr><td style="padding:6px 0;color:#666">Property</td><td>' + san(type || '—') + ' · ' + san(beds || '—') + '</td></tr>'
    + '<tr><td style="padding:6px 0;color:#666">Price/Night</td><td>PKR ' + priceVal.toLocaleString() + '</td></tr>'
    + '<tr><td style="padding:6px 0;color:#666">Address</td><td>' + san(address) + '</td></tr>'
    + '<tr><td style="padding:6px 0;color:#666">Category</td><td>' + san(category || 'General') + '</td></tr>'
    + '<tr><td style="padding:6px 0;color:#666">Photos</td><td>' + (req.files || []).length + ' uploaded</td></tr>'
    + '</table>'
    + (san(description || '') ? '<p style="background:#f5f5f3;padding:12px;border-radius:6px;margin-top:12px">' + san(description) + '</p>' : '')
    + '<div style="background:#FDF4E0;border:1px solid rgba(217,127,22,.2);border-radius:6px;padding:14px;margin-top:16px">'
    + '<strong style="color:#946800">Next Steps:</strong>'
    + '<ol style="color:#555;font-size:.85rem;margin:8px 0 0;padding-left:18px">'
    + '<li>WhatsApp ' + san(name) + ': <a href="' + waLink + '">' + san(phone) + '</a></li>'
    + '<li>Verify CNIC via NADRA Verisys: ' + cnicClean + '</li>'
    + '<li>Review property photos and description</li>'
    + '<li>Login to Admin Panel → Approve or Reject</li>'
    + '</ol></div>'
    + '<p style="text-align:center;margin-top:16px">'
    + '<a href="' + FRONTEND_URL + '/_admin_korda_secret/" style="background:#1C4D40;color:white;padding:10px 20px;border-radius:6px;text-decoration:none;font-weight:600">Open Admin Panel →</a>'
    + '</p></div></div>'
  );

  res.json({
    ok: true,
    message: "Application received! Our team will WhatsApp you within 24 hours to verify your CNIC.",
    id: appId,
  });
});

// ── AUTH ──────────────────────────────────────────────────
app.post('/api/auth/request-otp', authLimit, (req, res) => {
  const phone = san(req.body.phone || '', 20);
  if (!validPhone(phone))
    return res.status(400).json({ ok: false, error: 'Invalid Pakistani mobile number.' });

  const otp = process.env.NODE_ENV === 'production'
    ? Math.floor(100000 + Math.random() * 900000).toString()
    : '123456';

  DB.users = DB.users.filter(u => u.phone !== phone);
  DB.users.push({ phone, otp, otpExpiry: Date.now() + 600000 });

  if (process.env.NODE_ENV !== 'production') console.log('[OTP-DEV]', phone, ':', otp);

  res.json({ ok: true, message: 'OTP sent.', ...(process.env.NODE_ENV !== 'production' && { demo_otp: otp }) });
});

app.post('/api/auth/verify-otp', authLimit, (req, res) => {
  const phone = san(req.body.phone || '', 20);
  const otp   = san(req.body.otp   || '', 10);
  const user  = DB.users.find(u => u.phone === phone);

  if (!user || user.otp !== otp || Date.now() > user.otpExpiry)
    return res.status(401).json({ ok: false, error: 'Invalid or expired OTP.' });

  const token = genToken({ phone, id: user.id || phone, role: 'user' });
  res.json({ ok: true, token, isNewUser: !user.name });
});

// ── BOOKINGS ──────────────────────────────────────────────
app.post('/api/bookings', requireAuth, formLimit, (req, res) => {
  const { listingId, checkIn, checkOut, guests } = req.body;
  if (!listingId || !checkIn || !checkOut)
    return res.status(400).json({ ok: false, error: 'listingId, checkIn, checkOut required.' });
  if (new Date(checkIn) >= new Date(checkOut))
    return res.status(400).json({ ok: false, error: 'Check-out must be after check-in.' });

  const listing = DB.listings.find(l => l.id === san(listingId, 50) && l.status === 'approved');
  if (!listing) return res.status(404).json({ ok: false, error: 'Listing not available.' });

  const nights = Math.ceil((new Date(checkOut) - new Date(checkIn)) / 86400000);
  const total  = nights * listing.price;
  const bk = {
    id:          'BKG-' + Date.now() + '-' + crypto.randomBytes(4).toString('hex').toUpperCase(),
    listingId:   listing.id,
    guestId:     req.user.id,
    guestPhone:  req.user.phone,
    checkIn:     san(checkIn, 12),
    checkOut:    san(checkOut, 12),
    guests:      Math.min(20, Math.max(1, parseInt(guests) || 1)),
    nights,
    totalAmount: total,
    commission:  Math.round(total * COMMISSION),
    hostPayout:  total - Math.round(total * COMMISSION),
    status:      'pending_payment',
    createdAt:   new Date(),
  };
  DB.bookings.push(bk);
  res.status(201).json({ ok: true, booking: bk });
});

app.get('/api/bookings/my', requireAuth, (req, res) => {
  const bks = DB.bookings.filter(b => b.guestId === req.user.id || b.guestPhone === req.user.phone);
  res.json({ ok: true, bookings: bks });
});

app.post('/api/bookings/:id/checkin', requireAuth, (req, res) => {
  const bk = DB.bookings.find(b => b.id === req.params.id);
  if (!bk) return res.status(404).json({ ok: false, error: 'Booking not found.' });
  if (bk.guestId !== req.user.id && bk.guestPhone !== req.user.phone)
    return res.status(403).json({ ok: false, error: 'Not authorized.' });
  bk.status      = 'checked_in';
  bk.checkedInAt = new Date();
  bk.payoutAt    = new Date(Date.now() + 24 * 3600000);
  res.json({ ok: true, message: 'Check-in confirmed! Escrow releases to host in 24 hours.' });
});

app.post('/api/bookings/:id/dispute', requireAuth, formLimit, async (req, res) => {
  const reason = san(req.body.reason || '', 2000);
  if (!reason) return res.status(400).json({ ok: false, error: 'Dispute reason required.' });
  const bk = DB.bookings.find(b => b.id === req.params.id);
  if (!bk) return res.status(404).json({ ok: false, error: 'Booking not found.' });
  if (bk.guestId !== req.user.id && bk.guestPhone !== req.user.phone)
    return res.status(403).json({ ok: false, error: 'Not authorized.' });
  bk.status        = 'disputed';
  bk.disputeReason = reason;
  bk.disputeAt     = new Date();
  await sendEmail(NOTIFY_EMAIL, '⚖️ DISPUTE [' + bk.id + ']',
    '<p>Dispute filed for booking ' + bk.id + '</p><p>Reason: ' + reason + '</p>');
  res.json({ ok: true, message: 'Dispute filed. Our team responds within 24 hours.' });
});

// ── ADMIN ─────────────────────────────────────────────────
app.post('/api/admin/login', adminLimit, (req, res) => {
  const { password } = req.body;
  if (!password || password !== ADMIN_PASS) {
    console.warn('[SECURITY] Admin login fail:', req.ip);
    return res.status(401).json({ ok: false, error: 'Invalid credentials.' });
  }
  res.json({ ok: true, token: ADMIN_PASS, message: 'Authenticated.' });
});

app.get('/api/admin/stats', adminLimit, requireAdmin, (req, res) => {
  res.json({
    ok: true,
    stats: {
      applications: {
        pending: DB.applications.filter(a => a.status === 'pending').length,
        total:   DB.applications.length,
      },
      listings: {
        approved: DB.listings.filter(l => l.status === 'approved').length,
        total:    DB.listings.length,
      },
      bookings: {
        active: DB.bookings.filter(b => b.status === 'checked_in').length,
        total:  DB.bookings.length,
      },
      waitlist: { count: DB.waitlist.length },
      revenue: {
        total: DB.bookings.filter(b => b.status === 'checked_in')
                          .reduce((s, b) => s + (b.commission || 0), 0),
      },
    },
  });
});

app.get('/api/admin/applications', adminLimit, requireAdmin, (req, res) =>
  res.json({ ok: true, applications: DB.applications }));

app.post('/api/admin/applications/:id/approve', adminLimit, requireAdmin, (req, res) => {
  const appl = DB.applications.find(a => a.id === req.params.id);
  if (!appl) return res.status(404).json({ ok: false, error: 'Not found.' });
  appl.status     = 'approved';
  appl.approvedAt = new Date();
  const listing = {
    id:        'LST-' + Date.now() + '-' + crypto.randomBytes(4).toString('hex').toUpperCase(),
    ...appl.property,
    host:      appl.host,
    status:    'approved',
    createdAt: new Date(),
    featured:  false,
  };
  DB.listings.push(listing);
  console.log('[ADMIN] Listing approved:', listing.id);
  res.json({ ok: true, listing, message: 'Listing approved and live.' });
});

app.post('/api/admin/applications/:id/reject', adminLimit, requireAdmin, (req, res) => {
  const reason = san(req.body.reason || 'Does not meet requirements', 500);
  const appl = DB.applications.find(a => a.id === req.params.id);
  if (!appl) return res.status(404).json({ ok: false, error: 'Not found.' });
  appl.status          = 'rejected';
  appl.rejectedAt      = new Date();
  appl.rejectionReason = reason;
  res.json({ ok: true, message: 'Application rejected.' });
});

app.get('/api/admin/listings',  adminLimit, requireAdmin, (req, res) => res.json({ ok: true, listings:  DB.listings  }));
app.get('/api/admin/bookings',  adminLimit, requireAdmin, (req, res) => res.json({ ok: true, bookings:  DB.bookings  }));
app.get('/api/admin/waitlist',  adminLimit, requireAdmin, (req, res) => res.json({ ok: true, waitlist:  DB.waitlist, count: DB.waitlist.length }));
app.get('/api/admin/contacts',  adminLimit, requireAdmin, (req, res) => res.json({ ok: true, contacts:  DB.contacts  }));
app.get('/api/admin/reviews',   adminLimit, requireAdmin, (req, res) => res.json({ ok: true, reviews:   DB.reviews   }));

app.patch('/api/admin/listings/:id/feature', adminLimit, requireAdmin, (req, res) => {
  const l = DB.listings.find(x => x.id === req.params.id);
  if (!l) return res.status(404).json({ ok: false, error: 'Not found.' });
  l.featured = !l.featured;
  res.json({ ok: true, featured: l.featured });
});

// ── PAYMENT WEBHOOK (Safepay / DodoPay / Razorpay) ────────
app.post('/api/payments/webhook', (req, res) => {
  const event = req.body;
  // Verify webhook signature in production
  if (event?.type === 'checkout.completed') {
    const bk = DB.bookings.find(b => b.id === event.data?.object?.orderId);
    if (bk) {
      bk.paymentStatus = 'paid';
      bk.paidAt        = new Date();
      bk.status        = 'confirmed';
    }
  }
  res.json({ received: true });
});

// ── Error handlers ────────────────────────────────────────
app.use((req, res) =>
  res.status(404).json({ ok: false, error: req.method + ' ' + req.path + ' not found.' }));

app.use((err, req, res, next) => {
  console.error('[ERROR]', err.message);
  res.status(err.status || 500).json({
    ok: false,
    error: process.env.NODE_ENV === 'production' ? 'Internal server error.' : err.message,
  });
});

// ── Start ─────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log('\n🏡  Kor Da Backend v8');
  console.log('    Port:    ' + PORT);
  console.log('    Admin:   ' + FRONTEND_URL + '/_admin_korda_secret/');
  console.log('    Health:  http://localhost:' + PORT + '/api/health');
  console.log('    Email:   ' + (process.env.GMAIL_USER || 'NOT CONFIGURED'));
  console.log('    EasyPaisa: 03495620844');
  console.log('    WhatsApp:  +97471259576\n');
});

module.exports = app;
