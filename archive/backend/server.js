'use strict';
// ═══════════════════════════════════════════════════════════════
//  KOR DA — Production Backend v8 (Supabase Edition)
//  Pakistan's Verified Home Rental Platform
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
const { supabase } = require('./supabaseClient');

let jwt;
try { jwt = require('jsonwebtoken'); } catch (e) { jwt = null; }

const app  = express();
const PORT = process.env.PORT || 3001;

// ── Config ────────────────────────────────────────────────
if (!process.env.ADMIN_PASS) {
  console.error('❌ ADMIN_PASS is required in .env');
  process.exit(1);
}
if (!process.env.JWT_SECRET) {
  console.error('❌ JWT_SECRET must be set in .env');
  process.exit(1);
}

const ADMIN_EMAIL    = process.env.ADMIN_EMAIL || 'admin@korda.pk';
const ADMIN_PASS     = process.env.ADMIN_PASS;
const JWT_SECRET     = process.env.JWT_SECRET;
const NOTIFY_EMAIL   = process.env.NOTIFY_EMAIL   || process.env.GMAIL_USER;
const COMMISSION     = parseFloat(process.env.COMMISSION_RATE) || 0.08;
const FRONTEND_URL   = process.env.FRONTEND_URL   || 'https://korda.pk';
const ADMIN_IPS      = process.env.ADMIN_IPS ? process.env.ADMIN_IPS.split(',').map(s => s.trim()) : [];

if (!process.env.GMAIL_USER) console.warn('⚠  Set GMAIL_USER + GMAIL_APP_PASS in .env for email');
if (!ADMIN_IPS.length) console.warn('⚠  No ADMIN_IPS set — admin panel accessible from any IP');

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

// ── Auth Middleware ───────────────────────────────────────
function genToken(payload, exp) {
  if (!jwt) return 'demo_' + crypto.randomBytes(16).toString('hex');
  return jwt.sign(payload, JWT_SECRET, { expiresIn: exp || '24h', issuer: 'korda.pk' });
}
function verifyToken(tok) {
  if (!jwt) return { role: 'user', demo: true };
  try { return jwt.verify(tok, JWT_SECRET, { issuer: 'korda.pk' }); }
  catch (e) { return null; }
}

async function requireAuth(req, res, next) {
  const tok = (req.headers.authorization || '').replace('Bearer ', '');
  if (!tok) return res.status(401).json({ ok: false, error: 'Authentication required.' });
  
  // Try Supabase Auth first
  const { data: { user }, error } = await supabase.auth.getUser(tok);
  if (!error && user) {
    req.user = { id: user.id, email: user.email, role: 'user' };
    return next();
  }

  // Fallback to legacy JWT (e.g. for admin or older tokens)
  const p = verifyToken(tok);
  if (!p) return res.status(401).json({ ok: false, error: 'Token invalid or expired.' });
  req.user = p;
  next();
}

// Modified requireAdmin to support Supabase Auth tokens
const requireAdmin = async (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Authentication required' });

    try {
        // First try verifying as a legacy JWT (for current admin panel compat)
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            if (decoded.role === 'admin') {
                req.admin = decoded;
                return next();
            }
        } catch (e) {
            // Not a legacy JWT, continue to Supabase check
        }

        // Verify with Supabase
        const { data: { user }, error } = await supabase.auth.getUser(token);
        
        if (error || !user) throw new Error('Invalid token');
        
        // Check if user is the admin
        if (user.email === ADMIN_EMAIL) {
            req.admin = user;
            next();
        } else {
            res.status(403).json({ error: 'Access denied: Not an administrator' });
        }
    } catch (err) {
        res.status(403).json({ error: 'Admin access required' });
    }
};

async function optAuth(req, res, next) {
  const tok = (req.headers.authorization || '').replace('Bearer ', '');
  if (tok) {
    const { data: { user }, error } = await supabase.auth.getUser(tok);
    if (!error && user) {
      req.user = { id: user.id, email: user.email, role: 'user' };
    } else {
      req.user = verifyToken(tok);
    }
  }
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

// ── File uploads (Memory to Supabase) ─────────────────────
let multer;
try {
  multer = require('multer');
} catch (e) {
  console.warn('multer not installed. Run: npm install multer');
}

let upload = { array: () => (req, res, next) => next() };
if (multer) {
  upload = multer({
    storage: multer.memoryStorage(),
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
    if (!origin || allowed.includes('*') || allowed.includes(origin)) cb(null, true);
    else cb(new Error('CORS: not allowed'));
  },
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Admin-Token', 'X-Requested-With'],
  credentials: true,
}));

app.use(express.static(path.join(__dirname, '..')));
app.use('/api/', generalLimit);

// ── Admin IP restriction ──────────────────────────────────
function restrictAdminIP(req, res, next) {
  if (ADMIN_IPS.length && !ADMIN_IPS.includes(req.ip)) {
    console.warn('[SECURITY] Admin access blocked for IP:', req.ip);
    return res.status(403).json({ ok: false, error: 'IP not allowed.' });
  }
  next();
}
app.use('/api/admin', restrictAdminIP);

// ── Email (Nodemailer via Gmail) ──────────────────────────
const mailer = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_APP_PASS },
});

async function sendEmail(to, subject, html, replyTo) {
  if (!process.env.GMAIL_USER) return;
  try {
    await mailer.sendMail({ from: '"Kor Da" <' + process.env.GMAIL_USER + '>', to, subject, html, replyTo });
  } catch (err) { console.error('[EMAIL ERROR]', err.message); }
}

// ══════════════════════════════════════════════════════════
//  PUBLIC ROUTES
// ══════════════════════════════════════════════════════════

app.get('/api/health', async (req, res) => {
  const { count: listings } = await supabase.from('listings').select('*', { count: 'exact', head: true }).eq('status', 'approved');
  res.json({
    ok: true, service: 'Kor Da API v8 (Supabase)', time: new Date().toISOString(), stats: { listings: listings || 0 }
  });
});

app.get('/api/listings', optAuth, async (req, res) => {
  const { city, category, minPrice, maxPrice, page, limit } = req.query;
  let query = supabase.from('listings').select('*', { count: 'exact' }).eq('status', 'approved');
  
  if (city) query = query.ilike('city', `%${city}%`);
  if (category && category !== 'all') query = query.eq('category', category);
  if (minPrice) query = query.gte('price', Number(minPrice));
  if (maxPrice) query = query.lte('price', Number(maxPrice));

  const p = Math.max(1, parseInt(page) || 1);
  const lim = Math.min(50, Math.max(1, parseInt(limit) || 12));
  
  const { data, count, error } = await query.range((p - 1) * lim, p * lim - 1);
  if (error) return res.status(500).json({ ok: false, error: error.message });
  
  res.json({ ok: true, listings: data || [], total: count || 0, page: p, pages: Math.ceil((count || 0) / lim) });
});

app.get('/api/listings/:id', optAuth, async (req, res) => {
  const { data, error } = await supabase.from('listings').select('*').eq('id', req.params.id).eq('status', 'approved').single();
  if (error || !data) return res.status(404).json({ ok: false, error: 'Listing not found.' });
  
  const safe = { ...data, host: { name: data.host?.name, cnicVerified: true } };
  res.json({ ok: true, listing: safe });
});

// ── WAITLIST ──────────────────────────────────────────────
app.post('/api/waitlist', formLimit, async (req, res) => {
  const raw = san(req.body.email || '', 200);
  if (!raw || !validEmail(raw)) return res.status(400).json({ ok: false, error: 'Valid email required.' });
  
  const email = raw.toLowerCase().trim();
  const { error } = await supabase.from('waitlist').insert([{ email }]);
  if (error && error.code === '23505') return res.json({ ok: true, message: "You're already on the list!" });
  
  sendEmail(NOTIFY_EMAIL, '📬 Waitlist: ' + email, '<p>New signup: <strong>' + email + '</strong></p>');
  res.json({ ok: true, message: "You're on the list! Check your inbox." });
});

// ── CONTACT ───────────────────────────────────────────────
app.post('/api/contact', formLimit, async (req, res) => {
  const name = san(req.body.name || '', 100);
  const email = san(req.body.email || '', 200);
  const subject = san(req.body.subject || '', 200);
  const message = san(req.body.message || '', 3000);

  if (!name || !email || !message || message.length < 5) return res.status(400).json({ ok: false, error: 'Name, email, and message required.' });
  if (!validEmail(email)) return res.status(400).json({ ok: false, error: 'Invalid email.' });

  const { error } = await supabase.from('contacts').insert([{ name, email, subject, message }]);
  if (error) return res.status(500).json({ ok: false, error: 'Failed to send message.' });

  sendEmail(NOTIFY_EMAIL, '📩 Contact: ' + name, '<p>' + message + '</p>', email);
  res.json({ ok: true, message: "Message sent! We'll reply within 2 hours." });
});

// ── HOST APPLICATION ──────────────────────────────────────
app.post('/api/host', formLimit, upload.array('photos', 20), async (req, res) => {
  const { name, phone, cnic, city, type, beds, price, address, description, category, email, maxGuests } = req.body;

  if (!name || !phone || !cnic || !city || !address) return res.status(400).json({ ok: false, error: 'Please fill all required fields.' });
  const cnicClean = validCNIC(cnic);
  if (!cnicClean) return res.status(400).json({ ok: false, error: 'CNIC format: 00000-0000000-0' });
  const priceVal = validPrice(price);
  if (!priceVal) return res.status(400).json({ ok: false, error: 'Price must be PKR 100 to 10,000,000.' });

  const appId = 'APP-' + Date.now() + '-' + crypto.randomBytes(4).toString('hex').toUpperCase();
  
  // Upload photos to Supabase Storage
  const photos = [];
  if (req.files && req.files.length) {
    for (const file of req.files) {
      const ext = path.extname(file.originalname).toLowerCase().replace(/[^.a-z0-9]/g, '');
      const fileName = Date.now() + '-' + crypto.randomBytes(10).toString('hex') + ext;
      const { data, error } = await supabase.storage.from('uploads').upload(fileName, file.buffer, { contentType: file.mimetype });
      if (!error) {
        const { data: publicUrlData } = supabase.storage.from('uploads').getPublicUrl(fileName);
        photos.push(publicUrlData.publicUrl);
      }
    }
  }

  const appData = {
    id: appId,
    status: 'pending',
    host: { name: san(name, 100), phone: san(phone, 20), cnic: cnicClean, email: san(email || '', 200) },
    property: {
      city: san(city, 100), type: san(type || '', 100), beds: san(beds || '', 50), price: priceVal,
      maxGuests: parseInt(maxGuests) || 4, address: san(address, 500), description: san(description || '', 2000),
      category: san(category || '', 100), photos,
      amenities: Array.isArray(req.body.amenities) ? req.body.amenities.map(a => san(a, 50)) : (req.body.amenities ? [san(req.body.amenities, 50)] : [])
    }
  };

  const { error } = await supabase.from('applications').insert([appData]);
  if (error) return res.status(500).json({ ok: false, error: 'Database error. Please try again.' });

  sendEmail(NOTIFY_EMAIL, '🏡 HOST APPLICATION [' + appId + ']', '<p>New host application submitted.</p>');
  res.json({ ok: true, message: "Application received! We'll WhatsApp you.", id: appId });
});

// ── SUPABASE AUTH ─────────────────────────────────────────
app.post('/api/auth/signup', authLimit, async (req, res) => {
  const email = san(req.body.email || '', 200);
  const password = req.body.password;
  if (!email || !password) return res.status(400).json({ ok: false, error: 'Email and password required' });

  const { data, error } = await supabase.auth.signUp({ email, password });
  if (error) return res.status(400).json({ ok: false, error: error.message });
  res.json({ ok: true, user: data.user, message: 'Signup successful.' });
});

app.post('/api/auth/login', authLimit, async (req, res) => {
  const email = san(req.body.email || '', 200);
  const password = req.body.password;
  
  const { data, error } = await supabase.auth.signInWithPassword({ email, password });
  if (error) return res.status(401).json({ ok: false, error: error.message });
  res.json({ ok: true, token: data.session.access_token, user: data.user });
});

// ── BOOKINGS ──────────────────────────────────────────────
app.post('/api/bookings', requireAuth, formLimit, async (req, res) => {
  const { listingId, checkIn, checkOut, guests } = req.body;
  if (!listingId || !checkIn || !checkOut) return res.status(400).json({ ok: false, error: 'Fields required.' });

  const { data: listing } = await supabase.from('listings').select('*').eq('id', san(listingId, 50)).eq('status', 'approved').single();
  if (!listing) return res.status(404).json({ ok: false, error: 'Listing not available.' });

  const nights = Math.ceil((new Date(checkOut) - new Date(checkIn)) / 86400000);
  const total  = nights * listing.price;
  
  const bk = {
    id: 'BKG-' + Date.now() + '-' + crypto.randomBytes(4).toString('hex').toUpperCase(),
    listingId: listing.id, guestId: req.user.id, checkIn: san(checkIn, 12), checkOut: san(checkOut, 12),
    guests: Math.min(20, Math.max(1, parseInt(guests) || 1)), nights, totalAmount: total,
    commission: Math.round(total * COMMISSION), hostPayout: total - Math.round(total * COMMISSION),
    status: 'pending_payment'
  };

  const { error } = await supabase.from('bookings').insert([bk]);
  if (error) return res.status(500).json({ ok: false, error: 'Failed to create booking.' });
  res.status(201).json({ ok: true, booking: bk });
});

app.get('/api/bookings/my', requireAuth, async (req, res) => {
  const { data, error } = await supabase.from('bookings').select('*').eq('guestId', req.user.id);
  res.json({ ok: true, bookings: data || [] });
});

// ── ADMIN ─────────────────────────────────────────────────
app.post('/api/admin/login', async (req, res) => {
    const { email, password } = req.body;
    
    // Legacy password-only login (backward compatibility)
    if (!email && password === ADMIN_PASS) {
        const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '12h' });
        return res.json({ ok: true, token });
    }

    if (!email) return res.status(400).json({ ok: false, error: 'Email required' });

    try {
        // Authenticate with Supabase
        const { data, error } = await supabase.auth.signInWithPassword({ email, password });
        if (error) return res.status(401).json({ ok: false, error: error.message });

        // Check if the user is the designated admin
        if (data.user.email === ADMIN_EMAIL) {
            return res.json({ ok: true, token: data.session.access_token });
        } else {
            return res.status(403).json({ ok: false, error: 'Access denied: Not an administrator' });
        }
    } catch (err) {
        console.error('Admin login error:', err);
        res.status(500).json({ ok: false, error: 'Internal server error' });
    }
});

app.get('/api/admin/stats', adminLimit, requireAdmin, async (req, res) => {
  const [{ count: appsPending }, { count: listsApproved }, { count: bksTotal }, { count: waitTotal }, { data: bks }] = await Promise.all([
    supabase.from('applications').select('*', { count: 'exact', head: true }).eq('status', 'pending'),
    supabase.from('listings').select('*', { count: 'exact', head: true }).eq('status', 'approved'),
    supabase.from('bookings').select('*', { count: 'exact', head: true }),
    supabase.from('waitlist').select('*', { count: 'exact', head: true }),
    supabase.from('bookings').select('commission').eq('status', 'checked_in')
  ]);
  
  res.json({
    ok: true, stats: {
      applications: { pending: appsPending || 0 }, listings: { approved: listsApproved || 0 },
      bookings: { total: bksTotal || 0 }, waitlist: { count: waitTotal || 0 },
      revenue: { total: (bks || []).reduce((s, b) => s + (b.commission || 0), 0) },
    }
  });
});

app.get('/api/admin/applications', adminLimit, requireAdmin, async (req, res) => {
  const { data } = await supabase.from('applications').select('*');
  res.json({ ok: true, applications: data || [] });
});

app.post('/api/admin/applications/:id/approve', adminLimit, requireAdmin, async (req, res) => {
  const { data: appl } = await supabase.from('applications').select('*').eq('id', req.params.id).single();
  if (!appl) return res.status(404).json({ ok: false, error: 'Not found.' });
  
  await supabase.from('applications').update({ status: 'approved', approvedAt: new Date() }).eq('id', req.params.id);
  
  const listing = {
    id: 'LST-' + Date.now() + '-' + crypto.randomBytes(4).toString('hex').toUpperCase(),
    city: appl.property.city, type: appl.property.type, price: appl.property.price,
    ...appl.property, host: appl.host, status: 'approved', featured: false
  };
  await supabase.from('listings').insert([listing]);
  res.json({ ok: true, listing, message: 'Listing approved and live.' });
});

app.post('/api/admin/applications/:id/reject', adminLimit, requireAdmin, async (req, res) => {
  const reason = san(req.body.reason || 'Does not meet requirements', 500);
  await supabase.from('applications').update({ status: 'rejected', rejectedAt: new Date(), rejectionReason: reason }).eq('id', req.params.id);
  res.json({ ok: true, message: 'Application rejected.' });
});

app.get('/api/admin/listings', adminLimit, requireAdmin, async (req, res) => {
  const { data } = await supabase.from('listings').select('*'); res.json({ ok: true, listings: data || [] });
});
app.get('/api/admin/bookings', adminLimit, requireAdmin, async (req, res) => {
  const { data } = await supabase.from('bookings').select('*'); res.json({ ok: true, bookings: data || [] });
});
app.get('/api/admin/waitlist', adminLimit, requireAdmin, async (req, res) => {
  const { data } = await supabase.from('waitlist').select('*'); res.json({ ok: true, waitlist: data || [] });
});
app.get('/api/admin/contacts', adminLimit, requireAdmin, async (req, res) => {
  const { data } = await supabase.from('contacts').select('*'); res.json({ ok: true, contacts: data || [] });
});

app.patch('/api/admin/listings/:id/feature', adminLimit, requireAdmin, async (req, res) => {
  const { data: l } = await supabase.from('listings').select('featured').eq('id', req.params.id).single();
  if (!l) return res.status(404).json({ ok: false, error: 'Not found.' });
  await supabase.from('listings').update({ featured: !l.featured }).eq('id', req.params.id);
  res.json({ ok: true, featured: !l.featured });
});

app.use((err, req, res, next) => {
  console.error('[ERROR]', err.message);
  res.status(err.status || 500).json({ ok: false, error: 'Internal server error.' });
});

app.listen(PORT, () => {
  console.log('\n🏡  Kor Da Backend v8 (Supabase)');
  console.log('    Port:    ' + PORT);
});

module.exports = app;
