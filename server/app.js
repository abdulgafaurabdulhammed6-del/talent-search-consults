const path = require('path');
const fs = require('fs');
const express = require('express');
const helmet = require('helmet');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const FileType = require('file-type');
const csurf = require('csurf');
const Storage = require('./lib/storage');
const Validation = require('./lib/validation');
const DB = require('./lib/db');
const bcrypt = require('bcrypt');

require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Production environment checks
if (process.env.NODE_ENV === 'production') {
  if (!process.env.SESSION_SECRET) {
    console.error('FATAL: SESSION_SECRET must be set in production.');
    process.exit(1);
  }
  if (!process.env.ADMIN_EMAIL || !(process.env.ADMIN_PASSWORD || process.env.ADMIN_PASSWORD_HASH)) {
    console.error('FATAL: ADMIN_EMAIL and ADMIN_PASSWORD (or ADMIN_PASSWORD_HASH) must be set in production.');
    process.exit(1);
  }
}

app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '..', 'public')));

// Session (admin) - cookie hardening and note about production store
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 4 // 4 hours
  }
}));
// NOTE: Replace MemoryStore with a durable store (Redis) in production.

// Ensure secure upload directory exists and is not inside public
const UPLOAD_DIR = process.env.UPLOAD_DIR || path.join(__dirname, '..', 'secure_uploads');
const PUBLIC_DIR = path.join(__dirname, '..', 'public');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true, mode: 0o700 });
const absoluteUpload = path.resolve(UPLOAD_DIR);
if (absoluteUpload.startsWith(path.resolve(PUBLIC_DIR))) {
  console.error('FATAL: UPLOAD_DIR must not be inside the public directory. Update UPLOAD_DIR in your environment.');
  process.exit(1);
}

// Multer setup (store in memory then validate before saving to disk)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: parseInt(process.env.MAX_UPLOAD_BYTES || 10 * 1024 * 1024) }, // default 10MB
  fileFilter: (req, file, cb) => {
    // quick prefilter based on mimetype (not authoritative)
    const allowed = ['application/pdf', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'];
    if (!allowed.includes(file.mimetype)) {
      return cb(new multer.MulterError('LIMIT_UNEXPECTED_FILE', 'Only PDF and DOCX files are allowed'));
    }
    cb(null, true);
  }
});

// Rate limiter: 10 submissions per IP per hour
const submitLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: parseInt(process.env.RATE_LIMIT_SUBMISSIONS || 10), message: 'Too many submissions from this IP, please try later.' });

// Admin login rate limiter and CSRF protection
const adminLoginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 6, message: 'Too many login attempts from this IP, try again later.' });
const csrfProtection = csurf({ cookie: false });

// POST /api/submit-resume
app.post('/api/submit-resume', submitLimiter, upload.single('resume'), async (req, res, next) => {
  try {
    // Server-side validation
    const { name, email, phone, packageName } = req.body;
    const errors = Validation.validateSubmission({ name, email, phone, packageName });
    if (errors.length) return res.status(400).json({ errors });
    if (!req.file) return res.status(400).json({ errors: ['Resume file is required'] });

    // Validate file's magic bytes to avoid mimetype spoofing
    const ft = await FileType.fromBuffer(req.file.buffer);
    const allowedMimes = ['application/pdf', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'];
    if (!ft || !allowedMimes.includes(ft.mime)) {
      return res.status(400).json({ errors: ['Uploaded file is not a valid PDF or DOCX document'] });
    }

    // Save file securely (storage module will write to UPLOAD_DIR with safe filename)
    const stored = await Storage.saveBuffer(req.file.buffer, req.file.originalname, UPLOAD_DIR);

    // Save metadata in DB
    const id = DB.insertSubmission({ name, email, phone, packageName, originalFilename: req.file.originalname, storedFilename: stored.filename, mime: ft.mime, size: req.file.size });

    // Minimal response
    res.json({ success: true, id });
  } catch (err) {
    // Pass to centralized error handler
    next(err);
  }
});

// Admin auth middleware
function requireAdmin(req, res, next) {
  if (req.session && req.session.isAdmin) return next();
  return res.redirect('/admin/login');
}

// Helper: escape HTML to prevent XSS
function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Admin login page (with CSRF token)
app.get('/admin/login', csrfProtection, (req, res) => {
  res.send(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Admin Login</title><link rel="stylesheet" href="/styles.css"></head><body><main class="container"><h1>Admin Login</h1><form method="POST" action="/admin/login"><input type="hidden" name="_csrf" value="${req.csrfToken()}"><label>Email<br><input name="email" type="email" required></label><br><label>Password<br><input name="password" type="password" required></label><br><button class="btn btn-primary" type="submit">Sign in</button></form></main></body></html>`);
});

// Prepare admin password hash (in-memory) if plain password is supplied
let adminHash = process.env.ADMIN_PASSWORD_HASH || null;
(async () => {
  if (!adminHash && process.env.ADMIN_PASSWORD) {
    adminHash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 10);
  }
})();

// Admin login POST handler with rate limiter and CSRF protection
app.post('/admin/login', adminLoginLimiter, csrfProtection, express.urlencoded({ extended: true }), async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!process.env.ADMIN_EMAIL || !adminHash) {
      return res.status(500).send('Admin account not configured.');
    }
    if (email !== process.env.ADMIN_EMAIL) {
      return res.status(401).send('Invalid credentials');
    }
    const ok = await bcrypt.compare(password, adminHash);
    if (!ok) return res.status(401).send('Invalid credentials');
    req.session.isAdmin = true;
    res.redirect('/admin/submissions');
  } catch (err) {
    console.error('Admin login error:', { message: err && err.message });
    res.status(500).send('Server error');
  }
});

// Admin submissions list
app.get('/admin/submissions', requireAdmin, (req, res) => {
  const subs = DB.listSubmissions();
  const rows = subs.map(s => `<tr><td>${s.id}</td><td>${escapeHtml(s.name)}</td><td>${escapeHtml(s.email)}</td><td>${escapeHtml(new Date(s.created_at).toISOString())}</td><td><a href="/admin/submissions/${s.id}/download">Download</a></td></tr>`).join('');
  res.send(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Submissions</title><link rel="stylesheet" href="/styles.css"></head><body><main class="container"><h1>Submissions</h1><table style="width:100%;border-collapse:collapse"><thead><tr><th>ID</th><th>Name</th><th>Email</th><th>Received</th><th>File</th></tr></thead><tbody>${rows}</tbody></table><p><a href="/admin/logout">Log out</a></p></main></body></html>`);
});

// Admin download - streamed via server; sanitize filename
app.get('/admin/submissions/:id/download', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id, 10);
  const sub = DB.getSubmission(id);
  if (!sub) return res.status(404).send('Not found');
  const filePath = path.join(UPLOAD_DIR, sub.stored_filename);
  if (!fs.existsSync(filePath)) return res.status(404).send('File not found');
  const safeFilename = path.basename(sub.original_filename).replace(/[\r\n]/g, '_');
  return res.download(filePath, safeFilename);
});

app.get('/admin/logout', (req, res) => { req.session.destroy(() => res.redirect('/admin/login')); });

// Multer and general error handler
app.use((err, req, res, next) => {
  if (err && err.code && String(err.code).startsWith('LIMIT_')) {
    return res.status(413).json({ error: 'Uploaded file exceeds the allowed size.' });
  }
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ error: err.message });
  }
  console.error('Unhandled server error:', { message: err && err.message });
  res.status(500).json({ error: 'Server error' });
});

// Start DB and server
DB.init();
app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));

module.exports = app;
