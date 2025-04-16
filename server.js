#!/usr/bin/env node
const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

// =============================================
// MOBILE CONFIGURATION
// =============================================
process.env.NODE_OPTIONS = '--max-old-space-size=256'; // Reduce memory usage
const PORT = 3000;
const SECRET_KEY = 'Neuille21@'; // CHANGE THIS IN PRODUCTION!
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB limit for mobile

// =============================================
// INITIALIZE SERVER
// =============================================
const app = express();

// Mobile-optimized middleware
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST']
}));
app.use(express.json({ limit: '1mb' }));
app.use(express.static('public'));

// =============================================
// FILE STORAGE SETUP
// =============================================
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = 'public/uploads/';
    if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const safeName = file.originalname.replace(/[^a-zA-Z0-9._-]/g, '');
    cb(null, Date.now() + '-' + safeName.substring(0, 50)); // Truncate long names
  }
});

const upload = multer({
  storage,
  limits: { fileSize: MAX_FILE_SIZE },
  fileFilter: (req, file, cb) => {
    const allowedTypes = [
      'image/jpeg', 'image/png', 'application/pdf', 
      'text/plain', 'application/zip', 'application/vnd.android.package-archive'
    ];
    cb(null, allowedTypes.includes(file.mimetype));
  }
});

// =============================================
// DATABASE SETUP (JSON files)
// =============================================
const DB_PATHS = {
  users: path.join(__dirname, 'db-users.json'),
  files: path.join(__dirname, 'db-files.json'),
  contacts: path.join(__dirname, 'db-contacts.json')
};

function initDatabase() {
  // Initialize users database
  if (!fs.existsSync(DB_PATHS.users)) {
    const hashedPassword = bcrypt.hashSync("Neuille21@", 10);
    fs.writeFileSync(DB_PATHS.users, JSON.stringify([
      {
        id: "1",
        username: "admin",
        password: hashedPassword,
        role: "owner",
        createdAt: new Date().toISOString()
      }
    ], null, 2));
  }

  // Initialize files database
  if (!fs.existsSync(DB_PATHS.files)) {
    fs.writeFileSync(DB_PATHS.files, JSON.stringify({
      all: [],
      computing: [],
      school: [],
      android: []
    }, null, 2));
  }

  // Initialize contacts database
  if (!fs.existsSync(DB_PATHS.contacts)) {
    fs.writeFileSync(DB_PATHS.contacts, JSON.stringify([], null, 2));
  }
}

function readDB(dbName) {
  initDatabase();
  return JSON.parse(fs.readFileSync(DB_PATHS[dbName]));
}

function writeDB(dbName, data) {
  fs.writeFileSync(DB_PATHS[dbName], JSON.stringify(data, null, 2));
}

// =============================================
// AUTHENTICATION MIDDLEWARE
// =============================================
function authenticate(req, res, next) {
  const token = req.headers['x-auth-token'] || req.headers.authorization?.split(' ')[1];
  
  if (!token) return res.status(401).json({ error: 'Authentication required' });

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    
    const users = readDB('users');
    const user = users.find(u => u.id === decoded.id);
    if (!user) return res.status(403).json({ error: 'User not found' });
    
    req.user = user;
    next();
  });
}

// =============================================
// API ROUTES
// =============================================

// -------------------------
// Authentication Routes
// -------------------------
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const users = readDB('users');
  const user = users.find(u => u.username === username);

  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    SECRET_KEY,
    { expiresIn: '4h' }
  );

  res.json({ 
    token,
    user: {
      id: user.id,
      username: user.username,
      role: user.role
    }
  });
});

// -------------------------
// File Routes
// -------------------------
app.get('/api/files', (req, res) => {
  const category = req.query.category || 'all';
  const files = readDB('files');
  
  if (!files[category]) return res.status(400).json({ error: 'Invalid category' });
  
  res.json(files[category]);
});

app.post('/api/files', authenticate, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  const files = readDB('files');
  const newFile = {
    id: Date.now().toString(),
    name: req.file.originalname,
    path: '/uploads/' + req.file.filename,
    size: (req.file.size / 1024).toFixed(2) + ' KB',
    uploadedAt: new Date().toLocaleString(),
    category: req.body.category || 'other',
    uploadedBy: req.user.username
  };

  files[newFile.category].unshift(newFile);
  files.all.unshift(newFile);
  writeDB('files', files);

  res.json({ 
    success: true,
    file: newFile
  });
});

// -------------------------
// Contact Form Route
// -------------------------
app.post('/api/contact', (req, res) => {
  const { name, email, subject, message } = req.body;
  
  if (!name || !email || !subject || !message) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  const contacts = readDB('contacts');
  const newContact = {
    id: Date.now().toString(),
    name,
    email,
    subject,
    message,
    date: new Date().toISOString(),
    status: 'unread'
  };

  contacts.unshift(newContact);
  writeDB('contacts', contacts);

  res.json({ 
    success: true,
    message: 'Your message has been received!'
  });
});

// -------------------------
// Admin Routes (Optional)
// -------------------------
app.get('/api/admin/contacts', authenticate, (req, res) => {
  if (req.user.role !== 'owner') return res.status(403).json({ error: 'Forbidden' });
  res.json(readDB('contacts'));
});

// =============================================
// START SERVER (Mobile-optimized)
// =============================================
app.listen(PORT, '0.0.0.0', () => {
  initDatabase();
  console.log(`
  🚀 Mobile Server Running!
  Local:  http://localhost:${PORT}
  Network: http://${getLocalIP()}:${PORT}
  
  Admin Credentials:
  Username: admin
  Password: Neuille21@
  
  Endpoints:
  - POST /api/login
  - POST /api/contact
  - GET /api/files?category=[all|computing|school|android]
  - POST /api/files (with auth)
  `);
});

function getLocalIP() {
  const { networkInterfaces } = require('os');
  const nets = networkInterfaces();
  for (const name of Object.keys(nets)) {
    for (const net of nets[name]) {
      if (net.family === 'IPv4' && !net.internal) {
        return net.address;
      }
    }
  }
  return '0.0.0.0';
}