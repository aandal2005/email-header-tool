const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const fetch = require('node-fetch');
const bcrypt = require('bcryptjs');
const dns = require('dns').promises;
require('dotenv').config();

const app = express();

const PORT = process.env.PORT || 10000;
const SECRET = process.env.JWT_SECRET || 'secret_key';
const MONGO_URI = process.env.MONGO_URI || 'mongodb+srv://aandal:aandal2005@emailheadercluster.e2ir8k8.mongodb.net/emailAnalyzer?retryWrites=true&w=majority';

// MongoDB connection
mongoose.connect(MONGO_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// Middleware
const allowedOrigins = [
  'https://email-header-frontend.onrender.com', // deployed frontend
  'http://127.0.0.1:5500',                     // local frontend for testing
];

app.use(cors({
  origin: function(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('CORS not allowed'));
    }
  },
  methods: ['GET','POST','DELETE','OPTIONS'],
  credentials: true
}));
app.use(express.json());

// Header Schema
const headerSchema = new mongoose.Schema({
  from: String,
  to: String,
  subject: String,
  date: String,
  spf: String,
  dkim: String,
  dmarc: String,
  safeMeter: String,
  senderIP: String,
  ipLocation: String,
  createdAt: { type: Date, default: Date.now }
});
const Header = mongoose.model('Header', headerSchema);

// User model
const User = require('./models/User');

// Admin-only middleware
function adminOnly(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ error: 'Access denied' });

  try {
    const verified = jwt.verify(token, SECRET);
    if (verified.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    next();
  } catch (err) {
    res.status(400).json({ error: 'Invalid token' });
  }
}

// DMARC Helpers
async function getDmarcRecord(domain) {
  try {
    const records = await dns.resolveTxt(`_dmarc.${domain}`);
    return records.flat().join('');
  } catch {
    return null;
  }
}

function parseDmarcPolicy(record) {
  const match = record.match(/p=(none|quarantine|reject)/i);
  return match ? match[1].toLowerCase() : 'unknown';
}

// Extract Sender IP
function extractSenderIP(headerText) {
  const matches = headerText.match(/\[(\d{1,3}(?:\.\d{1,3}){3})\]/);
  return matches ? matches[1] : null;
}

// Register Route
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'All fields are required' });

  try {
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ error: 'Email already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashedPassword, role: 'user' });
    await user.save();

    res.json({ message: '✅ Registered successfully' });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ error: '❌ Server error during registration' });
  }
});

// Login Route
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'User not found' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: 'Invalid password' });

    const token = jwt.sign({ id: user._id, role: user.role }, SECRET, { expiresIn: '2h' });
    res.json({ message: '✅ Login successful', token, role: user.role || 'user' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '❌ Server error' });
  }
});

// Analyze Route
app.post('/analyze', async (req, res) => {
  const header = req.body.header;
  if (!header) return res.status(400).json({ error: 'No header provided' });

  const importantKeys = ['From', 'To', 'Subject', 'Date'];
  const lines = header.split('\n');
  const result = {};

  // Extract basic header info
  lines.forEach(line => {
    const [key, ...rest] = line.split(':');
    if (!key || rest.length === 0) return;
    const trimmedKey = key.trim();
    if (importantKeys.includes(trimmedKey)) result[trimmedKey] = rest.join(':').trim();
  });

  // SPF and DKIM extraction
  const spfRaw = (header.match(/spf=(\w+)/i) || [])[1];
  const dkimRaw = (header.match(/dkim=(\w+)/i) || [])[1];

  const spf = spfRaw ? spfRaw.toLowerCase() : 'not found';
  const dkim = dkimRaw ? dkimRaw.toLowerCase() : 'not found';

  // DMARC lookup
  let fromDomain = null;
  if (result['From']) {
    const match = result['From'].match(/<(.+)>/);
    const fromEmail = match?.[1] || result['From'];
    fromDomain = fromEmail.split('@')[1];
  }

  let dmarc = 'not found';
  if (fromDomain) {
    const dmarcRecord = await getDmarcRecord(fromDomain);
    if (dmarcRecord) dmarc = parseDmarcPolicy(dmarcRecord);
  }

  result['SPF Status'] = spf;
  result['DKIM Status'] = dkim;
  result['DMARC Status'] = dmarc;

  // Safe Meter
  const statuses = [spf, dkim, dmarc];
  const passCount = statuses.filter(v => v === 'pass').length;
  const unknownCount = statuses.filter(v => v === 'not found' || v === 'none').length;

  if (passCount === 3) result['Safe Meter'] = '✅ Safe – All checks passed';
  else if (passCount >= 2 || (passCount >= 1 && unknownCount > 0)) result['Safe Meter'] = '⚠️ Risk – Partial checks passed';
  else result['Safe Meter'] = '❌ Unsafe – Failed checks';

  // Sender IP & Geolocation
  const senderIP = extractSenderIP(header);
  result['Sender IP'] = senderIP || 'Not found';
  if (senderIP) {
    try {
      const geo = await fetch(`https://ip-api.com/json/${senderIP}`);
      const loc = await geo.json();
      result['IP Location'] = loc.status === 'success' ? `${loc.city}, ${loc.regionName}, ${loc.country}` : '❌ Lookup failed';
    } catch {
      result['IP Location'] = '❌ Lookup failed';
    }
  } else {
    result['IP Location'] = 'N/A';
  }

  // Save to DB
  try {
    await Header.create({
      from: result['From'],
      to: result['To'],
      subject: result['Subject'],
      date: result['Date'],
      spf: result['SPF Status'],
      dkim: result['DKIM Status'],
      dmarc: result['DMARC Status'],
      safeMeter: result['Safe Meter'],
      senderIP: result['Sender IP'],
      ipLocation: result['IP Location']
    });
  } catch (err) {
    console.error('DB Save Error:', err);
  }

  res.json({
    from: result['From'] || "Not found",
    to: result['To'] || "Not found",
    subject: result['Subject'] || "Not found",
    date: result['Date'] || "Not found",
    spf: result['SPF Status'] || "not found",
    dkim: result['DKIM Status'] || "not found",
    dmarc: result['DMARC Status'] || "not found",
    safeMeter: result['Safe Meter'] || "❌ Unsafe",
    senderIP: result['Sender IP'] || "Not found",
    ipLocation: result['IP Location'] || "N/A"
  });
});

// History Routes
app.get('/history', async (req, res) => {
  try {
    const history = await Header.find().sort({ createdAt: -1 }).limit(50);
    res.json(history);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch history' });
  }
});

app.delete('/history', adminOnly, async (req, res) => {
  try {
    await Header.deleteMany({});
    res.json({ message: 'History cleared successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to clear history' });
  }
});

// Start Server
app.listen(PORT, () => console.log(`✅ Server running at http://localhost:${PORT}`));
