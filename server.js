// server.js
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const fetch = require('node-fetch'); // if using Node18+ you can use global fetch instead
const dns = require('dns').promises;
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;
const SECRET = process.env.JWT_SECRET || 'secret_key';
const MONGO_URI = process.env.MONGO_URI || "mongodb+srv://aandal:aandal2005@emailheadercluster.e2ir8k8.mongodb.net/emailAnalyzer?retryWrites=true&w=majority";

// ---------- Middleware & CORS ----------
/*
  Replace these with your real frontend URL(s).
  Keep the origin check strict in production.
*/
const allowedOrigins = [
  'https://email-header-frontend.onrender.com', // your deployed frontend (example)
  'https://your-username.github.io',            // if you use GitHub Pages
  'http://127.0.0.1:5500'                      // local frontend for testing
];

app.use(cors({
  origin: function(origin, callback) {
    // allow requests with no origin (e.g. Postman, mobile apps)
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    console.warn('Blocked CORS origin:', origin);
    return callback(new Error('CORS not allowed'));
  },
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  credentials: true
}));

// parse json bodies
app.use(express.json({ limit: '200kb' }));

// ---------- MongoDB ----------
if (!MONGO_URI) {
  console.error('❌ MONGO_URI is not set. Please set process.env.MONGO_URI');
  process.exit(1);
}

mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);
  });

// ---------- Schemas / Models ----------
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

// Ensure you have ./models/User.js (provided below)
const User = require('./models/User');

// ---------- Helpers ----------
function safeSplitLines(text) {
  // handle \r\n and \n and \r
  return text.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
}

async function getDmarcRecord(domain) {
  try {
    const records = await dns.resolveTxt(`_dmarc.${domain}`);
    return records.flat().join('');
  } catch (err) {
    return null;
  }
}
function parseDmarcPolicy(record) {
  const match = record && record.match(/p=(none|quarantine|reject)/i);
  return match ? match[1].toLowerCase() : 'unknown';
}

function extractSenderIP(headerText) {
  // looks for [x.x.x.x] patterns often present in Received headers
  const matches = headerText.match(/\[(\d{1,3}(?:\.\d{1,3}){3})\]/);
  return matches ? matches[1] : null;
}

function parseTokenFromHeader(headerValue) {
  // allow "Bearer <token>" or just token
  if (!headerValue) return null;
  const parts = headerValue.split(' ');
  return parts.length === 2 && parts[0].toLowerCase() === 'bearer' ? parts[1] : headerValue;
}

// ---------- Auth middleware ----------
function adminOnly(req, res, next) {
  try {
    const raw = req.headers['authorization'];
    const token = parseTokenFromHeader(raw);
    if (!token) return res.status(401).json({ error: 'Access denied' });
    const verified = jwt.verify(token, SECRET);
    if (verified.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    req.user = verified;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ---------- Routes ----------
// Register
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });

  try {
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ error: 'Email already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashedPassword, role: 'user' });
    await user.save();
    return res.json({ message: '✅ Registered successfully' });
  } catch (err) {
    console.error('Register error:', err);
    return res.status(500).json({ error: 'Server error during registration' });
  }
});

// Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'User not found' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: 'Invalid password' });

    const token = jwt.sign({ id: user._id, role: user.role }, SECRET, { expiresIn: '2h' });
    return res.json({ message: '✅ Login successful', token, role: user.role || 'user' });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// ------------------ ANALYZE ROUTE ------------------
app.post('/analyze', async (req, res) => {
  try {
    const { header } = req.body;
    if (!header) return res.status(400).json({ error: 'No header provided' });

    const importantKeys = ['From', 'To', 'Subject', 'Date'];
    const lines = header.split('\n');
    const result = {};

    // Extract basic info
    lines.forEach(line => {
      const [key, ...rest] = line.split(':');
      if (!key || rest.length === 0) return;
      const trimmedKey = key.trim();
      if (importantKeys.includes(trimmedKey)) result[trimmedKey] = rest.join(':').trim();
    });

    // SPF / DKIM
    const spfRaw = (header.match(/spf=(\w+)/i) || [])[1];
    const dkimRaw = (header.match(/dkim=(\w+)/i) || [])[1];
    const spf = spfRaw ? spfRaw.toLowerCase() : 'not found';
    const dkim = dkimRaw ? dkimRaw.toLowerCase() : 'not found';

    // DMARC
    let dmarc = 'not found';
    try {
      if (result['From']) {
        const match = result['From'].match(/<(.+)>/);
        const fromEmail = match?.[1] || result['From'];
        const fromDomain = fromEmail.split('@')[1];
        if (fromDomain) {
          const dmarcRecord = await getDmarcRecord(fromDomain);
          if (dmarcRecord) dmarc = parseDmarcPolicy(dmarcRecord);
        }
      }
    } catch {
      dmarc = 'lookup failed';
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

    // Sender IP & geolocation
    let senderIP = extractSenderIP(header);
    result['Sender IP'] = senderIP || 'Not found';
    try {
      if (senderIP) {
        const geo = await fetch(`http://ip-api.com/json/${senderIP}`);
        const loc = await geo.json();
        result['IP Location'] = loc.status === 'success'
          ? `${loc.city}, ${loc.regionName}, ${loc.country}`
          : '❌ Lookup failed';
      } else {
        result['IP Location'] = 'N/A';
      }
    } catch {
      result['IP Location'] = '❌ Lookup failed';
    }

    // Save to DB (ignore errors)
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
    } catch (dbErr) {
      console.error('DB Save Error:', dbErr.message);
    }

    // Always respond safely
    res.json({
      from: result['From'] || "Not found",
      to: result['To'] || "Not found",
      subject: result['Subject'] || "Not found",
      date: result['Date'] || "Not found",
      spf: result['SPF Status'],
      dkim: result['DKIM Status'],
      dmarc: result['DMARC Status'],
      safeMeter: result['Safe Meter'],
      senderIP: result['Sender IP'],
      ipLocation: result['IP Location']
    });

  } catch (err) {
    console.error("Analyze Error:", err.message);
    res.status(200).json({   // ✅ prevent 500
      from: "Error",
      to: "Error",
      subject: "Error",
      date: "Error",
      spf: "error",
      dkim: "error",
      dmarc: "error",
      safeMeter: "❌ Analysis failed",
      senderIP: "N/A",
      ipLocation: "N/A"
    });
  }
});
// History
app.get('/history', async (req, res) => {
  try {
    const history = await Header.find().sort({ createdAt: -1 }).limit(50);
    return res.json(history);
  } catch (err) {
    console.error('History fetch error:', err);
    return res.status(500).json({ error: 'Failed to fetch history' });
  }
});

app.delete('/history', adminOnly, async (req, res) => {
  try {
    await Header.deleteMany({});
    return res.json({ message: 'History cleared successfully' });
  } catch (err) {
    console.error('Clear history error:', err);
    return res.status(500).json({ error: 'Failed to clear history' });
  }
});

// 404 handler
app.use((req, res) => res.status(404).json({ error: 'Endpoint not found' }));

// Global error handlers
process.on('unhandledRejection', (reason) => {
  console.error('Unhandled Rejection:', reason);
});
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
});

app.listen(PORT, () => console.log(`✅ Server running at port ${PORT}`));
