const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const fetch = require('node-fetch');
const bcrypt = require('bcryptjs');
const app = express();

const PORT = process.env.PORT || 10000;
const SECRET = 'secret_key'; // 🔐 Use environment variable in production

// MongoDB connection
mongoose.connect('mongodb+srv://aandal:aandal2005@emailheadercluster.e2ir8k8.mongodb.net/emailAnalyzer?retryWrites=true&w=majority')
  .then(() => console.log('✅ MongoDB connected'))
  .catch((err) => console.error('❌ MongoDB connection error:', err));

// Middleware
app.use(cors({
  origin: 'https://email-header-frontend.onrender.com',
}));
app.use(express.json());

// Mongoose schema for email headers
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

// Import user model
const User = require('./models/User');

// 🔐 Admin-only middleware
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

// 🔐 Register
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(400).json({ error: 'Email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    // 👇 Set default role as "user"
    const user = new User({ name, email, password: hashedPassword, role: 'user' });
    await user.save();

    res.json({ message: '✅ Registered successfully' });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ error: '❌ Server error during registration' });
  }
});

// 🔐 Login
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

// Extract sender IP
function extractSenderIP(header) {
  const match = header.match(/Received: from .*\[(\d+\.\d+\.\d+\.\d+)\]/);
  return match ? match[1] : null;
}

// 📌 Analyze email header
app.post('/analyze', async (req, res) => {
  const header = req.body.header;
  if (!header) return res.status(400).json({ error: 'No header provided' });

  const importantKeys = ['From', 'To', 'Subject', 'Date'];
  const lines = header.split('\n');
  const result = {};

  lines.forEach(line => {
    const [key, ...rest] = line.split(':');
    const trimmedKey = key.trim();
    if (importantKeys.includes(trimmedKey) && rest.length > 0) {
      result[trimmedKey] = rest.join(':').trim();
    }
  });

  const spf = (header.match(/spf=(\w+)/i) || [])[1] || 'not found';
  const dkim = (header.match(/dkim=(\w+)/i) || [])[1] || 'not found';
  const dmarc = (header.match(/dmarc=(\w+)/i) || [])[1] || 'not found';

  result['SPF Status'] = spf.toLowerCase();
  result['DKIM Status'] = dkim.toLowerCase();
  result['DMARC Status'] = dmarc.toLowerCase();

  if (spf === 'pass' && dkim === 'pass' && dmarc === 'pass') result['Safe Meter'] = '✅ Safe – All checks passed';
  else if ([spf, dkim, dmarc].filter(v => v === 'pass').length >= 2) result['Safe Meter'] = '⚠️ Risk – Partial checks passed';
  else result['Safe Meter'] = '❌ Unsafe – Failed checks';

  const senderIP = extractSenderIP(header);
  if (senderIP) {
    try {
      const geo = await fetch(`http://ip-api.com/json/${senderIP}`);
      const loc = await geo.json();
      result['Sender IP'] = senderIP;
      result['IP Location'] = `${loc.city}, ${loc.regionName}, ${loc.country}`;
    } catch {
      result['Sender IP'] = senderIP;
      result['IP Location'] = '❌ Lookup failed';
    }
  } else {
    result['Sender IP'] = 'Not found';
    result['IP Location'] = 'N/A';
  }

  // Save to DB
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

// 📌 Get history
app.get('/history', async (req, res) => {
  try {
    const history = await Header.find().sort({ createdAt: -1 }).limit(50);
    const cleanHistory = history.map(item => ({
      from: item.from,
      to: item.to,
      subject: item.subject,
      date: item.date,
      spf: item.spf,
      dkim: item.dkim,
      dmarc: item.dmarc,
      safeMeter: item.safeMeter,
      senderIP: item.senderIP,
      ipLocation: item.ipLocation
    }));
    res.json(cleanHistory);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '❌ Failed to fetch history' });
  }
});

// 📌 Clear history (admin only)
app.delete('/history', adminOnly, async (req, res) => {
  try {
    await Header.deleteMany({});
    res.json({ message: 'History cleared successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '❌ Failed to clear history' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`);
});
