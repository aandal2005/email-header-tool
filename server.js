// 📁 server.js
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fetch = require('node-fetch');

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = 'your-secret-key'; // Replace with environment variable in production

// MongoDB Connection
mongoose.connect('mongodb+srv://aandal:aandal2005@emailheadercluster.e2ir8k8.mongodb.net/emailAnalyzer?retryWrites=true&w=majority&appName=EmailHeaderCluster', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('✅ MongoDB connected'))
  .catch((err) => console.error('❌ MongoDB connection error:', err));

// Middleware
app.use(cors({ origin: 'https://email-header-frontend.onrender.com' }));
app.use(express.json());

// Schemas
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
});
const User = mongoose.model('User', userSchema);

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
  createdAt: { type: Date, default: Date.now },
  userId: mongoose.Schema.Types.ObjectId
});
const Header = mongoose.model('Header', headerSchema);

// Auth Middleware
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No token provided' });

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// Auth Routes
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ error: 'All fields are required' });

  const existingUser = await User.findOne({ email });
  if (existingUser) return res.status(400).json({ error: 'Email already registered' });

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = new User({ name, email, password: hashedPassword });
  await newUser.save();

  res.json({ message: 'Registered successfully' });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ error: 'Invalid email or password' });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).json({ error: 'Invalid email or password' });

  const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ message: 'Login successful', token });
});

// Analyze Route
function extractSenderIP(header) {
  const match = header.match(/Received: from .*\[(\d+\.\d+\.\d+\.\d+)\]/);
  return match ? match[1] : null;
}

app.post('/analyze', authMiddleware, async (req, res) => {
  const header = req.body.header;
  if (!header) return res.status(400).json({ error: 'No header provided' });

  const importantKeys = ['From', 'To', 'Delivered-To', 'Return-Path', 'Received-SPF', 'Subject', 'Date'];
  const lines = header.split('\n');
  const result = {};

  lines.forEach(line => {
    const [key, ...rest] = line.split(':');
    const trimmedKey = key.trim();
    if (importantKeys.includes(trimmedKey) && rest.length > 0) {
      result[trimmedKey] = rest.join(':').trim();
    }
  });

  const spfMatch = header.match(/spf=(\w+)/i);
  const dkimMatch = header.match(/dkim=(\w+)/i);
  const dmarcMatch = header.match(/dmarc=(\w+)/i);
  result['SPF Status'] = spfMatch ? spfMatch[1] : 'not found';
  result['DKIM Status'] = dkimMatch ? dkimMatch[1] : 'not found';
  result['DMARC Status'] = dmarcMatch ? dmarcMatch[1] : 'not found';

  if (result['SPF Status'] === 'pass' && result['DKIM Status'] === 'pass' && result['DMARC Status'] === 'pass') {
    result['Safe Meter'] = '✅ Safe – All checks passed';
  } else if ([result['SPF Status'], result['DKIM Status'], result['DMARC Status']].filter(x => x === 'pass').length >= 2) {
    result['Safe Meter'] = '⚠️ Risk – Partial checks passed';
  } else {
    result['Safe Meter'] = '❌ Unsafe – Failed checks';
  }

  const senderIP = extractSenderIP(header);
  if (senderIP) {
    try {
      const geoRes = await fetch(`http://ip-api.com/json/${senderIP}`);
      const geoData = await geoRes.json();
      result['Sender IP'] = senderIP;
      result['IP Location'] = `${geoData.city}, ${geoData.regionName}, ${geoData.country}`;
    } catch (err) {
      result['Sender IP'] = senderIP;
      result['IP Location'] = '❌ Location lookup failed';
    }
  } else {
    result['Sender IP'] = 'Not found';
    result['IP Location'] = 'N/A';
  }

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
    ipLocation: result['IP Location'],
    userId: req.user.userId
  });

  res.json(result);
});

// History Route
app.get('/history', authMiddleware, async (req, res) => {
  try {
    const history = await Header.find({ userId: req.user.userId }).sort({ createdAt: -1 }).limit(50);
    res.json(history);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch history' });
  }
});

// Start server
app.listen(PORT, () => console.log(`✅ Server running at http://localhost:${PORT}`));
