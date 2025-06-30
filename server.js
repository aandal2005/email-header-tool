const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const fetch = require('node-fetch');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const EmailHeader = require('./models/EmailHeader');
const User = require('./models/User');

dotenv.config();

const app = express();

// CORS for frontend
app.use(cors({
  origin: 'https://email-header-frontend.onrender.com'
}));

app.use(express.json());

// Connect MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// Extract sender IP
function extractSenderIP(header) {
  const match = header.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/);
  return match ? match[0] : 'Unknown';
}

// Rate safe meter
function getSafeMeter(spf, dkim, dmarc) {
  const passed = [spf, dkim, dmarc].filter(r => r === 'pass').length;
  if (passed === 3) return 'Safe';
  if (passed === 2) return 'Moderate';
  return 'Unsafe';
}

// Login API
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ error: 'User not found' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ error: 'Incorrect password' });

    const token = jwt.sign({ username: user.username, role: user.role }, 'secretkey', { expiresIn: '1h' });
    res.json({ token, role: user.role });
  } catch (error) {
    console.error('❌ Login Error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Analyze Email Header
app.post('/api/analyze', async (req, res) => {
  const header = req.body.header;
  if (!header) return res.status(400).json({ error: 'Header is required' });

  try {
    const from = (header.match(/From: (.*)/) || [])[1] || 'Unknown';
    const to = (header.match(/To: (.*)/) || [])[1] || 'Unknown';
    const subject = (header.match(/Subject: (.*)/) || [])[1] || 'Unknown';
    const date = (header.match(/Date: (.*)/) || [])[1] || 'Unknown';
    const spf = /spf=pass/.test(header) ? 'pass' : 'fail';
    const dkim = /dkim=pass/.test(header) ? 'pass' : 'fail';
    const dmarc = /dmarc=pass/.test(header) ? 'pass' : 'fail';

    const senderIP = extractSenderIP(header);
    let ipLocation = 'Unknown';
    try {
      const ipRes = await fetch(`http://ip-api.com/json/${senderIP}`);
      const ipData = await ipRes.json();
      ipLocation = ipData?.country || 'Unknown';
    } catch (e) {
      console.warn('⚠️ IP location fetch failed');
    }

    const safeMeter = getSafeMeter(spf, dkim, dmarc);

    const newHeader = new EmailHeader({
      from, to, subject, date, spf, dkim, dmarc, safeMeter, senderIP, ipLocation
    });

    await newHeader.save();

    res.json({ from, to, subject, date, spf, dkim, dmarc, safeMeter, senderIP, ipLocation });
  } catch (error) {
    console.error('❌ Analyze Error:', error);
    res.status(500).json({ error: 'Server error during analysis' });
  }
});

// Get History
app.get('/api/history', async (req, res) => {
  try {
    const history = await EmailHeader.find().sort({ createdAt: -1 });
    res.json(history);
  } catch (error) {
    console.error('❌ History Fetch Error:', error);
    res.status(500).json({ error: 'Failed to fetch history' });
  }
});

// Clear History
app.delete('/api/history', async (req, res) => {
  try {
    await EmailHeader.deleteMany({});
    res.json({ message: 'All history cleared.' });
  } catch (error) {
    console.error('❌ Clear Error:', error);
    res.status(500).json({ error: 'Failed to clear history.' });
  }
});
// ✅ Add this test route
app.get('/api/test', (req, res) => {
  res.send('Backend is working ✅');
});

// Start server
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
