const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const fetch = require('node-fetch');
const EmailHeader = require('./models/EmailHeader');

dotenv.config();

const app = express();
app.use(cors({
  origin: 'https://email-header-frontend.onrender.com'
}));
app.use(express.json());

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// Extract sender IP from header (simple match)
function extractSenderIP(header) {
  const match = header.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/);
  return match ? match[0] : 'Unknown';
}

// Rate email based on authentication
function getSafeMeter(spf, dkim, dmarc) {
  const passed = [spf, dkim, dmarc].filter(r => r === 'pass').length;
  if (passed === 3) return 'Safe';
  if (passed === 2) return 'Moderate';
  return 'Unsafe';
}

// Analyze Header
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
      ipLocation = ipData.country || 'Unknown';
    } catch (e) {
      console.warn('⚠️ IP location fetch failed');
    }

    const safeMeter = getSafeMeter(spf, dkim, dmarc);

    const newHeader = new EmailHeader({
      from, to, subject, date, spf, dkim, dmarc,
      safeMeter, senderIP, ipLocation
    });

    await newHeader.save();

    res.json({ from, to, subject, date, spf, dkim, dmarc, safeMeter, senderIP, ipLocation });
  } catch (error) {
    console.error('❌ Analyze Error:', error);
    res.status(500).json({ error: 'Server error during analysis' });
  }
});

// View all history
app.get('/api/history', async (req, res) => {
  try {
    const history = await EmailHeader.find().sort({ createdAt: -1 });
    res.json(history);
  } catch (error) {
    console.error('❌ History Fetch Error:', error);
    res.status(500).json({ error: 'Failed to fetch history' });
  }
});

// ✅ Clear all history
app.delete('/api/history', async (req, res) => {
  try {
    await EmailHeader.deleteMany({});
    res.json({ message: 'All history cleared.' });
  } catch (error) {
    console.error('❌ Clear Error:', error);
    res.status(500).json({ error: 'Failed to clear history.' });
  }
});

// Start server
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
