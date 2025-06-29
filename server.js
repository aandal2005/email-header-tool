const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const fetch = require('node-fetch'); // Ensure node-fetch is installed
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;

// MongoDB connection
mongoose.connect('your-mongodb-connection-string', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// Middleware
app.use(cors({
  origin: 'https://email-header-frontend.onrender.com'
}));
app.use(express.json());

// Mongoose Schema
const emailSchema = new mongoose.Schema({
  from: String,
  to: String,
  subject: String,
  date: String,
  spf: String,
  dkim: String,
  dmarc: String,
  safeMeter: String,
  senderIP: String,
  ipLocation: String
}, { timestamps: true });

const EmailHeader = mongoose.model('EmailHeader', emailSchema);

// ✅ Function to extract sender IP from raw header
function extractSenderIP(header) {
  const match = header.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/);
  return match ? match[0] : 'Unknown';
}

// ✅ Safe Meter logic (you can improve it)
function calculateSafeMeter(spf, dkim, dmarc) {
  let score = 0;
  if (spf === 'pass') score += 30;
  if (dkim === 'pass') score += 30;
  if (dmarc === 'pass') score += 40;
  return `${score}%`;
}

// POST /api/analyze
app.post('/api/analyze', async (req, res) => {
  try {
    const { header } = req.body;
    if (!header) return res.status(400).json({ error: 'Header required' });

    // Dummy parsing logic (replace with real parsing as needed)
    const from = header.includes('example@mail.com') ? 'example@mail.com' : '"Maiyyam.com" <support@noreply.edmingle.com>';
    const to = header.includes('aandalpriya94@gmail.com') ? 'aandalpriya94@gmail.com' : 'you@example.com';
    const subject = header.includes('Reminder') ? 'Reminder: Full-Stack (MERN) Development - Live Session starts in 1 hr' : 'Test Email';
    const date = new Date().toUTCString();

    const spf = header.includes('spf=pass') ? 'pass' : 'fail';
    const dkim = header.includes('dkim=pass') ? 'pass' : 'fail';
    const dmarc = header.includes('dmarc=pass') ? 'pass' : 'fail';

    const safeMeter = calculateSafeMeter(spf, dkim, dmarc);
    const senderIP = extractSenderIP(header);

    let ipLocation = 'Unknown';
    if (senderIP !== 'Unknown') {
      try {
        const ipRes = await fetch(`http://ip-api.com/json/${senderIP}`);
        const ipData = await ipRes.json();
        ipLocation = ipData?.country || 'Unknown';
      } catch (err) {
        console.warn('⚠️ IP location fetch failed:', err.message);
      }
    }

    const result = new EmailHeader({
      from, to, subject, date,
      spf, dkim, dmarc,
      safeMeter, senderIP, ipLocation
    });

    await result.save();

    res.json(result);
  } catch (err) {
    console.error('❌ Analyze error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/history
app.get('/api/history', async (req, res) => {
  try {
    const history = await EmailHeader.find().sort({ createdAt: -1 }).limit(10);
    res.json(history);
  } catch (err) {
    console.error('❌ History fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch history' });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
