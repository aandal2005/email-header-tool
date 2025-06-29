const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const fetch = require('node-fetch'); // for IP location

dotenv.config(); // ✅ Load .env variables

const app = express();

app.use(cors({
  origin: 'https://email-header-frontend.onrender.com' // ✅ Allow frontend
}));
app.use(express.json());

// ✅ Connect to MongoDB
// Connect to MongoDB (clean version)
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// ✅ Mongoose Schema
const HeaderSchema = new mongoose.Schema({
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
});

const Header = mongoose.model('Header', HeaderSchema);

// ✅ Extract IP from header
function extractSenderIP(header) {
  const match = header.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/);
  return match ? match[0] : 'Unknown';
}

// ✅ /api/analyze
app.post('/api/analyze', async (req, res) => {
  try {
    const { header } = req.body;
    if (!header) return res.status(400).json({ error: 'Missing email header' });

    // Dummy logic (replace with real analysis if needed)
    const from = header.match(/From:\s(.+)/i)?.[1] || 'Unknown';
    const to = header.match(/To:\s(.+)/i)?.[1] || 'Unknown';
    const subject = header.match(/Subject:\s(.+)/i)?.[1] || 'Unknown';
    const date = header.match(/Date:\s(.+)/i)?.[1] || 'Unknown';
    const spf = header.includes('spf=pass') ? 'pass' : 'fail';
    const dkim = header.includes('dkim=pass') ? 'pass' : 'fail';
    const dmarc = header.includes('dmarc=pass') ? 'pass' : 'fail';
    const safeMeter = (spf === 'pass' && dkim === 'pass' && dmarc === 'pass') ? 'Safe' : 'Unsafe';

    const senderIP = extractSenderIP(header);

    // Get location
    let ipLocation = 'Unknown';
    try {
      const ipRes = await fetch(`http://ip-api.com/json/${senderIP}`);
      const ipData = await ipRes.json();
      ipLocation = ipData?.country || 'Unknown';
    } catch (err) {
      console.warn('⚠️ Failed IP lookup:', err);
    }

    // Save to DB
    const saved = await Header.create({
      from, to, subject, date, spf, dkim, dmarc, safeMeter, senderIP, ipLocation
    });

    res.json(saved);
  } catch (error) {
    console.error('❌ Analyze Error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ✅ /api/history
app.get('/api/history', async (req, res) => {
  try {
    const data = await Header.find().sort({ _id: -1 }).limit(20);
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch history' });
  }
});

// ✅ Start server
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
