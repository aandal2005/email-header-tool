const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const mongoose = require('mongoose');

const app = express();
const PORT = process.env.PORT || 10000;

// MongoDB connection
mongoose.connect('mongodb+srv://aandal:<your_password>@emailheadercluster.e2ir8k8.mongodb.net/emailAnalyzer?retryWrites=true&w=majority&appName=EmailHeaderCluster', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log('✅ MongoDB connected');
}).catch((err) => {
  console.error('❌ MongoDB connection error:', err);
});

// Header schema and model
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
  createdAt: {
    type: Date,
    default: Date.now
  }
});
const Header = mongoose.model('Header', headerSchema);

app.use(cors({
  origin: 'https://email-header-frontend.onrender.com'
}));
app.use(express.json());

// Extract sender IP
function extractSenderIP(header) {
  const match = header.match(/Received: from .*\[(\d+\.\d+\.\d+\.\d+)\]/);
  return match ? match[1] : null;
}

// Analyze route
app.post('/analyze', async (req, res) => {
  const header = req.body.header;
  if (!header) {
    return res.status(400).json({ error: 'No header provided' });
  }

  const importantKeys = [
    'From', 'To', 'Delivered-To', 'Return-Path',
    'Received-SPF', 'Subject', 'Date'
  ];

  const lines = header.split('\n');
  const result = {};
  lines.forEach(line => {
    const [key, ...rest] = line.split(':');
    const trimmedKey = key.trim();
    if (importantKeys.includes(trimmedKey) && rest.length > 0) {
      result[trimmedKey] = rest.join(':').trim();
    }
  });

  // Status extractions
  const spfMatch = header.match(/spf=(\w+)/i);
  const dkimMatch = header.match(/dkim=(\w+)/i);
  const dmarcMatch = header.match(/dmarc=(\w+)/i);

  const spfStatus = spfMatch ? spfMatch[1].toLowerCase() : 'not found';
  const dkimStatus = dkimMatch ? dkimMatch[1].toLowerCase() : 'not found';
  const dmarcStatus = dmarcMatch ? dmarcMatch[1].toLowerCase() : 'not found';

  result['SPF Status'] = spfStatus;
  result['DKIM Status'] = dkimStatus;
  result['DMARC Status'] = dmarcStatus;

  if (spfStatus === 'pass' && dkimStatus === 'pass' && dmarcStatus === 'pass') {
    result['Safe Meter'] = '✅ Safe – All checks passed';
  } else if (
    (spfStatus === 'pass' && dkimStatus === 'pass') ||
    (spfStatus === 'pass' && dmarcStatus === 'pass') ||
    (dkimStatus === 'pass' && dmarcStatus === 'pass')
  ) {
    result['Safe Meter'] = '⚠️ Risk – Partial checks passed';
  } else {
    result['Safe Meter'] = '❌ Unsafe – Failed checks';
  }

  // IP Location
  const senderIP = extractSenderIP(header);
  if (senderIP) {
    try {
      const geoResponse = await fetch(`http://ip-api.com/json/${senderIP}`);
      const geoData = await geoResponse.json();
      result['Sender IP'] = senderIP;
      result['IP Location'] = `${geoData.city}, ${geoData.regionName}, ${geoData.country}`;
    } catch (err) {
      result['Sender IP'] = senderIP;
      result['IP Location'] = '❌ Failed to lookup location';
    }
  } else {
    result['Sender IP'] = 'Not found';
    result['IP Location'] = 'N/A';
  }

  // ✅ Save to MongoDB
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
    console.error('❌ Failed to save to DB:', err);
  }

  res.json(result);
});

app.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`);
});
