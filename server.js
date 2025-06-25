// server.js
const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');

const app = express();
const PORT = process.env.PORT || 10000;

app.use(cors({
  origin: 'https://email-header-frontend.onrender.com'
}));
app.use(express.json());

// Helper to extract sender IP from Received headers
function extractSenderIP(header) {
  const match = header.match(/Received: from .*\[(\d+\.\d+\.\d+\.\d+)\]/);
  return match ? match[1] : null;
}

app.post('/analyze', async (req, res) => {
  const header = req.body.header;

  if (!header) {
    return res.status(400).json({ error: 'No header provided' });
  }

  const importantKeys = [
    'From',
    'To',
    'Delivered-To',
    'Return-Path',
    'Received-SPF',
    'Subject',
    'Date'
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

  // Extract pass/fail statuses
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

  // IP Geolocation
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

  res.json(result);
});

app.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`);
});
