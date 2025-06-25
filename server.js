const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const app = express();
const PORT = process.env.PORT || 10000;

app.use(cors({ origin: 'https://email-header-frontend.onrender.com' }));
app.use(express.json());
app.use(express.static('public'));

function extractSenderIP(header) {
  const ipRegex = /Received:.*\[(\d{1,3}(?:\.\d{1,3}){3})\]/g;
  let match;
  while ((match = ipRegex.exec(header)) !== null) {
    const ip = match[1];
    if (!ip.startsWith('10.') && !ip.startsWith('192.168.') && !ip.startsWith('172.')) {
      return ip;
    }
  }
  return null;
}

app.post('/analyze', async (req, res) => {
  const header = req.body.header;

  if (!header) {
    return res.status(400).json({ error: 'No header provided' });
  }

  const importantKeys = [
    'Delivered-To',
    'Received-SPF',
    'Authentication-Results',
    'Return-Path',
    'DKIM-Signature',
    'ARC-Authentication-Results',
    'ARC-Message-Signature',
    'ARC-Seal'
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

  // Status checks
  const spfStatus = (header.match(/spf=(\w+)/i)?.[1] || 'not found').toLowerCase();
  const dkimStatus = (header.match(/dkim=(\w+)/i)?.[1] || 'not found').toLowerCase();
  const dmarcStatus = (header.match(/dmarc=(\w+)/i)?.[1] || 'not found').toLowerCase();

  result['SPF Status'] = spfStatus;
  result['DKIM Status'] = dkimStatus;
  result['DMARC Status'] = dmarcStatus;

  // Safe Meter
  if (spfStatus === 'pass' && dkimStatus === 'pass' && dmarcStatus === 'pass') {
    result['Safe Meter'] = '✅ Safe – All security checks passed';
  } else if ([spfStatus, dkimStatus, dmarcStatus].filter(v => v === 'pass').length >= 2) {
    result['Safe Meter'] = '⚠️ Risk – Partial pass, may be legit';
  } else {
    result['Safe Meter'] = '❌ Unsafe – Likely spoofed or spam';
  }

  // Extract sender IP
  const senderIP = extractSenderIP(header);
  result['Sender IP'] = senderIP || 'Not found';

  // IP location lookup
  if (senderIP) {
    try {
      const geoRes = await fetch(`https://ipapi.co/${senderIP}/json/`);
      const geoData = await geoRes.json();

      result['Sender Location'] = geoData.city
        ? `${geoData.city}, ${geoData.region}, ${geoData.country_name}`
        : 'Location not found';
    } catch (err) {
      result['Sender Location'] = 'Error fetching location';
    }
  }

  res.json(result);
});

app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
});
