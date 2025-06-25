const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');

const app = express();
const PORT = process.env.PORT || 10000;

app.use(cors({
  origin: 'https://email-header-frontend.onrender.com'  // Replace with your frontend domain if needed
}));
app.use(express.json());
app.use(express.static('public'));

app.post('/analyze', async (req, res) => {
  const header = req.body.header;

  if (!header) {
    return res.status(400).json({ error: 'No header provided' });
  }

  const importantKeys = [
    'Delivered-To', 'Received-SPF', 'Authentication-Results',
    'Return-Path', 'DKIM-Signature', 'ARC-Authentication-Results',
    'ARC-Message-Signature', 'ARC-Seal'
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

  // ✅ Extract pass/fail status
  const spfMatch = header.match(/spf=(\w+)/i);
  const dkimMatch = header.match(/dkim=(\w+)/i);
  const dmarcMatch = header.match(/dmarc=(\w+)/i);

  const spfStatus = spfMatch ? spfMatch[1].toLowerCase() : 'not found';
  const dkimStatus = dkimMatch ? dkimMatch[1].toLowerCase() : 'not found';
  const dmarcStatus = dmarcMatch ? dmarcMatch[1].toLowerCase() : 'not found';

  result['SPF Status'] = spfStatus;
  result['DKIM Status'] = dkimStatus;
  result['DMARC Status'] = dmarcStatus;

  // ✅ Safe Meter
  if (spfStatus === 'pass' && dkimStatus === 'pass' && dmarcStatus === 'pass') {
    result['Safe Meter'] = '✅ Safe – All security checks passed';
  } else if (
    (spfStatus === 'pass' && dkimStatus === 'pass') ||
    (spfStatus === 'pass' && dmarcStatus === 'pass') ||
    (dkimStatus === 'pass' && dmarcStatus === 'pass')
  ) {
    result['Safe Meter'] = '⚠️ Risk – Partial pass, email might be legit';
  } else {
    result['Safe Meter'] = '❌ Unsafe – Failed checks, could be spoofed';
  }

  // ✅ Sender IP detection
  const receivedMatch = header.match(/Received:.*\[(\d{1,3}(?:\.\d{1,3}){3})\]/);
  if (receivedMatch && receivedMatch[1]) {
    const senderIP = receivedMatch[1];
    result['Sender IP'] = senderIP;

    try {
      const geoRes = await fetch(`http://ip-api.com/json/${senderIP}`);
      const geoData = await geoRes.json();

      if (geoData.status === 'success') {
        result['Sender Location'] = `${geoData.city}, ${geoData.regionName}, ${geoData.country}`;
        result['ISP'] = geoData.isp;
      } else {
        result['Sender Location'] = 'Unknown';
      }
    } catch (err) {
      result['Sender Location'] = 'Lookup failed';
    }
  } else {
    result['Sender IP'] = 'Not found';
  }

  res.json(result);
});

app.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`);
});
