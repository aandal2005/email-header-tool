const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 10000;

// ✅ Enable CORS for frontend (use your deployed frontend URL)
app.use(cors({
  origin: 'https://email-header-frontend.onrender.com'
}));

app.use(express.json());

// ✅ POST /analyze route
app.post('/analyze', (req, res) => {
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

  // ✅ Extract SPF, DKIM, DMARC results
  const spfMatch = header.match(/spf=([a-z]+)/i);
  const dkimMatch = header.match(/dkim=([a-z]+)/i);
  const dmarcMatch = header.match(/dmarc=([a-z]+)/i);

  const spfStatus = spfMatch ? spfMatch[1].toLowerCase() : 'not found';
  const dkimStatus = dkimMatch ? dkimMatch[1].toLowerCase() : 'not found';
  const dmarcStatus = dmarcMatch ? dmarcMatch[1].toLowerCase() : 'not found';

  result['SPF Status'] = spfStatus;
  result['DKIM Status'] = dkimStatus;
  result['DMARC Status'] = dmarcStatus;

  // ✅ Safe Meter Verdict
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

  res.json(result);
});

// ✅ Start server on correct port
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Server running on port ${PORT}`);
});
