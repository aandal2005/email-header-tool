const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const app = express();

// ✅ Allow frontend origin
app.use(cors({
  origin: 'https://email-header-frontend.onrender.com'
}));

app.use(express.json());

// ✅ Connect to MongoDB
mongoose.connect('mongodb+srv://aandal:aandal2005@emailheadercluster.e2ir8k8.mongodb.net/emailAnalyzer?retryWrites=true&w=majority&appName=EmailHeaderCluster')
  .then(() => console.log('✅ MongoDB connected'))
  .catch((err) => console.error('❌ MongoDB connection error:', err));

// ✅ Define a Mongoose schema
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
  ipLocation: String
}, { timestamps: true });

const Header = mongoose.model('Header', headerSchema);

// ✅ Email header parsing logic
const parseHeader = (rawHeader) => {
  const lines = rawHeader.split(/\r?\n/);
  const result = {};

  lines.forEach(line => {
    const lower = line.toLowerCase();
    if (lower.startsWith("from:")) {
      result.from = line.substring(5).trim();
    } else if (lower.startsWith("to:")) {
      result.to = line.substring(3).trim();
    } else if (lower.startsWith("subject:")) {
      result.subject = line.substring(8).trim();
    } else if (lower.startsWith("date:")) {
      result.date = line.substring(5).trim();
    } else if (lower.includes("spf=")) {
      result.spf = line.match(/spf=(\w+)/)?.[1] || "unknown";
    } else if (lower.includes("dkim=")) {
      result.dkim = line.match(/dkim=(\w+)/)?.[1] || "unknown";
    } else if (lower.includes("dmarc=")) {
      result.dmarc = line.match(/dmarc=(\w+)/)?.[1] || "unknown";
    }
  });

  // 🔒 Dummy fields for now — you can improve these
  result.safeMeter = "90%";
  result.senderIP = "192.168.1.1";
  result.ipLocation = "India";

  return result;
};

// ✅ Analyze API
app.post('/api/analyze', async (req, res) => {
  try {
    const { header } = req.body;
    if (!header) {
      return res.status(400).json({ error: 'No header provided' });
    }

    const parsed = parseHeader(header);
    const saved = await Header.create(parsed);
    res.json(saved);
  } catch (err) {
    console.error('❌ Analyze failed:', err);
    res.status(500).json({ error: 'Failed to analyze header.' });
  }
});

// ✅ History API
app.get('/api/history', async (req, res) => {
  try {
    const history = await Header.find().sort({ createdAt: -1 }).limit(10);
    res.json(history);
  } catch (err) {
    console.error('❌ Fetch history failed:', err);
    res.status(500).json({ error: 'Failed to fetch history.' });
  }
});

// ✅ Start the server
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
