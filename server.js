const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const app = express();

// Use CORS
app.use(cors({
  origin: 'https://email-header-frontend.onrender.com'
}));

// Use middleware
app.use(express.json());

// Connect to MongoDB Atlas
mongoose.connect('mongodb+srv://aandal:aandal2005@emailheadercluster.e2ir8k8.mongodb.net/emailAnalyzer?retryWrites=true&w=majority&appName=EmailHeaderCluster', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('✅ Connected to MongoDB'))
.catch(err => console.error('❌ MongoDB connection error:', err));

// Define Mongoose schema
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
}, { timestamps: true });

const Header = mongoose.model('Header', HeaderSchema);

// Analyze endpoint
app.post('/api/analyze', async (req, res) => {
  try {
    const headerText = req.body.header;

    // ✳️ Simulated analysis logic (you can enhance this later)
    const result = {
      from: "example@mail.com",
      to: "you@example.com",
      subject: "Test Email",
      date: new Date().toUTCString(),
      spf: "pass",
      dkim: "pass",
      dmarc: "pass",
      safeMeter: "90%",
      senderIP: "192.168.1.1",
      ipLocation: "India"
    };

    // Save to database
    const saved = await Header.create(result);

    res.json(result);
  } catch (error) {
    console.error('Analyze Error:', error);
    res.status(500).json({ error: "Failed to analyze header" });
  }
});

// History endpoint
app.get('/api/history', async (req, res) => {
  try {
    const history = await Header.find().sort({ createdAt: -1 }).limit(10);
    res.json(history);
  } catch (error) {
    console.error('History Error:', error);
    res.status(500).json({ error: "Failed to fetch history" });
  }
});

// Start server
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
