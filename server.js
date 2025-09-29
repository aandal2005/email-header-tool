require('dotenv').config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const fetch = require('node-fetch');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;

// ---------------- BODY PARSER ----------------
// Increase JSON body limit to handle large email headers
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ limit: "10mb", extended: true }));

// ---------------- CORS ----------------
const allowedOrigins = [
  "https://email-header-frontend.onrender.com",
  "http://localhost:3000"
];

app.use(cors({
  origin: function(origin, callback){
    if (!origin) return callback(null, true); // allow server-to-server or curl requests
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error(`CORS blocked for ${origin}`), false);
    }
  },
  credentials: true,
  methods: ["GET", "POST", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));
app.options("*", cors());

// ---------------- MONGODB ----------------
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("✅ MongoDB connected"))
  .catch(err => console.error("❌ MongoDB connection error:", err));

// ---------------- SCHEMAS ----------------
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  role: { type: String, default: "user" }
});

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
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model("User", userSchema);
const Header = mongoose.model("Header", headerSchema);

// ---------------- AUTH ----------------
function authenticateToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: "No token provided" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.user = user;
    next();
  });
}

// ---------------- HELPERS ----------------
function extractSenderIP(header) {
  const match = header.match(/\b\d{1,3}(\.\d{1,3}){3}\b/);
  return match ? match[0] : null;
}

// ---------------- ROUTES ----------------
app.get("/", (req, res) => res.send("✅ Email Header Analyzer API running"));

// ---- REGISTER ----
app.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: "All fields required" });

    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ error: "Email already exists" });

    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, password: hashed });

    const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '1d' });
    res.json({ message: "✅ Registered successfully", token, role: user.role });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Registration failed" });
  }
});

// ---- LOGIN ----
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "All fields required" });

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: "Invalid credentials" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: "Invalid credentials" });

    const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '1d' });
    res.json({ message: "✅ Login successful", token, role: user.role });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Login failed" });
  }
});

// ---- ANALYZE ----
app.post("/analyze", async (req, res) => {
  try {
    const { header } = req.body;
    if (!header) return res.status(400).json({ error: "No header provided" });

    const importantKeys = ["From", "To", "Subject", "Date"];
    const lines = header.split(/\r?\n/);
    const result = {};

    lines.forEach(line => {
      const [key, ...rest] = line.split(":");
      if (!key || rest.length === 0) return;
      const trimmedKey = key.trim();
      if (importantKeys.includes(trimmedKey)) {
        result[trimmedKey] = rest.join(":").trim();
      }
    });

    const spf = (header.match(/spf=(\w+)/i)?.[1] || "not found").toLowerCase();
    const dkim = (header.match(/dkim=(\w+)/i)?.[1] || "not found").toLowerCase();
    const dmarc = (header.match(/dmarc=(\w+)/i)?.[1] || "not found").toLowerCase();

    result["SPF Status"] = spf;
    result["DKIM Status"] = dkim;
    result["DMARC Status"] = dmarc;

    const passCount = [spf, dkim, dmarc].filter(v => v === "pass").length;
    result["Safe Meter"] = passCount === 3
      ? "✅ Safe – All checks passed"
      : passCount >= 2
      ? "⚠️ Risk – Partial checks passed"
      : "❌ Unsafe – Failed checks";

    let senderIP = extractSenderIP(header) || "Not found";
    let ipLocation = "Unknown";

    if (senderIP !== "Not found") {
      try {
        const response = await fetch(`https://ipwhois.app/json/${senderIP}`);
        if (!response.ok) throw new Error(`HTTP error ${response.status}`);
        const geoData = await response.json();
        ipLocation = geoData.success !== false
          ? geoData.city ? `${geoData.city}, ${geoData.country}` : `${geoData.country || "Unknown"}`
          : "Private or unknown IP";
      } catch (err) {
        console.error("IP lookup error:", err.message);
        try {
          const fallback = await fetch(`http://ip-api.com/json/${senderIP}`);
          const data = await fallback.json();
          ipLocation = data.status === "success"
            ? `${data.city || "Unknown"}, ${data.country || "Unknown"}`
            : "Lookup failed";
        } catch (fallbackErr) {
          console.error("Fallback IP lookup failed:", fallbackErr.message);
          ipLocation = "Lookup failed";
        }
      }
    }

    result["Sender IP"] = senderIP;
    result["IP Location"] = ipLocation;

    await Header.create({
      from: result["From"] || "Not found",
      to: result["To"] || "Not found",
      subject: result["Subject"] || "Not found",
      date: result["Date"] || "Not found",
      spf,
      dkim,
      dmarc,
      safeMeter: result["Safe Meter"],
      senderIP,
      ipLocation,
    });

    res.json(result);
  } catch (err) {
    console.error("Analyze error:", err);
    res.status(500).json({ error: "Analysis failed", details: err.message });
  }
});

// ---- HISTORY ----
app.get("/history", authenticateToken, async (req,res) => {
  try {
    const history = await Header.find().sort({_id:-1}).limit(50);
    res.json(history);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch history" });
  }
});

// ---- CLEAR HISTORY ----
app.delete("/history", authenticateToken, async (req,res) => {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Admins only" });
  try {
    await Header.deleteMany({});
    res.json({ message: "✅ History cleared" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to clear history" });
  }
});

// ---- PROXY (Optional for frontend CORS) ----
app.post("/proxy-analyze", async (req, res) => {
  try {
    const { header } = req.body;
    const token = req.headers.authorization;

    const response = await fetch('https://email-header-backend.onrender.com/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': token },
      body: JSON.stringify({ header })
    });

    const data = await response.json();
    res.json(data);
  } catch (err) {
    console.error("Proxy error:", err);
    res.status(500).json({ error: "Proxy failed" });
  }
});

// ---------------- START SERVER ----------------
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
