// server.js
require('dotenv').config();

const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const dns = require("dns").promises; // kept - you can use getDmarcRecord later if needed
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "YourJWTSecretKey123!";

// Use Node's global fetch (Node 18+) — avoids node-fetch version problems
const fetchFn = globalThis.fetch.bind(globalThis);

// Try loading geoip-lite (optional). If not installed, server will still work.
let geoip = null;
try {
  geoip = require("geoip-lite");
} catch (err) {
  // geoip not available — we will gracefully fallback to online APIs only
  geoip = null;
  console.warn("geoip-lite not installed — falling back to online IP lookup only.");
}

// ---------------- MIDDLEWARE ----------------
app.use(express.json());

// Allowed origins (update with any additional dev URLs you use)
const allowedOrigins = [
  "https://email-header-frontend.onrender.com",
  "http://localhost:3000",
  "http://127.0.0.1:5500"
];

app.use(cors({
  origin: function (origin, callback) {
    // allow requests with no origin (like curl or server-to-server)
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) !== -1) {
      return callback(null, true);
    } else {
      return callback(new Error('CORS policy: This origin is not allowed'), false);
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  optionsSuccessStatus: 200
}));

// Ensure OPTIONS preflight responds
app.options('*', cors());

// ---------------- DATABASE ----------------
const MONGO_URI = process.env.MONGO_URI || "mongodb+srv://aandal:aandal2005@emailheadercluster.e2ir8k8.mongodb.net/?retryWrites=true&w=majority&appName=EmailHeaderCluster";

mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("✅ MongoDB connected successfully"))
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
});

const User = mongoose.model("User", userSchema);
const Header = mongoose.model("Header", headerSchema);

// ---------------- HELPERS ----------------
function extractSenderIP(header) {
  // find Received: lines, scan bottom-to-top (earliest hop)
  const receivedLines = header.split(/\r?\n/).filter(l => l.toLowerCase().startsWith("received:"));
  for (let i = receivedLines.length - 1; i >= 0; i--) {
    const line = receivedLines[i];
    // prefer bracketed IP [1.2.3.4]
    let m = line.match(/\[([0-9]{1,3}(?:\.[0-9]{1,3}){3})\]/);
    if (m && m[1]) return m[1];
    // otherwise try any IPv4-looking substring
    m = line.match(/([0-9]{1,3}(?:\.[0-9]{1,3}){3})/);
    if (m && m[1]) return m[1];
  }
  return null;
}

// ---------------- AUTH MIDDLEWARE ----------------
function authenticateToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: "No token provided" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.user = user;
    next();
  });
}

// ---------------- ROUTES ----------------
app.get("/", (req, res) => res.send("✅ Email Header Analyzer API running"));

// --------- REGISTER ---------
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: "All fields required" });

  try {
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

// --------- LOGIN ---------
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "All fields required" });

  try {
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

// --------- ANALYZE HEADER ---------
app.post("/analyze", async (req, res) => {
  try {
    const { header } = req.body;
    if (!header) return res.status(400).json({ error: "No header provided" });

    const importantKeys = ["From", "To", "Subject", "Date"];
    const lines = header.split(/\r?\n/);
    const result = {};

    // Extract basic header fields
    lines.forEach(line => {
      const [key, ...rest] = line.split(":");
      if (!key || rest.length === 0) return;
      const trimmedKey = key.trim();
      if (importantKeys.includes(trimmedKey)) {
        result[trimmedKey] = rest.join(":").trim();
      }
    });

    // SPF, DKIM, DMARC extraction (simple)
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

    // ---------- Sender IP & Geo (IPinfo -> geoip-lite fallback) ----------
    let senderIP = extractSenderIP(header) || "Not found";
    let ipLocation = "Unknown";

    if (senderIP !== "Not found") {
      try {
        // Prefer IPinfo if token provided, otherwise try without token (limited)
        const ipinfoKey = process.env.IP_GEO_API_KEY;
        const ipinfoUrl = ipinfoKey
          ? `https://ipinfo.io/${senderIP}/json?token=${ipinfoKey}`
          : `https://ipinfo.io/${senderIP}/json`;

        const geoRes = await fetchFn(ipinfoUrl);
        if (geoRes && geoRes.ok) {
          const geoData = await geoRes.json();
          if (geoData && (geoData.city || geoData.region || geoData.country)) {
            ipLocation = `${geoData.city || 'Unknown'}, ${geoData.region || 'Unknown'}, ${geoData.country || 'Unknown'}`;
          } else {
            // fallback to geoip-lite
            if (geoip) {
              const g = geoip.lookup(senderIP);
              if (g) ipLocation = `${g.city || 'Unknown'}, ${g.region || 'Unknown'}, ${g.country || 'Unknown'}`;
              else ipLocation = "Lookup failed";
            } else {
              ipLocation = "Lookup failed";
            }
          }
        } else {
          // if IPinfo failed (non-OK), fallback to geoip-lite if available
          if (geoip) {
            const g = geoip.lookup(senderIP);
            if (g) ipLocation = `${g.city || 'Unknown'}, ${g.region || 'Unknown'}, ${g.country || 'Unknown'}`;
            else ipLocation = "Lookup failed";
          } else {
            ipLocation = "Lookup failed";
          }
        }
      } catch (err) {
        console.error("IP lookup error:", err);
        if (geoip) {
          const g = geoip.lookup(senderIP);
          if (g) ipLocation = `${g.city || 'Unknown'}, ${g.region || 'Unknown'}, ${g.country || 'Unknown'}`;
          else ipLocation = "Lookup failed";
        } else {
          ipLocation = "Lookup failed";
        }
      }
    }

    result["Sender IP"] = senderIP;
    result["IP Location"] = ipLocation;

    // Save result to DB
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

// --------- FETCH HISTORY ---------
app.get("/history", authenticateToken, async (req, res) => {
  try {
    const history = await Header.find().sort({ _id: -1 }).limit(50);
    res.json(history);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch history" });
  }
});

// --------- CLEAR HISTORY (Admin only) ---------
app.delete("/history", authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: "Admins only" });
  try {
    await Header.deleteMany({});
    res.json({ message: "✅ History cleared" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to clear history" });
  }
});

// ---------------- START SERVER ----------------
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
