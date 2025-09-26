// server.js
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const dns = require("dns").promises;
const fetch = require("node-fetch");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = "YourJWTSecretKey123!"; // Hardcoded for simplicity

// ---------------- MIDDLEWARE ----------------
app.use(express.json());

// CORS: allow your frontend
app.use(cors({
  origin: ['https://email-header-frontend.onrender.com'], 
  methods: ['GET','POST','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization']
}));

app.options('*', cors()); // preflight

// ---------------- DATABASE ----------------
const MONGO_URI = "mongodb+srv://aandal:aandal2005@emailheadercluster.e2ir8k8.mongodb.net/?retryWrites=true&w=majority&appName=EmailHeaderCluster";

mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("✅ MongoDB connected successfully"))
  .catch(err => console.error("❌ MongoDB connection error:", err));

// ---------------- SCHEMAS ----------------
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  role: { type: String, default: "user" } // user or admin
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
  // Scan Received: headers from bottom to top
  const receivedLines = header.split("\n").filter(l => l.toLowerCase().startsWith("received:"));
  for (let i = receivedLines.length - 1; i >= 0; i--) {
    const match = receivedLines[i].match(/\[([0-9.]+)\]/);
    if (match) return match[1];
  }
  return null;
}

async function getDmarcRecord(domain) {
  try {
    const records = await dns.resolveTxt(`_dmarc.${domain}`);
    return records.flat().join(" ");
  } catch {
    return null;
  }
}

function parseDmarcPolicy(record) {
  if (!record) return "not found";
  const match = record.match(/p=([a-zA-Z]+)/);
  return match ? match[1].toLowerCase() : "none";
}

// ---------------- AUTH MIDDLEWARE ----------------
function authenticateToken(req, res, next) {
  const token = req.headers['authorization'];
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
app.post("/analyze", async (req, res) => {
  try {
    const { header } = req.body;
    if (!header) return res.status(400).json({ error: "No header provided" });

    // ---------------- Extract basic headers ----------------
    const importantKeys = ["From", "To", "Subject", "Date"];
    const lines = header.split("\n");
    const result = {};

    lines.forEach(line => {
      const [key, ...rest] = line.split(":");
      if (!key || rest.length === 0) return;
      const trimmedKey = key.trim();
      if (importantKeys.includes(trimmedKey)) {
        result[trimmedKey] = rest.join(":").trim();
      }
    });

    // ---------------- SPF / DKIM ----------------
    const spf = (header.match(/spf=(\w+)/i)?.[1] || "not found").toLowerCase();
    const dkim = (header.match(/dkim=(\w+)/i)?.[1] || "not found").toLowerCase();
    result["SPF Status"] = spf;
    result["DKIM Status"] = dkim;

    // ---------------- Sender IP ----------------
    const receivedLines = header.split("\n").filter(l => l.toLowerCase().startsWith("received:"));
    let senderIP = "Not found";
    for (let i = receivedLines.length - 1; i >= 0; i--) {
      const match = receivedLines[i].match(/\[([0-9.]+)\]/);
      if (match) {
        senderIP = match[1];
        break;
      }
    }
    result["Sender IP"] = senderIP;

    // ---------------- IP Geolocation ----------------
    let ipLocation = "Unknown";
    let isp = "Unknown";
    if (senderIP !== "Not found") {
      try {
        const geoRes = await fetch(`http://ip-api.com/json/${senderIP}`);
        const geoData = await geoRes.json();
        if (geoData.status === "success") {
          ipLocation = `${geoData.city}, ${geoData.regionName}, ${geoData.country}`;
          isp = geoData.isp;
        }
      } catch {
        ipLocation = "Lookup failed";
      }
    }
    result["IP Location"] = ipLocation;
    result["ISP"] = isp;

    // ---------------- DMARC Lookup ----------------
    let dmarc = "not found";
    try {
      const fromDomain = result["From"]?.split("@")[1];
      if (fromDomain) {
        const records = await dns.resolveTxt(`_dmarc.${fromDomain}`);
        const recordText = records.flat().join(" ");
        const match = recordText.match(/p=([a-zA-Z]+)/);
        dmarc = match ? match[1].toLowerCase() : "none";
      }
    } catch {
      dmarc = "not found";
    }
    result["DMARC Status"] = dmarc;

    // ---------------- Safe Meter ----------------
    const statuses = [spf, dkim, dmarc];
    const passCount = statuses.filter(v => v === "pass").length;
    result["Safe Meter"] =
      passCount === 3
        ? "✅ Safe – All checks passed"
        : passCount >= 2
        ? "⚠️ Risk – Partial checks passed"
        : "❌ Unsafe – Failed checks";

    // ---------------- Save to MongoDB ----------------
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

    // ---------------- Send Response ----------------
    res.json(result);

  } catch (err) {
    console.error("Analyze route error:", err);
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
