// server.js

const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const dns = require("dns").promises;
const fetch = require("node-fetch"); // npm install node-fetch
const bcrypt = require("bcrypt"); // npm install bcrypt
const jwt = require("jsonwebtoken"); // npm install jsonwebtoken

const app = express();
const PORT = 5000; // fixed port, change if needed
const JWT_SECRET = "your_jwt_secret_key"; // for demo; change in production

// ---------------- MIDDLEWARE ----------------
app.use(express.json());
app.use(cors()); // allow all origins, safe for testing

// ---------------- DATABASE ----------------
const MONGO_URI =
  "mongodb+srv://aandal:aandal2005@emailheadercluster.e2ir8k8.mongodb.net/?retryWrites=true&w=majority&appName=EmailHeaderCluster";

mongoose
  .connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("✅ MongoDB connected successfully"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

// ---------------- SCHEMAS ----------------
const headerSchema = new mongoose.Schema({
  userId: String,
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

const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String, // hashed
  role: { type: String, default: "user" }, // user/admin
});

const Header = mongoose.model("Header", headerSchema);
const User = mongoose.model("User", userSchema);

// ---------------- HELPERS ----------------
function extractSenderIP(header) {
  const ipRegex = /\[?(\d{1,3}(?:\.\d{1,3}){3})\]?/;
  const match = header.match(ipRegex);
  return match ? match[1] : null;
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
  const match = record.match(/p=([a-zA-Z]+)/);
  return match ? match[1].toLowerCase() : "none";
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Forbidden" });
    req.user = user;
    next();
  });
}

// ---------------- ROUTES ----------------

// Home
app.get("/", (req, res) => {
  res.send("✅ Email Header Analyzer API is running");
});

// Register
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ error: "All fields are required" });

  const existing = await User.findOne({ email });
  if (existing) return res.status(400).json({ error: "User already exists" });

  const hashed = await bcrypt.hash(password, 10);
  const user = await User.create({ name, email, password: hashed });
  const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, {
    expiresIn: "7d",
  });

  res.json({ message: "User registered", token });
});

// Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: "All fields are required" });

  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ error: "Invalid credentials" });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ error: "Invalid credentials" });

  const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, {
    expiresIn: "7d",
  });

  res.json({ message: "Login successful", token });
});

// Analyze Email Header
app.post("/analyze", authenticateToken, async (req, res) => {
  try {
    const { header } = req.body;
    if (!header) return res.status(400).json({ error: "No header provided" });

    const importantKeys = ["From", "To", "Subject", "Date"];
    const lines = header.split("\n");
    const result = {};

    // Extract basic info
    lines.forEach((line) => {
      const [key, ...rest] = line.split(":");
      if (!key || rest.length === 0) return;
      const trimmedKey = key.trim();
      if (importantKeys.includes(trimmedKey)) {
        result[trimmedKey] = rest.join(":").trim();
      }
    });

    // SPF / DKIM
    const spfRaw = (header.match(/spf=(\w+)/i) || [])[1];
    const dkimRaw = (header.match(/dkim=(\w+)/i) || [])[1];
    const spf = spfRaw ? spfRaw.toLowerCase() : "not found";
    const dkim = dkimRaw ? dkimRaw.toLowerCase() : "not found";

    // DMARC
    let dmarc = "not found";
    if (result["From"]) {
      try {
        const match = result["From"].match(/<(.+)>/);
        const fromEmail = match?.[1] || result["From"];
        const fromDomain = fromEmail.split("@")[1];
        if (fromDomain) {
          const dmarcRecord = await getDmarcRecord(fromDomain);
          if (dmarcRecord) dmarc = parseDmarcPolicy(dmarcRecord);
        }
      } catch {
        dmarc = "lookup failed";
      }
    }

    result["SPF Status"] = spf;
    result["DKIM Status"] = dkim;
    result["DMARC Status"] = dmarc;

    // Safe Meter
    const statuses = [spf, dkim, dmarc];
    const passCount = statuses.filter((v) => v === "pass").length;
    const unknownCount = statuses.filter((v) => v === "not found" || v === "none").length;

    if (passCount === 3) result["Safe Meter"] = "✅ Safe – All checks passed";
    else if (passCount >= 2 || (passCount >= 1 && unknownCount > 0)) result["Safe Meter"] = "⚠️ Risk – Partial checks passed";
    else result["Safe Meter"] = "❌ Unsafe – Failed checks";

    // Sender IP & geolocation
    let senderIP = extractSenderIP(header);
    result["Sender IP"] = senderIP || "Not found";

    try {
      if (senderIP) {
        const geo = await fetch(`http://ip-api.com/json/${senderIP}`);
        const loc = await geo.json();
        result["IP Location"] =
          loc.status === "success" ? `${loc.city}, ${loc.regionName}, ${loc.country}` : "❌ Lookup failed";
      } else {
        result["IP Location"] = "N/A";
      }
    } catch {
      result["IP Location"] = "❌ Lookup failed";
    }

    // Save to DB
    try {
      await Header.create({
        userId: req.user.id,
        from: result["From"],
        to: result["To"],
        subject: result["Subject"],
        date: result["Date"],
        spf: result["SPF Status"],
        dkim: result["DKIM Status"],
        dmarc: result["DMARC Status"],
        safeMeter: result["Safe Meter"],
        senderIP: result["Sender IP"],
        ipLocation: result["IP Location"],
      });
    } catch (dbErr) {
      console.error("DB Save Error:", dbErr.message);
    }

    res.json(result);
  } catch (err) {
    console.error("Analyze Error:", err.message);
    res.status(500).json({
      error: "Analysis failed",
    });
  }
});

// Get History
app.get("/history", authenticateToken, async (req, res) => {
  try {
    const headers = await Header.find({ userId: req.user.id }).sort({ _id: -1 });
    res.json(headers);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch history" });
  }
});

// ---------------- START SERVER ----------------
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
