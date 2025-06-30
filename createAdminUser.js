const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const User = require('./models/User');

// Replace with your actual Mongo URI or use dotenv
mongoose.connect('mongodb+srv://aandal:aandal2005@emailheadercluster.e2ir8k8.mongodb.net/emailAnalyzer', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(async () => {
  const password = await bcrypt.hash("admin123", 10);
  await User.create({ username: "admin", password, role: "admin" });
  console.log("✅ Admin user created");
  mongoose.disconnect();
}).catch(err => {
  console.error("❌ Failed to connect or create user:", err);
});
