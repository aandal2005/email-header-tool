// models/User.js
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: {
    type: String,
    required: true,
    unique: true // ✅ Only email should be unique
  },
  password: { type: String, required: true }
});

module.exports = mongoose.model('User', userSchema);
