const mongoose = require('mongoose');

const emailHeaderSchema = new mongoose.Schema({
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

module.exports = mongoose.model('EmailHeader', emailHeaderSchema);
