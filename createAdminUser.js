const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const User = require('./models/User');

// Replace <db_password> with your actual database password
const uri = 'mongodb+srv://aandal:aandal2005@emailheadercluster.e2ir8k8.mongodb.net/emailAnalyzer?retryWrites=true&w=majority';

mongoose.connect(uri)
  .then(() => console.log('MongoDB Atlas connected'))
  .catch(err => console.error('MongoDB connection error:', err));

async function createAdmin() {
  try {
    const hashedPassword = await bcrypt.hash('Admin@123', 10); // Set a strong password
    const adminExists = await User.findOne({ username: 'admin' });
    if (!adminExists) {
      const admin = new User({
        username: 'admin',
        password: hashedPassword,
        role: 'admin'
      });
      await admin.save();
      console.log('Admin created successfully');
    } else {
      console.log('Admin already exists');
    }
  } catch (err) {
    console.error('Error creating admin:', err);
  } finally {
    mongoose.disconnect();
  }
}

createAdmin();
