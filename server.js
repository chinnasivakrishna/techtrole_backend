const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const dotenv = require('dotenv');
const axios = require('axios');

dotenv.config();

const app = express();
app.use(express.json());

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  phoneNumber: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isPhoneVerified: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Store OTPs temporarily (in production, use Redis or similar)
const otpStore = new Map();

// Function to send OTP using MSG91 API
async function sendOTP(phoneNumber, otp) {
  try {
    const url = `https://api.msg91.com/api/v5/flow/`;
    const headers = {
      'Content-Type': 'application/json',
      'authkey': process.env.MSG91_AUTH_KEY
    };
    
    const data = {
      template_id: process.env.MSG91_TEMPLATE_ID,
      sender: process.env.MSG91_SENDER_ID,
      short_url: "0",
      mobiles: phoneNumber,
      VAR1: otp  // This will replace {{otp}} in your MSG91 template
    };

    const response = await axios.post(url, data, { headers });
    return response.data;
  } catch (error) {
    console.error('MSG91 API Error:', error.response?.data || error.message);
    throw error;
  }
}

// Send OTP
app.post('/api/auth/send-otp', async (req, res) => {
  try {
    const { phoneNumber } = req.body;
    
    if (!phoneNumber) {
      return res.status(400).json({ message: 'Phone number is required' });
    }
    
    // Generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    
    // Store OTP with expiry
    otpStore.set(phoneNumber, {
      otp,
      expiry: Date.now() + 10 * 60 * 1000 // 10 minutes
    });

    // Send OTP using MSG91
    await sendOTP(phoneNumber, otp);
    res.json({ message: 'OTP sent successfully' });

  } catch (error) {
    console.error('Send OTP error:', error);
    res.status(500).json({ 
      message: 'Failed to send OTP',
      error: error.message 
    });
  }
});

// Verify OTP
app.post('/api/auth/verify-otp', (req, res) => {
  const { phoneNumber, otp } = req.body;
  
  if (!phoneNumber || !otp) {
    return res.status(400).json({ message: 'Phone number and OTP are required' });
  }
  
  const storedOTPData = otpStore.get(phoneNumber);
  
  if (!storedOTPData || Date.now() > storedOTPData.expiry) {
    return res.status(400).json({ message: 'OTP expired or invalid' });
  }
  
  if (storedOTPData.otp !== otp) {
    return res.status(400).json({ message: 'Invalid OTP' });
  }
  
  otpStore.delete(phoneNumber);
  res.json({ message: 'OTP verified successfully' });
});

// Register User
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, phoneNumber, password } = req.body;

    // Validate input
    if (!username || !phoneNumber || !password) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ 
      $or: [{ username }, { phoneNumber }] 
    });

    if (existingUser) {
      return res.status(400).json({ 
        message: 'Username or phone number already registered' 
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user
    const user = new User({
      username,
      phoneNumber,
      password: hashedPassword,
      isPhoneVerified: true
    });

    await user.save();
    res.status(201).json({ message: 'User registered successfully' });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});