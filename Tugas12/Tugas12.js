const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

// MongoDB connection setup
mongoose.connect('mongodb://localhost:27017/transactionDB', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// MongoDB Schema for User
const userSchema = new mongoose.Schema({
  email: String,
  username: String,
  password: String,
});

const User = mongoose.model('User', userSchema);

// Register endpoint
app.post('/register', async (req, res) => {
  try {
    const { email, username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({ email, username, password: hashedPassword });
    await user.save();

    const token = jwt.sign({ userId: user._id }, 'secret_key');
    res.status(201).json({ token });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  try {
    const { email, username, password } = req.body;
    const user = await User.findOne({ $or: [{ email }, { username }] });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ message: 'Invalid password' });
    }

    const token = jwt.sign({ userId: user._id }, 'secret_key');
    res.json({ token });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Middleware to authenticate token
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ message: 'Token not provided' });

  jwt.verify(token, 'secret_key', (err, decoded) => {
    if (err) return res.status(403).json({ message: 'Failed to authenticate token' });
    req.userId = decoded.userId;
    next();
  });
};

// Define Transaction schema and routes (POST, GET, PUT, DELETE)

// ...

// Start the server
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
