const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = 'your_secret_key'; // Use an environment variable for production

// Middleware
app.use(bodyParser.json());
//dummy
// Dummy user data (replace with a real database in production)
const users = [
  {
    id: 1,
    username: 'user1',
    password: '$2b$10$J8HvJuXv8T5uYZZx8c8yEuBhU69ZVjd/Z8jSkCim43Hz3EaF10F7y' // 'password1' hashed
  }
];

// Register route
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  // Check if user already exists
  const userExists = users.find(user => user.username === username);
  if (userExists) {
    return res.status(409).json({ message: 'User already exists' });
  }

  // Hash the password
  const hashedPassword = await bcrypt.hash(password, 10);

  // Save the user (in a real app, save to the database)
  const newUser = { id: users.length + 1, username, password: hashedPassword };
  users.push(newUser);

  res.status(201).json({ message: 'User registered successfully' });
});

// Login route
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // Find the user
  const user = users.find(user => user.username === username);
  if (!user) {
    return res.status(404).json({ message: 'User not found' });
  }

  // Check password
  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(401).json({ message: 'Invalid password' });
  }

  // Create a token
  const token = jwt.sign({ userId: user.id }, SECRET_KEY, { expiresIn: '1h' });

  res.status(200).json({ message: 'Login successful', token });
});

// Middleware to protect routes
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ message: 'Access denied' });
  }

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Protected route example
app.get('/dashboard', authenticateToken, (req, res) => {
  res.status(200).json({ message: `Welcome to the dashboard, user ${req.user.userId}` });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

