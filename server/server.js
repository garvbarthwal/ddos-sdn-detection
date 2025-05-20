const express = require('express');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const path = require('path');
const axios = require('axios');

// Create Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Create a write stream for logging
const accessLogStream = fs.createWriteStream(
  path.join(__dirname, 'access.log'),
  { flags: 'a' }
);

// Set up middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(morgan('combined', { stream: accessLogStream }));

// Basic rate limiting as a defense mechanism
const limiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 100, // Limit each IP to 100 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many requests from this IP, please try again after a minute'
});

// Apply rate limiter to all requests
app.use(limiter);

// Routes
app.get('/', (req, res) => {
  res.send('Welcome to the DDoS test server! This server is intentionally vulnerable for educational purposes.');
});

app.get('/info', (req, res) => {
  // Simulate CPU-intensive operation
  let result = 0;
  for (let i = 0; i < 1000000; i++) {
    result += Math.random();
  }
  res.json({ 
    server: 'DDoS Test Server', 
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    load: result / 1000000
  });
});

app.post('/process', (req, res) => {
  // Simulate processing delay
  setTimeout(() => {
    res.json({ 
      status: 'success',
      message: 'Data processed successfully',
      data: req.body
    });
  }, 500); // 500ms delay
});

// Endpoint that demonstrates making external requests (can be abused for amplification attacks)
app.get('/fetch', async (req, res) => {
  const url = req.query.url || 'https://jsonplaceholder.typicode.com/todos/1';
  
  try {
    const response = await axios.get(url);
    res.json(response.data);
  } catch (error) {
    res.status(500).json({ 
      error: 'Failed to fetch external resource',
      message: error.message
    });
  }
});

// Add a resource-intensive endpoint
app.get('/heavy', (req, res) => {
  // Generate a large response
  const size = parseInt(req.query.size) || 1024; // Size in KB, default 1MB
  const data = Buffer.alloc(size * 1024).fill('A').toString();
  
  res.send(data);
});

// Add a vulnerable search endpoint
app.get('/search', (req, res) => {
  const query = req.query.q || '';
  // Simulate database search with delay proportional to query length
  // (demonstrates how certain queries can cause more server load)
  setTimeout(() => {
    res.json({
      query: query,
      results: [`Found ${query.length} results for "${query}"`]
    });
  }, Math.min(query.length * 10, 2000)); // Delay based on query length, max 2 seconds
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Access logs will be written to: ${path.join(__dirname, 'access.log')}`);
  console.log('WARNING: This server is designed for DDoS testing and is intentionally vulnerable!');
  console.log('DO NOT deploy in a production environment.');
});