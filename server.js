// server.js

import express from 'express';
// Commented out unused imports since login functionality is disabled
// import bcrypt from 'bcrypt';
// import jwt from 'jsonwebtoken';
// import mysql from 'mysql2/promise';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import https from 'https';
import fs from 'fs';

// Load environment variables
dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 9073;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const HOST = process.env.HOST || '0.0.0.0'; // 0.0.0.0 ensures the server binds to all network interfaces
const PUBLIC_URL = process.env.PUBLIC_URL || `http://localhost:${PORT}`;

// Database connection pool - COMMENTED OUT (not needed without login)
/*
const pool = mysql.createPool({
  host: '0.0.0.0',
  user: 'multycomm',
  password: 'Ayan@1012',
  database: 'dsouth',
  port: 3306,
  waitForConnections: true,
  connectionLimit: 10,
});
*/

// Middleware
app.use(express.json());
app.use(express.static('public'));

// Authentication middleware - COMMENTED OUT
/*
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};
*/

// Login endpoint - COMMENTED OUT
/*
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const connection = await pool.getConnection();
    try {
      const [rows] = await connection.query(
        'SELECT id, username, email, password FROM users WHERE username = ? OR email = ?',
        [username, username]
      );

      if (rows.length === 0) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const user = rows[0];
      const isValidPassword = await bcrypt.compare(password, user.password);

      if (!isValidPassword) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const token = jwt.sign(
        { id: user.id, username: user.username, email: user.email },
        JWT_SECRET,
        { expiresIn: '24h' }
      );

      res.json({
        success: true,
        token,
        user: { id: user.id, username: user.username, email: user.email }
      });

    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
*/

// Verify token endpoint - COMMENTED OUT
/*
app.get('/api/verify', authenticateToken, (req, res) => {
  res.json({ success: true, user: req.user });
});
*/

// Logout endpoint - COMMENTED OUT
/*
app.post('/api/logout', authenticateToken, (req, res) => {
  res.json({ success: true, message: 'Logged out successfully' });
});
*/

// Routes
app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Redirect root to dashboard directly (login commented out)
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Keep login route available if needed (commented out functionality)
/*
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});
*/

// SSL Certificate Management
const loadSSLCertificates = () => {
  try {
    const sslOptions = {
      key: fs.readFileSync('ssl/privkey.pem'),
      cert: fs.readFileSync('ssl/fullchain.pem')
    };
    
    console.log("🔒 SSL certificates loaded successfully");
    return sslOptions;
  } catch (error) {
    console.error("❌ Error loading SSL certificates:", error.message);
    
    // Check if SSL files exist
    const sslFiles = ['ssl/privkey.pem', 'ssl/fullchain.pem'];
    sslFiles.forEach(file => {
      if (!fs.existsSync(file)) {
        console.error(`❌ SSL file not found: ${file}`);
      }
    });
    
    console.log("⚠️  Falling back to HTTP server");
    return null;
  }
};

const sslOptions = loadSSLCertificates();

// Only use HTTPS if PUBLIC_URL starts with https://
const useHTTPS = PUBLIC_URL.startsWith('https://');

if (sslOptions && useHTTPS) {
  const server = https.createServer(sslOptions, app);
  server.listen(PORT, HOST, () => {
    console.log(`� HTTPS server running at ${PUBLIC_URL}`);
    console.log(`🌐 Server accessible on all network interfaces (${HOST}:${PORT})`);
  });
  
  server.on('error', (err) => {
    console.error('❌ HTTPS Server error:', err);
    if (err.code === 'EADDRINUSE') {
      console.error(`❌ Port ${PORT} is already in use. Try a different port.`);
    } else if (err.code === 'EACCES') {
      console.error(`❌ Permission denied. Port ${PORT} might require sudo privileges.`);
    }
    process.exit(1);
  });
} else {
  const server = app.listen(PORT, HOST, () => {
    console.log(`🌐 HTTP server running at ${PUBLIC_URL}`);
    if (!useHTTPS) {
      console.log(`⚠️  Running in HTTP mode (PUBLIC_URL is set to HTTP)`);
    } else {
      console.log(`⚠️  Running in HTTP mode (no SSL certificates found)`);
    }
  });
  
  server.on('error', (err) => {
    console.error('❌ HTTP Server error:', err);
    if (err.code === 'EADDRINUSE') {
      console.error(`❌ Port ${PORT} is already in use. Try a different port.`);
    } else if (err.code === 'EACCES') {
      console.error(`❌ Permission denied. Port ${PORT} might require sudo privileges.`);
    }
    process.exit(1);
  });
}