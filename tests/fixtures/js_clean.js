// Fixture: clean JavaScript — the scanner must report ZERO findings here.
const express = require('express');
const { execFile } = require('child_process');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const helmet = require('helmet');

const API_KEY = process.env.API_KEY;
const app = express();
app.use(helmet());

function requireAuth(req, res, next) {
  const token = jwt.verify(req.headers.authorization, process.env.JWT_SECRET, {
    algorithms: ['HS256'],
  });
  req.user = token;
  next();
}

app.get('/search', requireAuth, (req, res) => {
  const q = req.query.q;
  db.query('SELECT * FROM users WHERE name = ?', [q], (err, rows) => {
    res.json(rows);
  });
});

app.get('/admin/users', requireAuth, (req, res) => {
  res.json([]);
});

app.get('/profile', (req, res) => {
  const bio = req.body.bio;
  document.getElementById('bio').textContent = bio;
});

app.get('/run', requireAuth, (req, res) => {
  execFile('/usr/bin/convert', ['input.png', 'out.png'], (err, out) => {
    res.send('done');
  });
});

function makeSessionToken() {
  return crypto.randomUUID();
}

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', 'https://example.com');
  next();
});

app.get('/boom', (req, res) => {
  try {
    risky();
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal error' });
  }
});

const data = JSON.parse(req.body.payload);

// --- 2026 expansion: safe counterparts (must stay silent) ---
const defaults = { port: 8080, host: 'localhost' };
const mergedCfg = Object.assign({}, defaults, { port: 9090 }); // PROTO001-safe

app.get('/old-home', (req, res) => {
  res.redirect('/home'); // REDIR001-safe: fixed target
});

function findAlice() {
  return User.findOne({ user: 'alice', active: true }); // NOSQL001-safe
}

const DATE_RE = /^\d{4}-\d{2}-\d{2}$/; // REDOS001-safe

console.log('server started'); // LOG001-safe: no sensitive values
