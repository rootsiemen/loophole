// Fixture: clean JavaScript — the scanner must report ZERO findings here.
const express = require('express');
const { execFile } = require('child_process');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const API_KEY = process.env.API_KEY;
const app = express();

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
