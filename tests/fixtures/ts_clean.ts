// Fixture: clean TypeScript — the scanner must report ZERO findings here.
import express from 'express';
import * as fs from 'fs';
import * as path from 'path';

const app = express();
const BASE = '/data';
const ALLOWED_HOSTS = ['api.example.com'];

app.get('/search', (req, res) => {
  const q = req.query.q as string;
  db.query('SELECT * FROM items WHERE name LIKE ?', [`%${q}%`], (e, r) => {
    res.json(r);
  });
});

app.get('/fetch', (req, res) => {
  const target = req.query.url as string;
  const u = new URL(target);
  if (!ALLOWED_HOSTS.includes(u.hostname)) {
    res.status(400).send('bad host');
    return;
  }
  fetch('https://api.example.com/data').then(() => res.send('ok'));
});

app.get('/read', (req, res) => {
  const f = req.query.file as string;
  const p = path.resolve(BASE, f);
  if (!p.startsWith(BASE)) {
    res.status(400).send('bad path');
    return;
  }
  fs.readFile(p, 'utf8', (e, d) => res.send(d));
});
