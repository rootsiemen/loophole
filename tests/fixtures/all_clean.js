// Fixture: comprehensively clean JS — ZERO findings expected.
import crypto from 'node:crypto';

const API_KEY = process.env.API_KEY;
const DB_URL = process.env.DATABASE_URL;

async function getUser(id) {
  const rows = await db.query('SELECT id, name FROM users WHERE id = ?', [id]);
  return rows[0] || null;
}

function renderUser(name) {
  const el = document.createElement('span');
  el.textContent = name;
  document.body.appendChild(el);
}

function newId() {
  return crypto.randomUUID();
}

function hashForCache(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

async function fetchStatus() {
  const res = await fetch('https://status.example.com/health');
  return res.ok;
}

export { getUser, renderUser, newId, hashForCache, fetchStatus };
