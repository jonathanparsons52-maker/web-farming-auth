const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      username TEXT PRIMARY KEY,
      password TEXT NOT NULL,
      active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      settings JSONB DEFAULT '{}',
      proxies JSONB DEFAULT '[]',
      karma JSONB DEFAULT '[]',
      imported JSONB DEFAULT '[]'
    )
  `);
}

async function loadUsers() {
  const { rows } = await pool.query('SELECT * FROM users');
  return rows.map(r => ({
    username: r.username,
    password: r.password,
    active: r.active,
    createdAt: r.created_at,
    settings: r.settings || {},
    proxies: r.proxies || [],
    karma: r.karma || [],
    imported: r.imported || []
  }));
}

async function findByUsername(username) {
  const { rows } = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
  if (!rows[0]) return null;
  const r = rows[0];
  return { username: r.username, password: r.password, active: r.active, createdAt: r.created_at, settings: r.settings, proxies: r.proxies, karma: r.karma, imported: r.imported };
}

async function createUser(username, password) {
  const existing = await findByUsername(username);
  if (existing) throw new Error('User already exists');
  const hash = bcrypt.hashSync(password, 12);
  await pool.query('INSERT INTO users (username, password) VALUES ($1, $2)', [username, hash]);
}

async function deleteUser(username) {
  const { rowCount } = await pool.query('DELETE FROM users WHERE username = $1', [username]);
  if (rowCount === 0) throw new Error('User not found');
}

async function setActive(username, active) {
  const { rowCount } = await pool.query('UPDATE users SET active = $1 WHERE username = $2', [active, username]);
  if (rowCount === 0) throw new Error('User not found');
}

function validatePassword(user, password) {
  return bcrypt.compareSync(password, user.password);
}

async function getUserSettings(username) {
  const { rows } = await pool.query('SELECT settings FROM users WHERE username = $1', [username]);
  return rows[0]?.settings || {};
}

async function saveUserSettings(username, settings) {
  await pool.query('UPDATE users SET settings = $1 WHERE username = $2', [JSON.stringify(settings), username]);
}

async function getUserData(username, type) {
  const { rows } = await pool.query(`SELECT ${type} FROM users WHERE username = $1`, [username]);
  return rows[0]?.[type] || [];
}

async function saveUserData(username, type, data) {
  await pool.query(`UPDATE users SET ${type} = $1 WHERE username = $2`, [JSON.stringify(data), username]);
}

module.exports = { initDB, findByUsername, createUser, deleteUser, setActive, validatePassword, loadUsers, getUserSettings, saveUserSettings, getUserData, saveUserData };
