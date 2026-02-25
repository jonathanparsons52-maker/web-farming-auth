const { Pool } = require('pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

async function initSessions() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS sessions (
      username TEXT NOT NULL,
      session_id TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      PRIMARY KEY (username, session_id)
    )
  `);
}

async function setSession(username, sessionId) {
  await pool.query(
    `INSERT INTO sessions (username, session_id) VALUES ($1, $2) ON CONFLICT (username, session_id) DO NOTHING`,
    [username, sessionId]
  );
}

async function isValidSession(username, sessionId) {
  const { rows } = await pool.query(
    'SELECT 1 FROM sessions WHERE username = $1 AND session_id = $2',
    [username, sessionId]
  );
  return rows.length > 0;
}

async function clearSession(username) {
  await pool.query('DELETE FROM sessions WHERE username = $1', [username]);
}

module.exports = { initSessions, setSession, isValidSession, clearSession };
