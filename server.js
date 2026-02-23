const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { initDB, findByUsername, validatePassword, loadUsers, createUser, deleteUser, setActive, getUserSettings, saveUserSettings, getUserData, saveUserData } = require('./users');
const { setSession, isValidSession, clearSession } = require('./sessions');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-in-railway-env';
const ADMIN_KEY = process.env.ADMIN_KEY || 'change-this-admin-key-in-railway-env';
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'Crumpet';

app.use(cors());
app.use(express.json({ limit: '10mb' }));

function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ success: false, message: 'Authentication required' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (!isValidSession(decoded.username, decoded.sessionId)) {
      return res.status(401).json({ success: false, message: 'Session expired — logged in elsewhere' });
    }
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ success: false, message: 'Invalid or expired token' });
  }
}

function requireAdminKey(req, res, next) {
  const key = req.headers['x-admin-key'];
  if (!key || key !== ADMIN_KEY) return res.status(403).json({ success: false, message: 'Forbidden' });
  next();
}

app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ success: false, message: 'Username and password required' });
  try {
    const user = await findByUsername(username);
    if (!user || !user.active) return res.status(401).json({ success: false, message: 'Invalid credentials' });
    if (!validatePassword(user, password)) return res.status(401).json({ success: false, message: 'Invalid credentials' });
    const sessionId = uuidv4();
    setSession(user.username, sessionId);
    const token = jwt.sign({ username: user.username, sessionId }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ success: true, token, username: user.username });
  } catch (e) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/verify', requireAuth, (req, res) => {
  res.json({ success: true, username: req.user.username, isAdmin: req.user.username === ADMIN_USERNAME });
});

app.post('/logout', requireAuth, (req, res) => {
  clearSession(req.user.username);
  res.json({ success: true });
});

app.get('/admin/users', requireAdminKey, async (req, res) => {
  try {
    const users = await loadUsers();
    res.json({ success: true, users: users.map(u => ({ username: u.username, active: u.active, createdAt: u.createdAt })) });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

app.post('/admin/users', requireAdminKey, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ success: false, message: 'Username and password required' });
  try {
    await createUser(username, password);
    res.json({ success: true });
  } catch (e) {
    res.status(400).json({ success: false, message: e.message });
  }
});

app.delete('/admin/users/:username', requireAdminKey, async (req, res) => {
  try {
    await deleteUser(req.params.username);
    res.json({ success: true });
  } catch (e) {
    res.status(404).json({ success: false, message: e.message });
  }
});

app.patch('/admin/users/:username', requireAdminKey, async (req, res) => {
  try {
    await setActive(req.params.username, req.body.active);
    res.json({ success: true });
  } catch (e) {
    res.status(404).json({ success: false, message: e.message });
  }
});

app.get('/settings', requireAuth, async (req, res) => {
  try {
    const settings = await getUserSettings(req.user.username);
    res.json({ success: true, settings: settings || {} });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

app.post('/settings', requireAuth, async (req, res) => {
  try {
    await saveUserSettings(req.user.username, req.body);
    res.json({ success: true });
  } catch (e) {
    res.status(400).json({ success: false, message: e.message });
  }
});

app.get('/data/:type', requireAuth, async (req, res) => {
  const { type } = req.params;
  const allowed = ['proxies', 'karma', 'imported'];
  if (!allowed.includes(type)) return res.status(400).json({ success: false, message: 'Invalid type' });
  try {
    const data = await getUserData(req.user.username, type);
    res.json({ success: true, data: data || [] });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

app.post('/data/:type', requireAuth, async (req, res) => {
  const { type } = req.params;
  const allowed = ['proxies', 'karma', 'imported'];
  if (!allowed.includes(type)) return res.status(400).json({ success: false, message: 'Invalid type' });
  try {
    await saveUserData(req.user.username, type, req.body);
    res.json({ success: true });
  } catch (e) {
    res.status(400).json({ success: false, message: e.message });
  }
});

const PORT = process.env.PORT || 3001;

initDB().then(() => {
  app.listen(PORT, () => console.log(`Auth server running on port ${PORT}`));
}).catch(err => {
  console.error('Failed to init database:', err.message);
  process.exit(1);
});
