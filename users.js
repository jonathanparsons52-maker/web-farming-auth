const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');

const USERS_FILE = path.join(__dirname, 'users.json');

function loadUsers() {
  if (!fs.existsSync(USERS_FILE)) {
    fs.writeFileSync(USERS_FILE, JSON.stringify([], null, 2));
  }
  return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
}

function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

function findByUsername(username) {
  return loadUsers().find(u => u.username === username);
}

function createUser(username, password) {
  const users = loadUsers();
  if (users.find(u => u.username === username)) throw new Error('User already exists');
  const hash = bcrypt.hashSync(password, 12);
  const user = { username, password: hash, createdAt: new Date().toISOString(), active: true };
  users.push(user);
  saveUsers(users);
  return user;
}

function deleteUser(username) {
  const users = loadUsers();
  const filtered = users.filter(u => u.username !== username);
  if (filtered.length === users.length) throw new Error('User not found');
  saveUsers(filtered);
}

function setActive(username, active) {
  const users = loadUsers();
  const user = users.find(u => u.username === username);
  if (!user) throw new Error('User not found');
  user.active = active;
  saveUsers(users);
}

function validatePassword(user, password) {
  return bcrypt.compareSync(password, user.password);
}

module.exports = { findByUsername, createUser, deleteUser, setActive, validatePassword, loadUsers };
