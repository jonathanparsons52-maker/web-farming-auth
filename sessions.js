const activeSessions = new Map();

function setSession(username, sessionId) {
  activeSessions.set(username, sessionId);
}

function isValidSession(username, sessionId) {
  return activeSessions.get(username) === sessionId;
}

function clearSession(username) {
  activeSessions.delete(username);
}

module.exports = { setSession, isValidSession, clearSession };
