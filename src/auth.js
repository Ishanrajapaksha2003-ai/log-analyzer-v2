// Optional password protection (HTTP Basic). Enabled only when DASHBOARD_PASSWORD is set,
// so local development stays frictionless and a public deployment is locked.
const crypto = require('crypto');

const digest = s => crypto.createHash('sha256').update(String(s)).digest();
const safeEqual = (a, b) => crypto.timingSafeEqual(digest(a), digest(b));

function check(header, user, pass) {
  if (!header || !header.startsWith('Basic ')) return false;
  const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
  const i = decoded.indexOf(':');
  if (i < 0) return false;
  // evaluate both so timing does not reveal which part was wrong
  const okUser = safeEqual(decoded.slice(0, i), user);
  const okPass = safeEqual(decoded.slice(i + 1), pass);
  return okUser && okPass;
}

function httpGuard(user, pass) {
  return (req, res, next) => {
    if (check(req.headers.authorization, user, pass)) return next();
    res.set('WWW-Authenticate', 'Basic realm="Log Analyzer", charset="UTF-8"');
    res.status(401).send('Authentication required');
  };
}

function socketGuard(user, pass) {
  return (socket, next) =>
    check(socket.handshake.headers.authorization, user, pass) ? next() : next(new Error('unauthorized'));
}

module.exports = { check, httpGuard, socketGuard };
