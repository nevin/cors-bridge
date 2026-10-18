'use strict';
// Only one CORS Bridge runs per data folder. Starting it again (double-clicking the app a second time) opens the
// dashboard of the copy that is already running instead of failing on busy ports.
const fs = require('fs');
const http = require('http');
const P = require('./paths');
const { atomicWrite } = require('./util');

function read(file = P.INSTANCE_FILE) {
  try {
    const info = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (Number.isInteger(info.pid) && Number.isInteger(info.port) && typeof info.token === 'string') return info;
  } catch {
    /* none, or unreadable */
  }
  return null;
}

// The file holds the dashboard token, so only this user may read it (like the private keys next to it).
function write(info, file = P.INSTANCE_FILE) {
  atomicWrite(file, JSON.stringify(info), 0o600);
}

function clear(pid = process.pid, file = P.INSTANCE_FILE) {
  const info = read(file);
  if (info && info.pid === pid) {
    try {
      fs.unlinkSync(file);
    } catch {
      /* already gone */
    }
  }
}

function alive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return e.code === 'EPERM';
  }
}

// Asks the dashboard for a session with the saved token. Only a running CORS Bridge with that token answers
// with its session cookie, so a different program that took over the port or the process id is not mistaken for it.
function answers(info, timeout = 1500) {
  return new Promise((resolve) => {
    const req = http.get(
      { host: '127.0.0.1', port: info.port, path: `/?token=${encodeURIComponent(info.token)}`, headers: { host: `127.0.0.1:${info.port}` }, timeout },
      (res) => {
        res.resume();
        resolve(res.statusCode === 302 && String(res.headers['set-cookie'] || '').includes('cb_token='));
      }
    );
    req.on('timeout', () => req.destroy());
    req.on('error', () => resolve(false));
  });
}

// Returns { pid, port, token } of the CORS Bridge already running with this data folder, or null.
async function findRunning(file = P.INSTANCE_FILE) {
  const info = read(file);
  if (!info || info.pid === process.pid || !alive(info.pid)) return null;
  return (await answers(info)) ? info : null;
}

const dashboardUrl = (info) => `http://127.0.0.1:${info.port}/?token=${info.token}`;

module.exports = { read, write, clear, findRunning, dashboardUrl };
