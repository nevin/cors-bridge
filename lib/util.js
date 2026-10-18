'use strict';
const fs = require('fs');
const net = require('net');

class UserError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.name = 'UserError';
    this.status = status;
  }
}

function atomicWrite(file, data, mode = 0o600) {
  const tmp = `${file}.tmp-${process.pid}-${Date.now()}`;
  fs.writeFileSync(tmp, data, { mode });
  fs.renameSync(tmp, file);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const isIp = (s) => net.isIP(String(s)) !== 0;

function isLoopbackAddress(addr) {
  if (!addr) return false;
  return addr === '::1' || addr.startsWith('127.') || /^::ffff:127\./.test(addr);
}

module.exports = { UserError, atomicWrite, sleep, isIp, isLoopbackAddress };
