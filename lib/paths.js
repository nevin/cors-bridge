'use strict';
const os = require('os');
const path = require('path');
const fs = require('fs');

// All app data (config, certificates, private keys) lives in one folder in your home directory.
const DATA_DIR = process.env.CORS_BRIDGE_HOME || path.join(os.homedir(), '.cors-bridge');
const CERT_DIR = path.join(DATA_DIR, 'certs');
const CONFIG_FILE = path.join(DATA_DIR, 'config.json');
const CERT_INDEX = path.join(CERT_DIR, 'index.json');

function ensureDirs() {
  fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
  fs.mkdirSync(CERT_DIR, { recursive: true, mode: 0o700 });
}

module.exports = { DATA_DIR, CERT_DIR, CONFIG_FILE, CERT_INDEX, ensureDirs };
