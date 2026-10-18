'use strict';
const os = require('os');
const path = require('path');
const fs = require('fs');

// Name of the folder that turns on portable mode when it sits next to the app.
const PORTABLE_NAME = 'cors-bridge-data';

let isSea = false;
try {
  isSea = require('node:sea').isSea();
} catch {
  isSea = false;
}

// The folder the user sees the app in. Inside a macOS app the program is "CORS Bridge.app/Contents/MacOS/...",
// so that is the folder holding the .app.
function appFolder(execPath) {
  const dir = path.dirname(execPath);
  const m = /^(.*\.app)[/\\]Contents[/\\]MacOS$/.exec(dir);
  return m ? path.dirname(m[1]) : dir;
}

// The folder a portable "cors-bridge-data" folder is looked for in. The desktop app passes its own location in
// CORS_BRIDGE_APP_DIR (a Windows portable .exe runs from a temporary copy, so only the app knows where it really is).
function appBase({ env = process.env, execPath = process.execPath, sea = isSea, projectDir = path.join(__dirname, '..') } = {}) {
  if (env.CORS_BRIDGE_APP_DIR) return env.CORS_BRIDGE_APP_DIR;
  return sea ? appFolder(execPath) : projectDir;
}

// All app data (config, certificates, private keys) lives in one folder:
// 1. CORS_BRIDGE_HOME if set,
// 2. a "cors-bridge-data" folder next to the app (portable mode, for example on a USB stick),
// 3. otherwise ".cors-bridge" in your home folder.
function resolveDataDir({ env = process.env, execPath = process.execPath, sea = isSea, projectDir = path.join(__dirname, '..'), home = os.homedir() } = {}) {
  if (env.CORS_BRIDGE_HOME) return { dir: env.CORS_BRIDGE_HOME, portable: false };
  const portable = path.join(appBase({ env, execPath, sea, projectDir }), PORTABLE_NAME);
  try {
    if (fs.statSync(portable).isDirectory()) return { dir: portable, portable: true };
  } catch {
    /* no portable folder */
  }
  return { dir: path.join(home, '.cors-bridge'), portable: false };
}

const resolved = resolveDataDir();
const DATA_DIR = resolved.dir;
const PORTABLE = resolved.portable;
const CERT_DIR = path.join(DATA_DIR, 'certs');
const CONFIG_FILE = path.join(DATA_DIR, 'config.json');
const CERT_INDEX = path.join(CERT_DIR, 'index.json');
const INSTANCE_FILE = path.join(DATA_DIR, 'instance.json');
const LOG_FILE = path.join(DATA_DIR, 'cors-bridge.log');

// macOS runs a downloaded app that was never moved from a random read-only copy ("App Translocation"),
// where the portable folder next to it cannot be seen.
const TRANSLOCATED = /\/AppTranslocation\//.test(process.execPath);
const APP_FOLDER = appBase();

function ensureDirs() {
  fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
  fs.mkdirSync(CERT_DIR, { recursive: true, mode: 0o700 });
}

module.exports = {
  DATA_DIR,
  PORTABLE,
  PORTABLE_NAME,
  TRANSLOCATED,
  CERT_DIR,
  CONFIG_FILE,
  CERT_INDEX,
  INSTANCE_FILE,
  LOG_FILE,
  isSea,
  APP_FOLDER,
  appFolder,
  appBase,
  resolveDataDir,
  ensureDirs,
};
