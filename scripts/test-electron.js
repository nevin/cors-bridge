'use strict';
// Runs the test suite with the Node inside Electron (it uses BoringSSL instead of OpenSSL), the way the
// desktop app runs the code.
const { spawnSync } = require('child_process');
const path = require('path');
const electron = require('electron');

const r = spawnSync(electron, [path.join(__dirname, '..', 'test', 'run.js')], {
  stdio: 'inherit',
  env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' },
});
process.exit(r.status === null ? 1 : r.status);
