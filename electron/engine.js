'use strict';
// Runs CORS Bridge itself (the dashboard server and the proxy) in its own process, started by electron/main.js with
// utilityProcess.fork. A crash or a slow operation here cannot freeze or close the window and the tray icon, and
// the app can start the engine again.
//
// Messages to the app:   ready { origin, token, running }, status { running }, quit, error { message },
//                        startup-error { message }
// Messages from the app: start-proxy, stop-proxy, stop (clean up, then end)
const P = require('../lib/paths');
const desktop = require('../lib/desktop');
const { startCorsBridge } = require('../lib/app');

const parent = process.parentPort;
const send = (msg) => parent.postMessage(msg);
let bridge = null;

async function main() {
  P.ensureDirs();
  if (process.env.CORS_BRIDGE_LOG_TO_FILE === '1') desktop.useLogFile(P.LOG_FILE);
  bridge = await startCorsBridge({ onQuit: () => send({ type: 'quit' }) });
  bridge.engine.on('status', (s) => send({ type: 'status', running: s.running }));
  if (P.PORTABLE) console.log(`  Portable mode: data is kept in ${P.DATA_DIR}`);
  send({ type: 'ready', origin: bridge.origin, token: bridge.token, running: bridge.engine.running });
}

parent.on('message', async (e) => {
  const msg = (e && e.data) || {};
  try {
    if (msg.type === 'start-proxy') await bridge.engine.start();
    else if (msg.type === 'stop-proxy') await bridge.engine.stop();
    else if (msg.type === 'stop') {
      if (bridge) await bridge.stop();
      process.exit(0);
    }
  } catch (err) {
    send({ type: 'error', message: err.message });
  }
});

// The app starts a fresh engine after a crash; this one only writes down why.
process.on('uncaughtException', (err) => {
  console.error(err && err.stack ? err.stack : err);
  process.exit(1);
});

main().catch((err) => {
  console.error(err && err.stack ? err.stack : err);
  send({ type: 'startup-error', message: err.message || String(err) });
  setTimeout(() => process.exit(1), 50); // let the message reach the app first
});
