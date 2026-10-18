#!/usr/bin/env node
'use strict';
// The command-line program: runs CORS Bridge in a terminal and opens the dashboard in the browser.
// The desktop app (electron/main.js) runs the same code in its own window.
const P = require('./lib/paths');
const instance = require('./lib/instance');
const desktop = require('./lib/desktop');
const { startCorsBridge } = require('./lib/app');

const major = Number(process.versions.node.split('.')[0]);
if (major < 18) {
  console.error(`CORS Bridge needs Node.js 18 or newer (you have ${process.version}). Get it from https://nodejs.org`);
  process.exit(1);
}

// Started without a terminal (for example from a file manager) there is nowhere to print to, so messages go to a
// log file in the data folder.
const headless = desktop.headless();

async function main() {
  P.ensureDirs();
  if (headless) desktop.useLogFile(P.LOG_FILE);
  const args = process.argv.slice(2);
  const open = !args.includes('--no-open');

  // Started a second time: show the dashboard of the copy that is already running.
  const running = await instance.findRunning();
  if (running) {
    console.log(`  CORS Bridge is already running. Dashboard: ${instance.dashboardUrl(running)}`);
    if (open) desktop.openBrowser(instance.dashboardUrl(running));
    process.exit(0);
  }

  let bridge = null;
  let exiting = false;
  const quit = async (code = 0) => {
    if (exiting) return;
    exiting = true;
    if (bridge) await bridge.stop();
    process.exit(code);
  };
  process.on('SIGINT', () => quit(0));
  process.on('SIGTERM', () => quit(0));
  process.on('SIGHUP', () => quit(0)); // terminal window closed (also sent on Windows when the console closes)
  process.on('SIGBREAK', () => quit(0)); // Ctrl+Break on Windows
  const crashed = (e) => {
    console.error(e && e.stack ? e.stack : e);
    quit(1);
  };
  process.on('uncaughtException', crashed);
  process.on('unhandledRejection', crashed);

  bridge = await startCorsBridge({ onQuit: () => quit(0) });
  console.log('');
  console.log('  CORS Bridge is running.');
  console.log(`  Dashboard: ${bridge.url}`);
  if (P.PORTABLE) console.log(`  Portable mode: data is kept in ${P.DATA_DIR}`);
  if (!headless) console.log('  Leave this window open while you test. Press Ctrl+C or the Quit button in the dashboard to quit.');
  console.log('');
  if (open) desktop.openBrowser(bridge.url);
}

main().catch((e) => {
  console.error(e.message || e);
  if (headless) desktop.showError('CORS Bridge could not start', `${e.message || e}\n\nDetails are in ${P.LOG_FILE}`);
  process.exit(1);
});
