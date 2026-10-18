#!/usr/bin/env node
'use strict';
const crypto = require('crypto');
const store = require('./lib/store');
const hosts = require('./lib/hosts');
const P = require('./lib/paths');
const instance = require('./lib/instance');
const desktop = require('./lib/desktop');
const { ProxyEngine } = require('./lib/proxy');
const { createApiServer } = require('./lib/api');

const major = Number(process.versions.node.split('.')[0]);
if (major < 18) {
  console.error(`CORS Bridge needs Node.js 18 or newer (you have ${process.version}). Get it from https://nodejs.org`);
  process.exit(1);
}

// Started from Finder or Explorer there is no window to print to, so messages go to a log file in the data folder.
const headless = desktop.headless();

async function main() {
  P.ensureDirs();
  if (headless) desktop.useLogFile(P.LOG_FILE);
  const args = process.argv.slice(2);
  const open = !args.includes('--no-open');

  // Started a second time (for example by double-clicking the app again): show the dashboard of the running copy.
  const running = await instance.findRunning();
  if (running) {
    console.log(`  CORS Bridge is already running. Dashboard: ${instance.dashboardUrl(running)}`);
    if (open) desktop.openBrowser(instance.dashboardUrl(running));
    process.exit(0);
  }

  const token = process.env.CORS_BRIDGE_TOKEN || crypto.randomBytes(24).toString('hex');
  const engine = new ProxyEngine({
    getRules: () => store.load().rules,
    getSettings: () => store.load().settings,
  });
  // Letting other devices in is meant for one testing session, so it never survives a restart.
  const startCfg = store.load();
  if (startCfg.settings.allowLan) {
    startCfg.settings.allowLan = false;
    store.save(startCfg);
    console.log('  Note: "Let other devices on my network use the proxy" was turned off. Turn it on again in Settings if you still need it.');
  }
  let port = Number(process.env.CORS_BRIDGE_UI_PORT) || store.load().settings.uiPort;

  // A redirect left behind points the API host names at this computer while nothing answers there (or while
  // another program does), so remove it however CORS Bridge ends: the Quit button, Ctrl+C, closing the window,
  // or a crash.
  let closing = false;
  const shutdown = async (code = 0) => {
    if (closing) return;
    closing = true;
    console.log('\n  Shutting down...');
    try {
      await engine.stop();
      if (store.load().settings.cleanupHostsOnExit && hosts.status().entries.length) {
        await hosts.remove();
        console.log('  Removed the hosts-file redirect.');
      }
    } catch (e) {
      console.error(`  Could not remove the hosts-file redirect: ${e.message}`);
    }
    instance.clear();
    process.exit(code);
  };
  process.on('SIGINT', () => shutdown(0));
  process.on('SIGTERM', () => shutdown(0));
  process.on('SIGHUP', () => shutdown(0)); // terminal window closed (also sent on Windows when the console closes)
  process.on('SIGBREAK', () => shutdown(0)); // Ctrl+Break on Windows
  const crashed = (e) => {
    console.error(e && e.stack ? e.stack : e);
    shutdown(1);
  };
  process.on('uncaughtException', crashed);
  process.on('unhandledRejection', crashed);

  const server = createApiServer({ engine, token, getPort: () => port, onQuit: () => shutdown(0) });
  await new Promise((resolve, reject) => {
    let tries = 0;
    const attempt = () => {
      server.once('error', (e) => {
        if (e.code === 'EADDRINUSE' && tries++ < 10) {
          port += 1;
          attempt();
        } else reject(e);
      });
      server.listen(port, '127.0.0.1', resolve);
    };
    attempt();
  });
  instance.write({ pid: process.pid, port, token, startedAt: new Date().toISOString() });

  const url = `http://127.0.0.1:${port}/?token=${token}`;
  console.log('');
  console.log('  CORS Bridge is running.');
  console.log(`  Dashboard: ${url}`);
  if (P.PORTABLE) console.log(`  Portable mode: data is kept in ${P.DATA_DIR}`);
  if (!headless) console.log('  Leave this window open while you test. Press Ctrl+C or the Quit button in the dashboard to quit.');
  console.log('');
  if (open) desktop.openBrowser(url);

  const cfg = store.load();
  if (cfg.settings.autoStartProxy && cfg.rules.some((r) => r.enabled)) {
    engine.start().then(
      () => console.log('  Proxy started automatically.'),
      (e) => console.error(`  Could not start the proxy: ${e.message}`)
    );
  }

  if (hosts.status().entries.length) {
    console.log('  Note: a hosts-file redirect from an earlier session is still active on this computer.');
    console.log('  Remove it from the Devices tab when you are done, or that host name will keep pointing at the proxy.\n');
  }
}

main().catch((e) => {
  console.error(e.message || e);
  if (headless) desktop.showError('CORS Bridge could not start', `${e.message || e}\n\nDetails are in ${P.LOG_FILE}`);
  process.exit(1);
});
