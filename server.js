#!/usr/bin/env node
'use strict';
const crypto = require('crypto');
const { spawn } = require('child_process');
const store = require('./lib/store');
const hosts = require('./lib/hosts');
const P = require('./lib/paths');
const { ProxyEngine } = require('./lib/proxy');
const { createApiServer } = require('./lib/api');

const major = Number(process.versions.node.split('.')[0]);
if (major < 18) {
  console.error(`CORS Bridge needs Node.js 18 or newer (you have ${process.version}). Get it from https://nodejs.org`);
  process.exit(1);
}

function openBrowser(url) {
  try {
    if (process.platform === 'darwin') spawn('open', [url], { stdio: 'ignore', detached: true }).unref();
    else if (process.platform === 'win32') spawn('cmd', ['/c', 'start', '""', url], { stdio: 'ignore', detached: true, windowsHide: true }).unref();
    else spawn('xdg-open', [url], { stdio: 'ignore', detached: true }).unref();
  } catch {
    /* the URL is printed anyway */
  }
}

async function main() {
  P.ensureDirs();
  const args = process.argv.slice(2);
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
  const server = createApiServer({ engine, token, getPort: () => port });

  // A redirect left behind points the API host names at this computer while nothing answers there (or while
  // another program does), so remove it however CORS Bridge ends: Ctrl+C, closing the window, or a crash.
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

  const url = `http://127.0.0.1:${port}/?token=${token}`;
  console.log('');
  console.log('  CORS Bridge is running.');
  console.log(`  Dashboard: ${url}`);
  console.log('  Leave this window open while you test. Press Ctrl+C to quit.');
  console.log('');
  if (!args.includes('--no-open')) openBrowser(url);

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
  process.exit(1);
});
