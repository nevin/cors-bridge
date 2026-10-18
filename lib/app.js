'use strict';
// Starts and stops CORS Bridge: the dashboard server and the proxy engine. Shared by the command-line program
// (server.js) and the desktop app (electron/main.js), which only differ in how they show it and how they quit.
const crypto = require('crypto');
const store = require('./store');
const hosts = require('./hosts');
const P = require('./paths');
const instance = require('./instance');
const { ProxyEngine } = require('./proxy');
const { createApiServer } = require('./api');

// onQuit: called when the dashboard's Quit button is pressed.
// Resolves to { url, origin, port, token, engine, stop }. stop() shuts everything down and never throws.
async function startCorsBridge({ onQuit } = {}) {
  P.ensureDirs();
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
  const server = createApiServer({ engine, token, getPort: () => port, onQuit });
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

  // A redirect left behind points the API host names at this computer while nothing answers there (or while
  // another program does), so it is removed however CORS Bridge ends, if that setting is on.
  let stopping = null;
  const stop = () => {
    if (!stopping) {
      stopping = (async () => {
        console.log('\n  Shutting down...');
        server.close();
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
      })();
    }
    return stopping;
  };

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

  const origin = `http://127.0.0.1:${port}`;
  return { url: `${origin}/?token=${token}`, origin, port, token, engine, stop };
}

module.exports = { startCorsBridge };
