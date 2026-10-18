'use strict';
const http = require('http');
const https = require('https');
const tls = require('tls');
const fs = require('fs');
const os = require('os');
const path = require('path');
const dns = require('dns').promises;
const crypto = require('crypto');
const store = require('./store');
const certs = require('./certs');
const hosts = require('./hosts');
const devices = require('./devices');
const P = require('./paths');
const { UserError, isIp, isLoopbackAddress } = require('./util');

const PUBLIC = path.join(__dirname, '..', 'public');
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml' };

// In the single-file executable the dashboard files are embedded as assets instead of lying next to the code.
let sea = null;
try {
  sea = require('node:sea');
  if (!sea.isSea()) sea = null;
} catch {
  sea = null;
}

// Returns the file contents for a dashboard path such as "/app.js", or null if there is no such file.
function readPublic(rel) {
  if (sea) {
    try {
      return Buffer.from(sea.getAsset(`public${rel}`));
    } catch {
      return null;
    }
  }
  const file = path.normalize(path.join(PUBLIC, rel));
  if (!file.startsWith(PUBLIC) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) return null;
  return fs.readFileSync(file);
}

function localAddresses() {
  const out = new Set(['127.0.0.1', '::1']);
  for (const list of Object.values(os.networkInterfaces())) for (const i of list || []) out.add(i.address);
  return out;
}

async function resolveReal(host) {
  if (isIp(host)) return host;
  let addrs = [];
  try {
    addrs = await dns.resolve4(host); // asks DNS directly, ignoring the hosts file
  } catch {
    /* fall back below */
  }
  if (!addrs.length) {
    try {
      addrs = (await dns.lookup(host, { all: true, family: 4 })).map((a) => a.address);
    } catch {
      /* handled below */
    }
  }
  addrs = addrs.filter((a) => !a.startsWith('127.'));
  if (!addrs.length)
    throw new UserError(
      `Could not find the real address of ${host}. Make sure you are connected to the network or VPN that can reach it, or type the server IP yourself.`
    );
  return addrs[0];
}

// Shown when the dashboard is opened without the token, for example from a bookmark after a restart.
const SIGN_IN_PAGE = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>CORS Bridge</title>
<style>
:root { --fog:#eef2f5; --paper:#fff; --ink:#14212b; --steel:#5a6b78; --line:#cbd5dd; --span:#1f5fbf; color-scheme: light dark; }
@media (prefers-color-scheme: dark) { :root { --fog:#0f1a22; --paper:#16242e; --ink:#e6edf2; --steel:#9db0bd; --line:#2c3f4c; --span:#6ea2f0; } }
body { margin:0; background:var(--fog); color:var(--ink); font:15px/1.5 "Avenir Next","Segoe UI Variable Text","Segoe UI",system-ui,-apple-system,sans-serif; }
main { max-width:520px; margin:12vh auto; padding:0 16px; }
.card { background:var(--paper); border:1px solid var(--line); border-radius:6px; padding:22px 24px; }
h1 { font-size:1.2rem; margin:0 0 10px; display:flex; align-items:center; gap:10px; }
h1 svg { width:46px; height:auto; flex:none; }
p { margin:0 0 10px; } .muted { color:var(--steel); font-size:.9rem; }
code { font-family:ui-monospace,"SF Mono","Cascadia Mono",Menlo,Consolas,monospace; font-size:.9em; }
</style></head><body><main><div class="card">
<h1>${String(readPublic('/logo.svg') || '').replace('role="img" aria-label="CORS Bridge"', 'aria-hidden="true"')}CORS Bridge</h1>
<p>This page needs the address that was printed in the terminal window when CORS Bridge started. It includes a one-time token.</p>
<p class="muted">Look for the line that starts with <code>Dashboard:</code> and open that address. If CORS Bridge was restarted, the old address no longer works.</p>
</div></main></body></html>
`;

function createApiServer({ engine, token, getPort, onQuit }) {
  const tokenBuf = Buffer.from(token);

  const tokenOk = (v) => {
    const b = Buffer.from(String(v || ''));
    return b.length === tokenBuf.length && crypto.timingSafeEqual(b, tokenBuf);
  };
  const cookieToken = (req) => {
    const m = /(?:^|;\s*)cb_token=([^;]+)/.exec(req.headers.cookie || '');
    return m ? decodeURIComponent(m[1]) : '';
  };

  function state() {
    const cfg = store.load();
    return {
      platform: {
        os: process.platform,
        arch: process.arch,
        node: process.version,
        dataDir: P.DATA_DIR,
        portable: P.PORTABLE,
        portableName: P.PORTABLE_NAME,
        appFolder: P.APP_FOLDER,
        translocated: P.TRANSLOCATED,
        logFile: P.LOG_FILE,
        canQuit: !!onQuit,
        hostsPath: hosts.hostsPath(),
      },
      settings: cfg.settings,
      rules: cfg.rules,
      proxy: engine.status(),
      certs: certs.list(),
      activeCaId: cfg.activeCaId,
      hosts: hosts.status(),
    };
  }

  // ------------------------------------------------------------ devices
  const caList = () => certs.list().filter((c) => c.kind === 'ca');

  function pickCa(caId) {
    if (caId) {
      const c = certs.get(caId);
      if (!c || c.kind !== 'ca') throw new UserError('Pick a CA certificate');
      return c;
    }
    const cfg = store.load();
    const c = (cfg.activeCaId && certs.get(cfg.activeCaId)) || caList()[0];
    return c || certs.generateCa({});
  }

  function rememberIos(udid, change) {
    const cfg = store.load();
    const rec = cfg.devices.ios[udid] || { caIds: [] };
    change(rec);
    if (rec.caIds.length) cfg.devices.ios[udid] = { ...rec, updatedAt: new Date().toISOString() };
    else delete cfg.devices.ios[udid];
    store.save(cfg);
  }

  async function androidDevices() {
    const list = await devices.androidList();
    const cas = caList();
    const byHash = new Map(cas.map((c) => [certs.androidFileName(certs.firstPem(c.id)), c.id]));
    for (const d of list.devices) {
      if (d.state !== 'device') continue;
      const probe = await devices.androidProbe(d.serial, [...byHash.keys()]);
      d.caInstalled = probe.caPresent.map((n) => byHash.get(n));
      d.hostsEntries = probe.hostsEntries;
    }
    return list;
  }

  async function iosDevices() {
    const list = await devices.iosList();
    const rec = store.load().devices.ios;
    const known = new Set(caList().map((c) => c.id));
    for (const d of list.devices) d.caInstalled = ((rec[d.udid] && rec[d.udid].caIds) || []).filter((id) => known.has(id));
    return list;
  }

  async function iosInstall(udid, ca) {
    const out = await devices.iosInstallCa(udid, certs.firstPem(ca.id));
    rememberIos(udid, (rec) => {
      if (!rec.caIds.includes(ca.id)) rec.caIds.push(ca.id);
    });
    return out;
  }

  // Runs the steps one after another and collects their output, so a failure shows what already happened.
  async function runSteps(list) {
    const steps = [];
    const notes = [];
    for (const [label, fn] of list) {
      try {
        const out = await fn();
        if (out && out.steps) steps.push(...out.steps);
        else steps.push({ label, ok: true });
        if (out && out.note) notes.push(out.note);
      } catch (e) {
        if (e.steps) steps.push(...e.steps);
        steps.push({ label, ok: false, output: e.message });
        throw Object.assign(new UserError(`${label} failed: ${e.message}`, e.status || 400), { steps });
      }
    }
    return { ok: true, steps, notes };
  }

  function deviceTarget(body) {
    const platform = body.platform;
    const id = String(body.id || '').trim();
    if (!['android', 'ios'].includes(platform)) throw new UserError('Unknown device type');
    if (!id) throw new UserError('Pick a device');
    return { platform, id };
  }

  // ------------------------------------------------------------ export / import
  const SHARED_SETTINGS = ['androidHostIp', 'autoStartProxy', 'cleanupHostsOnExit'];
  const RULE_FIELDS = ['host', 'scheme', 'listenPort', 'upstreamHost', 'upstreamScheme', 'upstreamPort', 'verifyUpstream', 'stripOrigin', 'note', 'group', 'testPath', 'cors'];

  function exportData() {
    const cfg = store.load();
    const settings = {};
    for (const k of SHARED_SETTINGS) settings[k] = cfg.settings[k];
    return {
      app: 'cors-bridge',
      format: 1,
      exportedAt: new Date().toISOString(),
      settings,
      // Certificates are not included: each person keeps their own CA and private keys.
      rules: cfg.rules.map((r) => ({ enabled: r.enabled, ...Object.fromEntries(RULE_FIELDS.map((k) => [k, r[k]])) })),
    };
  }

  // What a rule from someone else's file would do that is worth a second look before turning it on.
  function importWarnings(rule) {
    const w = [];
    if (rule.scheme === 'https' && rule.upstreamScheme === 'http') w.push('Sends your app\'s requests to the real server unencrypted (http).');
    if (rule.upstreamScheme === 'https' && !rule.verifyUpstream) w.push('Does not check the real server\'s certificate.');
    if (rule.cors.origin === 'reflect') w.push('Lets any website read the answers, with your cookies.');
    if (rule.cors.origin === '*') w.push('Lets any website read the answers.');
    if (!rule.upstreamHost) w.push('The real server address is missing. CORS Bridge will try to find it.');
    return w;
  }

  // dryRun = only report what would change. Imported rules always arrive paused, so nothing is redirected
  // or forwarded until the person has looked at them.
  async function importData(body) {
    const data = body.data;
    if (!data || typeof data !== 'object' || data.app !== 'cors-bridge' || !Array.isArray(data.rules))
      throw new UserError('That is not a CORS Bridge export file.');
    if (data.format > 1) throw new UserError('That file was made by a newer version of CORS Bridge. Update CORS Bridge, then import it again.');
    if (data.rules.length > 500) throw new UserError('That file has more than 500 rules.');
    const dryRun = !!body.dryRun;
    const replace = body.mode === 'replace';
    const cfg = store.load();
    const warnings = [];
    const plan = [];
    let added = 0;
    let updated = 0;
    if (replace) cfg.rules = [];
    for (const [i, raw] of data.rules.entries()) {
      let rule;
      try {
        if (!raw || typeof raw !== 'object') throw new UserError('not a rule');
        const input = Object.fromEntries(RULE_FIELDS.filter((k) => raw[k] !== undefined).map((k) => [k, raw[k]]));
        input.cors = store.migrateCors(raw.cors || {});
        input.enabled = false;
        const host = String(raw.host || '').toLowerCase();
        const same = cfg.rules.find((r) => r.host === host && r.listenPort === Number(raw.listenPort) && r.group === store.normalizeGroup(raw.group));
        rule = store.normalizeRule({ ...input, hostInput: '', certId: same ? same.certId : null }, same ? { id: same.id } : {});
        const ruleWarnings = importWarnings(rule);
        if (!rule.upstreamHost && !dryRun) {
          try {
            rule.upstreamHost = await resolveReal(rule.host);
          } catch {
            warnings.push(`${rule.host}: the real server address is missing and could not be found. Open the rule and click Find it.`);
          }
        }
        if (rule.upstreamHost) checkLoop(rule);
        if (findClash(cfg.rules, rule)) throw clashError(rule, findClash(cfg.rules, rule));
        plan.push({
          action: same ? 'update' : 'add',
          host: rule.host,
          address: `${rule.scheme}://${rule.host}:${rule.listenPort}`,
          upstream: rule.upstreamHost ? `${rule.upstreamScheme}://${rule.upstreamHost}:${rule.upstreamPort}` : '',
          group: rule.group,
          warnings: ruleWarnings,
        });
        if (same) {
          cfg.rules = cfg.rules.map((r) => (r.id === same.id ? rule : r));
          updated++;
        } else {
          cfg.rules.push(rule);
          added++;
        }
      } catch (e) {
        if (!(e instanceof UserError)) throw e;
        const msg = `Rule ${i + 1}${raw && raw.host ? ` (${String(raw.host).slice(0, 80)})` : ''} will be skipped: ${e.message}`;
        plan.push({ action: 'skip', host: raw && raw.host ? String(raw.host).slice(0, 80) : `Rule ${i + 1}`, warnings: [e.message] });
        warnings.push(dryRun ? msg : msg.replace('will be skipped', 'was skipped'));
      }
    }
    const settings = [];
    if (data.settings && typeof data.settings === 'object') {
      for (const k of SHARED_SETTINGS) {
        if (data.settings[k] === undefined) continue;
        let v = data.settings[k];
        if (k === 'androidHostIp') {
          if (!isIp(String(v))) {
            warnings.push('The Android host address in the file is not an IP address, so it is not used.');
            continue;
          }
          v = String(v);
        } else v = !!v;
        if (cfg.settings[k] !== v) settings.push({ name: k, from: cfg.settings[k], to: v });
        cfg.settings[k] = v;
      }
    }
    if (!dryRun) store.save(cfg);
    return { dryRun, added, updated, plan, settings, warnings };
  }

  const json = (res, status, body) => {
    const data = JSON.stringify(body);
    res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
    res.end(data);
  };

  async function readBody(req) {
    const chunks = [];
    let size = 0;
    for await (const c of req) {
      size += c.length;
      if (size > 10 * 1024 * 1024) throw new UserError('Request too large', 413);
      chunks.push(c);
    }
    if (!chunks.length) return {};
    try {
      return JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch {
      throw new UserError('Invalid JSON');
    }
  }

  async function reloadIfRunning() {
    if (engine.running) {
      try {
        await engine.reload();
      } catch (e) {
        return e.message;
      }
    }
    return null;
  }

  function ruleEntries(ip) {
    return store
      .load()
      .rules.filter((r) => r.enabled)
      .map((r) => ({ ip, host: r.host }));
  }

  function checkLoop(rule) {
    const local = localAddresses();
    const up = rule.upstreamHost;
    if (up === 'localhost' || local.has(up) || up.startsWith('127.')) {
      if (rule.upstreamPort === rule.listenPort && rule.upstreamScheme === rule.scheme)
        throw new UserError(
          'The real server address points back to this computer on the same port, so the proxy would call itself. Use the real server IP (resolved while connected to your network/VPN).'
        );
    }
    if (up.toLowerCase() === rule.host)
      throw new UserError('The upstream address must be an IP address (or a different name) so it does not loop back through the redirect.');
  }

  // Two rules may share a host and port only when they are in different groups and at most one is on,
  // so a team can keep "dev" and "uat" rules for the same address and switch between them.
  function findClash(rules, rule) {
    return rules.find(
      (r) => r.id !== rule.id && r.host === rule.host && r.listenPort === rule.listenPort && (r.group === rule.group || (r.enabled && rule.enabled))
    );
  }
  function clashError(rule, other) {
    if (other.group !== rule.group)
      return new UserError(`The rule for ${rule.host} on port ${rule.listenPort} in group "${other.group || 'no group'}" is on. Pause it first, or switch groups.`);
    return new UserError(`There is already a rule for ${rule.host} on port ${rule.listenPort}${rule.group ? ` in group "${rule.group}"` : ''}.`);
  }

  async function saveRule(body) {
    const cfg = store.load();
    const prev = body.id ? cfg.rules.find((r) => r.id === body.id) : undefined;
    if (body.id && !prev) throw new UserError('Rule not found', 404);
    const rule = store.normalizeRule(body, prev || {});
    if (!rule.upstreamHost) rule.upstreamHost = await resolveReal(rule.host);
    if (rule.upstreamHost.startsWith('127.') === false && !isIp(rule.upstreamHost) && rule.upstreamHost.toLowerCase() === rule.host)
      rule.upstreamHost = await resolveReal(rule.host);
    checkLoop(rule);
    if (rule.listenPort === cfg.settings.uiPort) throw new UserError(`Port ${rule.listenPort} is used by this dashboard.`);
    if (rule.certId) {
      const c = certs.get(rule.certId);
      if (!c || c.kind !== 'leaf' || !c.hasKey) throw new UserError('Pick a server certificate that has a private key.');
    }
    const clash = findClash(cfg.rules, rule);
    if (clash) throw clashError(rule, clash);
    if (prev) cfg.rules = cfg.rules.map((r) => (r.id === rule.id ? rule : r));
    else cfg.rules.push(rule);
    store.save(cfg);
    return rule;
  }

  async function selfTest(rule) {
    const origin = 'http://localhost';
    const caPems = certs.allCaPems();
    const doReq = (method, extra) =>
      new Promise((resolve) => {
        const lib = rule.scheme === 'https' ? https : http;
        const opts = {
          host: '127.0.0.1',
          port: rule.listenPort,
          method,
          path: extra.path || '/',
          headers: { host: rule.host, origin, ...(extra.headers || {}) },
          timeout: 15000,
        };
        if (rule.scheme === 'https') {
          opts.servername = isIp(rule.host) ? undefined : rule.host;
          opts.rejectUnauthorized = false;
          opts.ca = [...tls.rootCertificates, ...caPems];
        }
        const r = lib.request(opts, (res) => {
          const sock = res.socket;
          const chunks = [];
          res.on('data', (c) => chunks.length < 20 && chunks.push(c));
          res.on('end', () =>
            resolve({
              status: res.statusCode,
              headers: res.headers,
              body: Buffer.concat(chunks).toString('utf8').slice(0, 300),
              trusted: sock && sock.authorized !== undefined ? sock.authorized : null,
              trustError: sock && sock.authorizationError ? String(sock.authorizationError) : null,
            })
          );
        });
        r.on('timeout', () => r.destroy(new Error('timed out')));
        r.on('error', (e) => resolve({ error: e.code || e.message }));
        r.end();
      });
    const preflight = await doReq('OPTIONS', {
      headers: { 'access-control-request-method': 'GET', 'access-control-request-headers': 'authorization,content-type' },
    });
    const actual = await doReq('GET', { path: rule.testPath || '/' });
    const acao = (r) => r && r.headers && r.headers['access-control-allow-origin'];
    return {
      host: rule.host,
      path: rule.testPath || '/',
      preflight,
      actual,
      corsOk: !!(preflight.status && preflight.status < 300 && acao(preflight) && acao(actual)),
    };
  }

  // --------------------------------------------------------------- routes
  const routes = [];
  const route = (method, pattern, fn) => routes.push({ method, re: new RegExp(`^${pattern}$`), fn });

  route('GET', '/api/state', async () => state());
  route('GET', '/api/resolve', async (req, res, m, url) => ({ ip: await resolveReal(String(url.searchParams.get('host') || '').trim().toLowerCase()) }));

  route('POST', '/api/rules', async (req, res, m, url, body) => {
    const rule = await saveRule(body);
    const warning = await reloadIfRunning();
    return { rule, warning, state: state() };
  });
  route('DELETE', '/api/rules/([a-f0-9]+)', async (req, res, m) => {
    const cfg = store.load();
    cfg.rules = cfg.rules.filter((r) => r.id !== m[1]);
    store.save(cfg);
    const warning = await reloadIfRunning();
    return { warning, state: state() };
  });
  route('POST', '/api/rules/([a-f0-9]+)/test', async (req, res, m) => {
    const rule = store.load().rules.find((r) => r.id === m[1]);
    if (!rule) throw new UserError('Rule not found', 404);
    if (!engine.running) throw new UserError('Start the proxy first, then run the test.');
    return selfTest(rule);
  });

  route('POST', '/api/proxy/(start|stop|restart)', async (req, res, m) => {
    if (m[1] === 'start') await engine.start();
    else if (m[1] === 'stop') await engine.stop();
    else {
      await engine.stop();
      await engine.start();
    }
    return state();
  });

  route('POST', '/api/certs/generate-ca', async (req, res, m, url, body) => ({ cert: certs.generateCa({ name: body.name }), state: state() }));
  route('POST', '/api/certs/issue', async (req, res, m, url, body) => ({
    cert: certs.issueLeaf({ hosts: body.hosts, caId: body.caId, days: Math.min(Number(body.days) || 365, 825), name: body.name }),
    state: state(),
  }));
  route('POST', '/api/certs/import', async (req, res, m, url, body) => {
    if (body.pfxBase64) {
      throw new UserError(
        'Password-protected .pfx/.p12 files are not supported directly. Convert it to PEM first: openssl pkcs12 -in file.pfx -nodes -out all.pem (OpenSSL ships with Git for Windows), then import the PEM file.'
      );
    }
    const imported = certs.importCert(body);
    return { imported, state: state() };
  });
  route('DELETE', '/api/certs/([a-f0-9]+)', async (req, res, m) => {
    const inUse = store.load().rules.filter((r) => r.certId === m[1]);
    if (inUse.length) {
      const cfg = store.load();
      cfg.rules = cfg.rules.map((r) => (r.certId === m[1] ? { ...r, certId: null } : r));
      store.save(cfg);
    }
    certs.remove(m[1]);
    const warning = await reloadIfRunning();
    return { warning, state: state() };
  });
  route('POST', '/api/certs/([a-f0-9]+)/activate', async (req, res, m) => {
    certs.setActiveCa(m[1]);
    return state();
  });
  route('GET', '/api/certs/([a-f0-9]+)/download', async (req, res, m, url) => {
    const f = certs.exportCert(m[1], url.searchParams.get('format') || 'pem');
    res.writeHead(200, {
      'content-type': f.type,
      'content-disposition': `attachment; filename="${f.filename}"`,
      'cache-control': 'no-store',
    });
    res.end(f.body);
    return undefined;
  });

  route('GET', '/api/hosts', async () => hosts.status());
  route('POST', '/api/hosts/apply', async () => {
    const entries = ruleEntries('127.0.0.1');
    if (!entries.length) throw new UserError('There are no enabled rules to redirect.');
    return { result: await hosts.apply(entries), state: state() };
  });
  route('POST', '/api/hosts/remove', async () => ({ result: await hosts.remove(), state: state() }));

  route('GET', '/api/android/devices', async () => androidDevices());
  route('POST', '/api/android/install-ca', async (req, res, m, url, body) => {
    const c = certs.get(body.caId);
    if (!c || c.kind !== 'ca') throw new UserError('Pick a CA certificate');
    const pem = certs.firstPem(c.id);
    return devices.androidInstallCa(body.serial, pem, certs.androidFileName(pem));
  });
  route('POST', '/api/android/apply-hosts', async (req, res, m, url, body) => {
    const entries = ruleEntries(store.load().settings.androidHostIp || '10.0.2.2');
    if (!entries.length) throw new UserError('There are no enabled rules to redirect.');
    return devices.androidApplyHosts(body.serial, entries);
  });
  route('POST', '/api/android/remove-hosts', async (req, res, m, url, body) => devices.androidRemoveHosts(body.serial));

  route('POST', '/api/android/remove-ca', async (req, res, m, url, body) => devices.androidRemoveCa(body.serial));

  route('GET', '/api/ios/devices', async () => iosDevices());
  route('POST', '/api/ios/install-ca', async (req, res, m, url, body) => {
    const c = certs.get(body.caId);
    if (!c || c.kind !== 'ca') throw new UserError('Pick a CA certificate');
    return iosInstall(body.udid, c);
  });

  // One button per device: install the CA, then point the rule host names at this computer.
  route('POST', '/api/devices/setup', async (req, res, m, url, body) => {
    const { platform, id } = deviceTarget(body);
    const ca = pickCa(body.caId);
    if (platform === 'android') {
      const entries = ruleEntries(store.load().settings.androidHostIp || '10.0.2.2');
      if (!entries.length) throw new UserError('There are no enabled rules to redirect.');
      const pem = certs.firstPem(ca.id);
      const out = await runSteps([
        ['Install CA', () => devices.androidInstallCa(id, pem, certs.androidFileName(pem))],
        ['Apply redirect', () => devices.androidApplyHosts(id, entries)],
      ]);
      return { ...out, note: 'Done until the emulator does a cold boot. Restart the app under test.', state: state() };
    }
    const entries = ruleEntries('127.0.0.1');
    if (!entries.length) throw new UserError('There are no enabled rules to redirect.');
    const out = await runSteps([
      ['Install CA', () => iosInstall(id, ca)],
      ['Apply redirect', async () => {
        const r = await hosts.apply(entries);
        return { steps: [{ label: r.changed ? 'Updated this Mac\'s hosts file' : 'This Mac\'s hosts file was already up to date', ok: true }] };
      }],
    ]);
    return { ...out, note: 'Restart the app under test so it picks up the certificate and the redirect.', state: state() };
  });
  route('POST', '/api/devices/undo', async (req, res, m, url, body) => {
    const { platform, id } = deviceTarget(body);
    if (platform === 'android') {
      const out = await runSteps([
        ['Remove redirect', () => devices.androidRemoveHosts(id)],
        ['Remove CA', () => devices.androidRemoveCa(id)],
      ]);
      return { ...out, note: 'The emulator is back to normal. Restart the app under test.', state: state() };
    }
    const out = await runSteps([
      ['Remove redirect', async () => {
        await hosts.remove();
        return { steps: [{ label: 'Removed the redirect from this Mac\'s hosts file', ok: true }] };
      }],
      ['Remove CA', async () => {
        const r = await devices.iosResetKeychain(id);
        rememberIos(id, (rec) => {
          rec.caIds = [];
        });
        return r;
      }],
    ]);
    return { ...out, note: 'The simulator is back to normal. Restart the app under test.', state: state() };
  });

  // Turns every rule in a group on or off. Turning a group on pauses other rules that use the same address and port.
  route('POST', '/api/groups', async (req, res, m, url, body) => {
    const group = store.normalizeGroup(body.group);
    const cfg = store.load();
    const members = cfg.rules.filter((r) => r.group === group);
    if (!members.length) throw new UserError(group ? `There are no rules in group "${group}".` : 'There are no rules without a group.');
    const on = !!body.enabled;
    const paused = [];
    cfg.rules = cfg.rules.map((r) => {
      if (r.group === group) return { ...r, enabled: on };
      if (on && r.enabled && members.some((x) => x.host === r.host && x.listenPort === r.listenPort)) {
        paused.push(r);
        return { ...r, enabled: false };
      }
      return r;
    });
    store.save(cfg);
    const warning = await reloadIfRunning();
    return { paused: paused.map((r) => ({ id: r.id, host: r.host, group: r.group })), warning, state: state() };
  });

  route('GET', '/api/export', async (req, res) => {
    const data = JSON.stringify(exportData(), null, 2);
    res.writeHead(200, {
      'content-type': 'application/json; charset=utf-8',
      'content-disposition': `attachment; filename="cors-bridge-rules-${new Date().toISOString().slice(0, 10)}.json"`,
      'cache-control': 'no-store',
    });
    res.end(data);
    return undefined;
  });
  route('POST', '/api/import', async (req, res, m, url, body) => {
    const out = await importData(body);
    if (out.dryRun) return out;
    const warning = await reloadIfRunning();
    return { ...out, warning, state: state() };
  });

  route('POST', '/api/settings', async (req, res, m, url, body) => {
    const cfg = store.load();
    const s = cfg.settings;
    if (body.lanClients !== undefined) {
      const list = (Array.isArray(body.lanClients) ? body.lanClients : String(body.lanClients).split(/[\s,]+/)).map((x) => String(x).trim()).filter(Boolean);
      const bad = list.find((x) => !isIp(x));
      if (bad) throw new UserError(`"${bad.slice(0, 60)}" is not an IP address. Enter the address of the phone, for example 192.168.1.20.`);
      if (list.length > 20) throw new UserError('Enter at most 20 addresses.');
      s.lanClients = [...new Set(list)];
    }
    if (body.allowLan !== undefined) {
      if (body.allowLan && !s.lanClients.length) throw new UserError('Enter the IP address of the device that should use the proxy first.');
      s.allowLan = !!body.allowLan;
    }
    if (body.autoStartProxy !== undefined) s.autoStartProxy = !!body.autoStartProxy;
    if (body.cleanupHostsOnExit !== undefined) s.cleanupHostsOnExit = !!body.cleanupHostsOnExit;
    const seconds = (v, min, max, label) => {
      const n = Number(v);
      if (!Number.isInteger(n) || n < min || n > max) throw new UserError(`${label} must be a whole number of seconds between ${min} and ${max}.`);
      return n;
    };
    if (body.connectTimeoutSec !== undefined) s.connectTimeoutSec = seconds(body.connectTimeoutSec, 1, 120, 'The time to wait for a connection');
    if (body.answerTimeoutSec !== undefined) s.answerTimeoutSec = seconds(body.answerTimeoutSec, 5, 3600, 'The time to wait for an answer');
    if (body.androidHostIp !== undefined) {
      const ip = String(body.androidHostIp).trim();
      if (!isIp(ip)) throw new UserError('Android host address must be an IP address (10.0.2.2 for the emulator).');
      s.androidHostIp = ip;
    }
    store.save(cfg);
    return state();
  });

  // The Quit button. Answers first, then shuts down (which also removes the hosts redirect if that is turned on).
  route('POST', '/api/quit', async () => {
    if (!onQuit) throw new UserError('Quit is not available here.');
    const removesRedirect = store.load().settings.cleanupHostsOnExit && hosts.status().entries.length > 0;
    setTimeout(onQuit, 100);
    return { ok: true, removesRedirect };
  });

  route('GET', '/api/logs', async () => ({ logs: engine.logs }));
  route('DELETE', '/api/logs', async () => {
    engine.clearLogs();
    return { ok: true };
  });

  // --------------------------------------------------------------- server
  const hostAllowed = (hostHeader) => {
    const port = getPort();
    return ['127.0.0.1', 'localhost', '[::1]'].some((h) => hostHeader === `${h}:${port}`);
  };

  const server = http.createServer(async (req, res) => {
    res.setHeader('x-content-type-options', 'nosniff');
    res.setHeader('x-frame-options', 'DENY');
    res.setHeader('referrer-policy', 'no-referrer');
    res.setHeader('content-security-policy', "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'");

    // Defence against DNS rebinding and other websites calling this local API.
    if (!isLoopbackAddress(req.socket.remoteAddress) || !hostAllowed(req.headers.host || '')) {
      res.writeHead(403, { 'content-type': 'text/plain' });
      return res.end('Forbidden');
    }
    const url = new URL(req.url, `http://${req.headers.host}`);

    if (url.searchParams.has('token') && tokenOk(url.searchParams.get('token'))) {
      res.writeHead(302, {
        'set-cookie': `cb_token=${token}; HttpOnly; SameSite=Strict; Path=/`,
        location: url.pathname || '/',
      });
      return res.end();
    }
    if (!tokenOk(cookieToken(req))) {
      if (url.pathname.startsWith('/api/'))
        return json(res, 401, { error: 'Session expired. Open the address printed in the terminal window again.' });
      res.writeHead(401, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
      return res.end(SIGN_IN_PAGE);
    }
    const site = req.headers['sec-fetch-site'];
    if (site && !['same-origin', 'none'].includes(site)) {
      res.writeHead(403, { 'content-type': 'text/plain' });
      return res.end('Forbidden');
    }

    try {
      if (url.pathname === '/api/events') {
        res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-store', connection: 'keep-alive' });
        res.write(': connected\n\n');
        const onLog = (e) => res.write(`data: ${JSON.stringify(e)}\n\n`);
        const onStatus = (s) => res.write(`event: status\ndata: ${JSON.stringify(s)}\n\n`);
        engine.on('log', onLog);
        engine.on('status', onStatus);
        const ping = setInterval(() => res.write(': ping\n\n'), 20000);
        req.on('close', () => {
          clearInterval(ping);
          engine.off('log', onLog);
          engine.off('status', onStatus);
        });
        return;
      }
      if (url.pathname.startsWith('/api/')) {
        for (const r of routes) {
          if (r.method !== req.method) continue;
          const m = r.re.exec(url.pathname);
          if (!m) continue;
          const body = req.method === 'POST' ? await readBody(req) : {};
          const out = await r.fn(req, res, m, url, body);
          if (out !== undefined) json(res, 200, out);
          return;
        }
        return json(res, 404, { error: 'Not found' });
      }
      // static files
      const rel = url.pathname === '/' ? '/index.html' : url.pathname;
      const data = readPublic(rel);
      if (!data) {
        res.writeHead(404, { 'content-type': 'text/plain' });
        return res.end('Not found');
      }
      res.writeHead(200, { 'content-type': MIME[path.extname(rel)] || 'application/octet-stream', 'cache-control': 'no-store' });
      res.end(data);
    } catch (e) {
      const status = e.status || 500;
      if (!res.headersSent) json(res, status, { error: e.message, steps: e.steps });
      else res.end();
      if (!e.status) console.error(e);
    }
  });

  return server;
}

module.exports = { createApiServer, resolveReal };
