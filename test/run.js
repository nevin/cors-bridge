'use strict';
// End-to-end tests. Run with: npm test   (no network access needed)
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const https = require('https');
const net = require('net');
const crypto = require('crypto');
const { execFileSync, spawnSync } = require('child_process');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cb-test-'));
process.env.CORS_BRIDGE_HOME = path.join(tmp, 'home');
process.env.CORS_BRIDGE_HOSTS_FILE = path.join(tmp, 'hosts');
fs.writeFileSync(process.env.CORS_BRIDGE_HOSTS_FILE, '127.0.0.1 localhost\n::1 localhost\n');

const store = require('../lib/store');
const certs = require('../lib/certs');
const hosts = require('../lib/hosts');
const { ProxyEngine } = require('../lib/proxy');
const { createApiServer } = require('../lib/api');

let passed = 0;
let failed = 0;
async function test(name, fn) {
  try {
    await fn();
    passed++;
    console.log(`  ok   ${name}`);
  } catch (e) {
    failed++;
    console.log(`  FAIL ${name}\n       ${e && e.stack ? e.stack.split('\n').slice(0, 4).join('\n       ') : e}`);
  }
}
const eq = (a, b, m) => {
  if (a !== b) throw new Error(`${m || 'not equal'}: got ${JSON.stringify(a)}, expected ${JSON.stringify(b)}`);
};
const ok = (v, m) => {
  if (!v) throw new Error(m || 'expected truthy');
};
const hasOpenssl = spawnSync('openssl', ['version']).status === 0;

function request(opts, body) {
  return new Promise((resolve, reject) => {
    const lib = opts.https ? https : http;
    const r = lib.request(opts, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }));
    });
    r.on('error', reject);
    if (body) r.write(body);
    r.end();
  });
}

(async () => {
  console.log('\nCertificates');
  let ca;
  let leaf;
  await test('generate a CA and issue a server certificate', async () => {
    ca = certs.generateCa({ name: 'Test CA' });
    leaf = certs.issueLeaf({ hosts: ['api.test.local', '*.wild.test.local'] });
    eq(ca.kind, 'ca');
    eq(leaf.kind, 'leaf');
    ok(leaf.names.includes('api.test.local'));
    eq(certs.get(ca.id).isActive, true, 'first CA becomes active');
  });
  await test('certificate verifies with OpenSSL and has the right host name', async () => {
    if (!hasOpenssl) return console.log('       (skipped, openssl not installed)');
    fs.writeFileSync(path.join(tmp, 'ca.pem'), certs.firstPem(ca.id));
    fs.writeFileSync(path.join(tmp, 'leaf.pem'), certs.firstPem(leaf.id));
    const out = execFileSync('openssl', ['verify', '-CAfile', path.join(tmp, 'ca.pem'), '-verify_hostname', 'api.test.local', path.join(tmp, 'leaf.pem')]).toString();
    ok(out.includes('OK'), out);
  });
  await test('Android file name matches openssl subject_hash_old', async () => {
    if (!hasOpenssl) return console.log('       (skipped, openssl not installed)');
    const expected = execFileSync('openssl', ['x509', '-subject_hash_old', '-noout', '-in', path.join(tmp, 'ca.pem')]).toString().trim();
    eq(certs.androidFileName(certs.firstPem(ca.id)), `${expected}.0`);
  });
  await test('wildcard host matching covers one label only', async () => {
    ok(certs.hostMatches(['*.example.com'], 'a.example.com'));
    ok(!certs.hostMatches(['*.example.com'], 'a.b.example.com'));
    ok(!certs.hostMatches(['*.example.com'], 'example.com'));
  });
  await test('import: CA bundle without key is install-only; leaf without key is rejected', async () => {
    const [imp] = certs.importCert({ certPem: certs.firstPem(ca.id), name: 'Company root' });
    eq(imp.id, ca.id, 'duplicate of existing CA is recognised');
    let threw = false;
    try {
      certs.importCert({ certPem: certs.firstPem(leaf.id) });
    } catch (e) {
      threw = /private key/i.test(e.message);
    }
    ok(threw, 'leaf without key must be rejected');
  });
  await test('import: company-style leaf + key (encrypted key, wrong passphrase, mismatch)', async () => {
    if (!hasOpenssl) return console.log('       (skipped, openssl not installed)');
    const d = path.join(tmp, 'corp');
    fs.mkdirSync(d);
    const sh = (...a) => execFileSync('openssl', a, { cwd: d, stdio: 'pipe' });
    sh('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '30', '-subj', '/CN=Corp Root CA/O=Corp', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign');
    sh('req', '-newkey', 'rsa:2048', '-keyout', 'srv.key', '-out', 'srv.csr', '-subj', '/CN=corp.example.com', '-passout', 'pass:secret');
    fs.writeFileSync(path.join(d, 'ext.cnf'), 'subjectAltName=DNS:corp.example.com\nbasicConstraints=CA:FALSE\n');
    sh('x509', '-req', '-in', 'srv.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'srv.pem', '-days', '30', '-extfile', 'ext.cnf');
    const rd = (f) => fs.readFileSync(path.join(d, f), 'utf8');
    let msg = '';
    try { certs.importCert({ certPem: rd('srv.pem'), keyPem: rd('srv.key') }); } catch (e) { msg = e.message; }
    ok(/encrypted/i.test(msg), `expected encrypted-key message, got: ${msg}`);
    msg = '';
    try { certs.importCert({ certPem: rd('srv.pem'), keyPem: rd('srv.key'), passphrase: 'nope' }); } catch (e) { msg = e.message; }
    ok(/passphrase/i.test(msg), `expected wrong-passphrase message, got: ${msg}`);
    const [c] = certs.importCert({ certPem: `${rd('srv.pem')}\n${rd('ca.pem')}`, keyPem: rd('srv.key'), passphrase: 'secret', name: 'Corp server' });
    eq(c.kind, 'leaf');
    eq(c.origin, 'imported');
    ok(certs.findLeafForHost('corp.example.com').id === c.id, 'imported cert is preferred for its host');
    msg = '';
    try { certs.importCert({ certPem: certs.firstPem(leaf.id), keyPem: rd('ca.key') }); } catch (e) { msg = e.message; }
    ok(/does not match/i.test(msg), `expected mismatch message, got: ${msg}`);
    // company CA with key can sign new server certs, and OpenSSL accepts the chain
    const [corpCa] = certs.importCert({ certPem: rd('ca.pem'), keyPem: rd('ca.key'), name: 'Corp CA' });
    eq(corpCa.canSign, true);
    const signed = certs.issueLeaf({ hosts: ['signed.example.com'], caId: corpCa.id });
    fs.writeFileSync(path.join(d, 'signed.pem'), certs.firstPem(signed.id));
    const v = execFileSync('openssl', ['verify', '-CAfile', path.join(d, 'ca.pem'), '-verify_hostname', 'signed.example.com', path.join(d, 'signed.pem')]).toString();
    ok(v.includes('OK'), v);
    certs.remove(corpCa.id);
  });

  await test('import: a combined PEM (key and certificate in one file) is split automatically', async () => {
    if (!hasOpenssl) return console.log('       (skipped, openssl not installed)');
    const d = path.join(tmp, 'combined');
    fs.mkdirSync(d);
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'k.pem', '-out', 'c.pem', '-days', '30', '-subj', '/CN=combined.example.com', '-addext', 'subjectAltName=DNS:combined.example.com', '-addext', 'basicConstraints=CA:FALSE'], { cwd: d, stdio: 'pipe' });
    const all = `Bag Attributes\n${fs.readFileSync(path.join(d, 'k.pem'), 'utf8')}${fs.readFileSync(path.join(d, 'c.pem'), 'utf8')}`;
    const split = certs.splitCombinedPem(all);
    ok(/BEGIN PRIVATE KEY/.test(split.keyPem) && !/PRIVATE/.test(split.certPem));
    const [c] = certs.importCert({ certPem: all });
    eq(c.kind, 'leaf');
    eq(c.hasKey, true);
    certs.remove(c.id);
  });

  console.log('\nRules');
  await test('test path and group are normalised', async () => {
    const r = store.normalizeRule({ hostInput: 'https://a.test.local', upstreamHost: '203.0.113.1', testPath: 'health?x=1', group: ' UAT ' });
    eq(r.testPath, '/health?x=1');
    eq(r.group, 'uat');
    eq(store.normalizeRule({ hostInput: 'a.test.local', upstreamHost: '203.0.113.1' }).testPath, '/');
    eq(store.normalizeTestPath('https://a.test.local/v1/ping'), '/v1/ping');
    let threw = false;
    try { store.normalizeGroup('dev/<x>'); } catch { threw = true; }
    ok(threw, 'odd group names are rejected');
  });

  await test('CORS values that end up in headers are checked (strict for input, cleaned for saved data)', async () => {
    const bad = [
      { origin: 'custom', customOrigin: 'https://a.example\r\nSet-Cookie: x=1' },
      { origin: 'app', customOrigin: 'https://a.example/path' },
      { methods: 'GET\r\nX-Evil: 1' },
      { headers: 'content-type, x y' },
      { exposeHeaders: 'a\nb' },
      { origin: 'custom', customOrigin: '' },
    ];
    for (const c of bad) {
      let threw = false;
      try { store.normalizeCors(c, { strict: true }); } catch { threw = true; }
      ok(threw, `should refuse ${JSON.stringify(c)}`);
    }
    const lenient = store.normalizeCors({ origin: 'custom', customOrigin: 'https://ok.example, bad\r\nx', methods: 'GET\nX' });
    eq(lenient.customOrigin, 'https://ok.example');
    eq(lenient.methods, 'reflect');
    eq(store.normalizeCors({}).origin, 'app', 'new rules only answer the app');
    eq(store.migrateCors({ origin: 'reflect' }).origin, 'app', 'old default moves to app');
    eq(store.migrateCors({ origin: 'reflect', policy: 2 }).origin, 'reflect', 'a deliberate choice stays');
    const cfgV1 = store.load();
    store.save({ ...cfgV1, settings: { ...cfgV1.settings, cleanupHostsOnExit: false, settingsVersion: undefined } });
    eq(store.load().settings.cleanupHostsOnExit, true, 'old configs get the redirect cleaned up on quit');
    store.save({ ...cfgV1, settings: { ...cfgV1.settings, cleanupHostsOnExit: false } });
    eq(store.load().settings.cleanupHostsOnExit, false, 'turning it off again sticks');
    store.save(cfgV1);
  });

  console.log('\nHosts file');
  await test('admin write on macOS carries the text inside the command and replaces the file in one step', async () => {
    if (process.platform !== 'darwin') return console.log('       (skipped, macOS only)');
    const d = fs.mkdtempSync(path.join(tmp, 'elev-'));
    const target = path.join(d, "ho'sts");
    fs.writeFileSync(target, 'old\n');
    const content = '127.0.0.1 localhost\n# it\'s "quoted" $HOME `x`\n';
    const cmd = hosts.darwinWriteCommand(content, target);
    ok(cmd.includes(`mktemp '${path.join(d, '.cors-bridge-hosts.XXXXXX')}'`) && (cmd.match(/mktemp/g) || []).length === 1, 'the only temp file is created by root next to the hosts file');
    execFileSync('/bin/sh', ['-c', cmd]);
    eq(fs.readFileSync(target, 'utf8'), content);
    eq(fs.statSync(target).mode & 0o777, 0o644);
    eq(fs.readdirSync(d).length, 1, 'no temp file left behind');
  });
  await test('admin write on Windows is one encoded PowerShell command', async () => {
    const enc = hosts.windowsWriteCommand('127.0.0.1 a.test\r\n', 'C:\\Windows\\System32\\drivers\\etc\\hosts');
    const ps = Buffer.from(enc, 'base64').toString('utf16le');
    ok(ps.includes('FromBase64String') && ps.includes("Move-Item -Force -LiteralPath $tmp -Destination 'C:\\Windows\\System32\\drivers\\etc\\hosts'"), ps);
    ok(!/Temp|AppData/i.test(ps), 'nothing is read from the user temp folder');
  });
  await test('managed block is added, replaced and removed without touching other lines', async () => {
    for (const eol of ['\n', '\r\n']) {
      const orig = `127.0.0.1 localhost${eol}# my line${eol}`;
      const a = hosts.buildContent(orig, [{ ip: '127.0.0.1', host: 'api.test.local' }]);
      ok(a.includes('127.0.0.1 api.test.local') && a.startsWith(orig));
      const b = hosts.buildContent(a, [{ ip: '10.0.2.2', host: 'x.test.local' }]);
      ok(!b.includes('api.test.local') && b.includes('10.0.2.2 x.test.local'));
      eq(hosts.buildContent(b, []), orig, 'removal restores the original');
      eq(hosts.parseBlock(b).length, 1);
    }
  });
  await test('apply and remove on a (test) hosts file', async () => {
    const r = await hosts.apply([{ ip: '127.0.0.1', host: 'api.test.local' }]);
    ok(r.changed);
    ok(fs.readFileSync(process.env.CORS_BRIDGE_HOSTS_FILE, 'utf8').includes('api.test.local'));
    await hosts.remove();
    eq(fs.readFileSync(process.env.CORS_BRIDGE_HOSTS_FILE, 'utf8'), '127.0.0.1 localhost\n::1 localhost\n');
  });

  console.log('\nProxy engine');
  // upstream "real server": no CORS support, adds its own conflicting CORS header on /conflict
  const upstream = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      if (req.url === '/conflict') res.setHeader('Access-Control-Allow-Origin', 'https://wrong.example');
      res.setHeader('X-Custom', 'abc');
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ method: req.method, url: req.url, host: req.headers.host, origin: req.headers.origin || null, body: Buffer.concat(chunks).toString() }));
    });
  });
  upstream.on('upgrade', (req, socket) => {
    socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n');
    socket.on('data', (d) => socket.write(Buffer.concat([Buffer.from('echo:'), d])));
  });
  await new Promise((r) => upstream.listen(19080, '127.0.0.1', r));

  const cfg = store.load();
  const rule = store.normalizeRule({ hostInput: 'https://api.test.local:18443', upstreamHost: '127.0.0.1', upstreamScheme: 'http', upstreamPort: 19080 });
  const deadRule = store.normalizeRule({ hostInput: 'https://dead.test.local:18443', upstreamHost: '127.0.0.1', upstreamScheme: 'http', upstreamPort: 19999 });
  cfg.rules = [rule, deadRule];
  store.save(cfg);
  const engine = new ProxyEngine({ getRules: () => store.load().rules, getSettings: () => store.load().settings });
  await engine.start();
  const caPem = certs.firstPem(ca.id);
  const base = (host, extra = {}) => ({ https: true, agent: false, host: '127.0.0.1', port: 18443, servername: host, ca: caPem, headers: { host, ...(extra.headers || {}) }, ...extra, });

  await test('browsers can validate the served certificate against the generated CA', async () => {
    const r = await request({ ...base('api.test.local'), path: '/hello', method: 'GET' });
    eq(r.status, 200);
  });
  await test('preflight is answered locally with reflected origin, headers and credentials', async () => {
    const r = await request({ ...base('api.test.local'), path: '/x', method: 'OPTIONS', headers: { host: 'api.test.local', origin: 'capacitor://localhost', 'access-control-request-method': 'POST', 'access-control-request-headers': 'authorization, content-type' } });
    eq(r.status, 204);
    eq(r.headers['access-control-allow-origin'], 'capacitor://localhost');
    eq(r.headers['access-control-allow-credentials'], 'true');
    eq(r.headers['access-control-allow-headers'], 'authorization, content-type');
    ok(/POST/.test(r.headers['access-control-allow-methods']));
  });
  await test('real requests are proxied (method, path, body, Host) and get CORS + expose headers', async () => {
    const r = await request({ ...base('api.test.local'), path: '/items?a=1', method: 'POST', headers: { host: 'api.test.local', origin: 'http://localhost', 'content-type': 'text/plain', 'content-length': '5' } }, 'hello');
    eq(r.status, 200);
    const j = JSON.parse(r.body);
    eq(j.method, 'POST');
    eq(j.url, '/items?a=1');
    eq(j.host, 'api.test.local');
    eq(j.body, 'hello');
    eq(r.headers['access-control-allow-origin'], 'http://localhost');
    ok(/x-custom/.test(r.headers['access-control-expose-headers']), 'custom response header is exposed');
    ok(/Origin/.test(r.headers.vary));
  });
  await test("the server's own conflicting CORS header is replaced, not duplicated", async () => {
    const r = await request({ ...base('api.test.local'), path: '/conflict', method: 'GET', headers: { host: 'api.test.local', origin: 'http://localhost' } });
    eq(r.headers['access-control-allow-origin'], 'http://localhost');
  });
  await test('unreachable server returns 502 that still carries CORS headers (so the browser shows the real error)', async () => {
    const r = await request({ ...base('dead.test.local'), path: '/', method: 'GET', headers: { host: 'dead.test.local', origin: 'http://localhost' } });
    eq(r.status, 502);
    eq(r.headers['access-control-allow-origin'], 'http://localhost');
    ok(/ECONNREFUSED/.test(r.body));
  });
  await test('WebSocket upgrade is tunnelled', async () => {
    await new Promise((resolve, reject) => {
      const r = https.request({ ...base('api.test.local'), path: '/ws', method: 'GET', headers: { host: 'api.test.local', connection: 'Upgrade', upgrade: 'websocket' } });
      r.on('upgrade', (res, socket) => {
        eq(res.statusCode, 101);
        socket.write('ping');
        socket.once('data', (d) => {
          try { eq(d.toString(), 'echo:ping'); resolve(); } catch (e) { reject(e); } finally { socket.destroy(); }
        });
      });
      r.on('error', reject);
      r.end();
    });
  });
  await test('requests are logged', async () => {
    ok(engine.logs.some((l) => l.preflight && l.status === 204));
    ok(engine.logs.some((l) => l.status === 502));
  });
  await test('log entries carry request/response headers, the CORS headers added, and hide secrets', async () => {
    await request({ ...base('api.test.local'), path: '/conflict', method: 'GET', headers: { host: 'api.test.local', origin: 'http://localhost', authorization: 'Bearer abcdefghijklmnopqrstuvwxyz0123456789' } });
    const l = engine.logs[engine.logs.length - 1];
    eq(l.path, '/conflict');
    eq(l.resHeaders['access-control-allow-origin'], 'https://wrong.example', 'what the server sent');
    eq(l.corsAdded['access-control-allow-origin'], 'http://localhost', 'what CORS Bridge sent instead');
    ok(/hidden/.test(l.reqHeaders.authorization) && !l.reqHeaders.authorization.includes('0123456789'), l.reqHeaders.authorization);
    const pre = engine.logs.find((x) => x.preflight);
    ok(pre.corsAdded['access-control-allow-methods'], 'preflight lists the headers it answered with');
  });
  await test('default policy: the app origins get CORS headers, other websites do not', async () => {
    for (const o of ['capacitor://localhost', 'ionic://localhost', 'http://localhost:8100', 'https://localhost', 'http://10.0.2.2:8100']) {
      const r = await request({ ...base('api.test.local'), path: '/x', method: 'GET', headers: { host: 'api.test.local', origin: o } });
      eq(r.headers['access-control-allow-origin'], o, o);
    }
    const evil = 'https://evil.example';
    const pre = await request({ ...base('api.test.local'), path: '/x', method: 'OPTIONS', headers: { host: 'api.test.local', origin: evil, 'access-control-request-method': 'GET', 'access-control-request-private-network': 'true' } });
    eq(pre.status, 403);
    eq(pre.headers['access-control-allow-origin'], undefined);
    eq(pre.headers['access-control-allow-private-network'], undefined);
    const get = await request({ ...base('api.test.local'), path: '/conflict', method: 'GET', headers: { host: 'api.test.local', origin: evil, cookie: 'session=1' } });
    eq(get.status, 200);
    eq(get.headers['access-control-allow-origin'], undefined, "the server's own header is removed too");
    eq(get.headers['access-control-allow-credentials'], undefined);
    ok(/Origin/.test(get.headers.vary), 'caches keep answers per origin');
    ok(engine.logs.some((l) => /origin not allowed: https:\/\/evil.example/.test(l.note)), 'the live log says why');
  });
  await test('private network permission only for the app, even when a rule allows any website', async () => {
    const cfgA = store.load();
    cfgA.rules = cfgA.rules.map((r) => (r.host === 'api.test.local' ? { ...r, cors: { ...r.cors, origin: 'reflect', customOrigin: 'https://partner.example' } } : r));
    store.save(cfgA);
    await engine.reload();
    const pna = (origin) => request({ ...base('api.test.local'), path: '/x', method: 'OPTIONS', headers: { host: 'api.test.local', origin, 'access-control-request-method': 'GET', 'access-control-request-private-network': 'true' } });
    let r = await pna('https://evil.example');
    eq(r.headers['access-control-allow-origin'], 'https://evil.example', 'any origin, as chosen');
    eq(r.headers['access-control-allow-private-network'], undefined);
    r = await pna('capacitor://localhost');
    eq(r.headers['access-control-allow-private-network'], 'true');
    r = await pna('https://partner.example');
    eq(r.headers['access-control-allow-private-network'], 'true', 'listed origins too');
  });
  await test('a header value Node refuses gives a 500 instead of crashing the app', async () => {
    const good = store.load().rules;
    const broken = good.map((r) => (r.host === 'api.test.local' ? { ...r, cors: { ...r.cors, methods: 'GET\r\nX-Evil: 1' } } : r));
    engine.getRules = () => broken; // bypasses the checks in the store on purpose
    await engine.reload();
    const r = await request({ ...base('api.test.local'), path: '/x', method: 'OPTIONS', headers: { host: 'api.test.local', origin: 'http://localhost', 'access-control-request-method': 'GET' } });
    eq(r.status, 500);
    ok(/could not be sent/.test(r.body));
    const again = await request({ ...base('api.test.local'), path: '/hello', method: 'GET', headers: { host: 'api.test.local', origin: 'http://localhost' } });
    eq(again.status, 200, 'still running');
    engine.getRules = () => store.load().rules;
  });
  await engine.stop();

  console.log('\nManagement API and device helpers');
  const token = crypto.randomBytes(8).toString('hex');
  let apiPort;
  const engine2 = new ProxyEngine({ getRules: () => store.load().rules, getSettings: () => store.load().settings });
  const api = createApiServer({ engine: engine2, token, getPort: () => apiPort });
  await new Promise((r) => api.listen(0, '127.0.0.1', r));
  apiPort = api.address().port;
  const call = (method, p, body, headers = {}) =>
    request({ host: '127.0.0.1', port: apiPort, path: p, method, headers: { host: `127.0.0.1:${apiPort}`, cookie: `cb_token=${token}`, 'content-type': 'application/json', ...headers } }, body ? JSON.stringify(body) : undefined);

  await test('API rejects missing token, wrong token, foreign Host header and cross-site requests', async () => {
    eq((await call('GET', '/api/state', null, { cookie: '' })).status, 401);
    eq((await call('GET', '/api/state', null, { cookie: 'cb_token=wrong' })).status, 401);
    eq((await call('GET', '/api/state', null, { host: 'evil.example.com' })).status, 403);
    eq((await call('GET', '/api/state', null, { 'sec-fetch-site': 'cross-site' })).status, 403);
    eq((await call('GET', '/api/state')).status, 200);
  });
  await test('without the token, pages get a styled HTML page and API calls get JSON', async () => {
    const page = await call('GET', '/', null, { cookie: '' });
    eq(page.status, 401);
    ok(/text\/html/.test(page.headers['content-type']) && /Dashboard:/.test(page.body) && /prefers-color-scheme: dark/.test(page.body));
    ok(page.body.includes('<svg') && page.body.includes('aria-hidden="true"'), 'the logo is built into the page (it cannot load files without the token)');
    const logo = await call('GET', '/logo.svg');
    ok(logo.status === 200 && /image\/svg\+xml/.test(logo.headers['content-type']), 'the dashboard serves its logo');
    const j = await call('GET', '/api/state', null, { cookie: '' });
    ok(/Session expired/.test(JSON.parse(j.body).error));
  });
  await test('token link sets a SameSite=Strict cookie', async () => {
    const r = await call('GET', `/?token=${token}`, null, { cookie: '' });
    eq(r.status, 302);
    ok(/SameSite=Strict/.test(r.headers['set-cookie'][0]) && /HttpOnly/.test(r.headers['set-cookie'][0]));
  });
  await test('rules: create, loop protection, start proxy, self-test, delete', async () => {
    store.save({ ...store.load(), rules: [] });
    let r = await call('POST', '/api/rules', { hostInput: 'https://loop.test.local', upstreamHost: '127.0.0.1', upstreamPort: 443 });
    eq(r.status, 400);
    ok(/itself|loop/i.test(JSON.parse(r.body).error), r.body);
    r = await call('POST', '/api/rules', { hostInput: 'https://api2.test.local:18444', upstreamHost: '127.0.0.1', upstreamScheme: 'http', upstreamPort: 19080 });
    eq(r.status, 200, r.body);
    const id = JSON.parse(r.body).rule.id;
    r = await call('POST', '/api/proxy/start');
    eq(r.status, 200, r.body);
    ok(JSON.parse(r.body).proxy.running);
    r = await call('POST', `/api/rules/${id}/test`);
    const t = JSON.parse(r.body);
    ok(t.corsOk, r.body);
    eq(t.preflight.status, 204);
    eq(t.actual.status, 200);
    eq(t.actual.trusted, true, 'certificate chains to the generated CA');
    eq(t.path, '/');
    r = await call('POST', '/api/rules', { id, hostInput: 'https://api2.test.local:18444', testPath: '/v1/health' });
    eq(r.status, 200, r.body);
    r = await call('POST', `/api/rules/${id}/test`);
    eq(JSON.parse(r.body).path, '/v1/health');
    ok(JSON.parse(r.body).actual.body.includes('"url":"/v1/health"'), 'the test request used the test path');
    await call('POST', '/api/proxy/stop');
    r = await call('DELETE', `/api/rules/${id}`);
    eq(JSON.parse(r.body).state.rules.length, 0);
  });
  await test('certificate download formats', async () => {
    const pem = await call('GET', `/api/certs/${ca.id}/download?format=pem`);
    ok(pem.body.startsWith('-----BEGIN CERTIFICATE-----'));
    const and = await call('GET', `/api/certs/${ca.id}/download?format=android`);
    ok(/filename="[0-9a-f]{8}\.0"/.test(and.headers['content-disposition']));
    const cer = await call('GET', `/api/certs/${ca.id}/download?format=cer`);
    eq(cer.status, 200);
  });
  await test('Android helper drives adb correctly (fake adb)', async () => {
    if (process.platform === 'win32') return console.log('       (skipped on Windows)');
    const fake = path.join(tmp, 'fake');
    fs.mkdirSync(path.join(fake, 'pushed'), { recursive: true });
    fs.writeFileSync(path.join(fake, 'hosts'), '127.0.0.1 localhost\n');
    const script = `#!/bin/bash
D="${fake}"
echo "$@" >> "$D/calls.log"
if [ "$1" = "devices" ]; then printf 'List of devices attached\\nemulator-5554\\tdevice product:sdk model:sdk_gphone64 device:emu transport_id:1\\n'; exit 0; fi
if [ "$1" = "-s" ]; then shift 2; fi
case "$1" in
  root) echo "adbd is already running as root";;
  wait-for-device) ;;
  push) cp "$2" "$D/pushed/$(basename "$3")"; echo "1 file pushed";;
  shell)
    case "$2" in
      *getprop*) printf '14\\n34\\n1\\nuserdebug\\n';;
      "id -u") echo 0;;
      "cat /system/etc/hosts") cat "$D/hosts";;
      "sh /data/local/tmp/cb-hosts-apply.sh") cp "$D/pushed/cb-hosts" "$D/hosts"; echo applied;;
      "sh /data/local/tmp/cb-install-ca.sh") touch "$D/installed"; echo installed;;
      "sh /data/local/tmp/cb-remove-ca.sh") rm -f "$D/installed"; echo removed;;
      "sh /data/local/tmp/cb-hosts-remove.sh") printf '127.0.0.1 localhost\\n' > "$D/hosts"; echo removed;;
      ls*) [ -f "$D/installed" ] && echo "\${2#ls }" || exit 1;;
      *) ;;
    esac;;
esac
`;
    fs.writeFileSync(path.join(fake, 'adb'), script, { mode: 0o755 });
    process.env.ADB = path.join(fake, 'adb');
    let r = await call('GET', '/api/android/devices');
    const list = JSON.parse(r.body);
    eq(list.devices.length, 1);
    eq(list.devices[0].rootable, true);
    eq(list.devices[0].sdk, 34);
    r = await call('POST', '/api/android/install-ca', { serial: 'emulator-5554', caId: ca.id });
    eq(r.status, 200, r.body);
    const hash = certs.androidFileName(certs.firstPem(ca.id));
    ok(fs.existsSync(path.join(fake, 'pushed', hash)), 'certificate pushed under its hash name');
    const sh = fs.readFileSync(path.join(fake, 'pushed', 'cb-install-ca.sh'), 'utf8');
    ok(sh.includes(`CERT=/data/local/tmp/${hash}`) && sh.includes('mount -t tmpfs') && sh.includes('conscrypt'));
    store.save({ ...store.load(), rules: [store.normalizeRule({ hostInput: 'https://api.test.local', upstreamHost: '203.0.113.5', upstreamPort: 443 })] });
    r = await call('POST', '/api/android/apply-hosts', { serial: 'emulator-5554' });
    eq(r.status, 200, r.body);
    const h = fs.readFileSync(path.join(fake, 'hosts'), 'utf8');
    ok(h.includes('127.0.0.1 localhost') && h.includes('10.0.2.2 api.test.local'), h);
  });
  await test('Android: device list shows what is installed; setup and undo run both steps', async () => {
    if (process.platform === 'win32') return console.log('       (skipped on Windows)');
    const fake = path.join(tmp, 'fake');
    const hash = certs.androidFileName(certs.firstPem(ca.id));
    let d = JSON.parse((await call('GET', '/api/android/devices')).body).devices[0];
    ok(d.caInstalled.includes(ca.id), 'CA from the previous test is detected');
    eq(d.hostsEntries.map((e) => `${e.ip} ${e.host}`).join(), '10.0.2.2 api.test.local');
    let r = await call('POST', '/api/devices/undo', { platform: 'android', id: 'emulator-5554' });
    eq(r.status, 200, r.body);
    ok(!fs.existsSync(path.join(fake, 'installed')) && !fs.readFileSync(path.join(fake, 'hosts'), 'utf8').includes('api.test.local'));
    ok(fs.readFileSync(path.join(fake, 'pushed', 'cb-remove-ca.sh'), 'utf8').includes('umount $APEX'));
    d = JSON.parse((await call('GET', '/api/android/devices')).body).devices[0];
    eq(d.caInstalled.length, 0);
    eq(d.hostsEntries.length, 0);
    r = await call('POST', '/api/devices/setup', { platform: 'android', id: 'emulator-5554' });
    eq(r.status, 200, r.body);
    const out = JSON.parse(r.body);
    ok(out.steps.some((s) => /trust store/.test(s.label)) && out.steps.some((s) => /redirect/i.test(s.label)), r.body);
    ok(fs.existsSync(path.join(fake, 'pushed', hash)));
    d = JSON.parse((await call('GET', '/api/android/devices')).body).devices[0];
    ok(d.caInstalled.includes(ca.id) && d.hostsEntries.length === 1);
  });
  await test('iOS: setup remembers the CA per simulator and applies the Mac redirect; undo reverses both (fake xcrun)', async () => {
    if (process.platform === 'win32') return console.log('       (skipped on Windows)');
    const fx = path.join(tmp, 'fakexcrun');
    fs.mkdirSync(fx);
    fs.writeFileSync(path.join(fx, 'xcrun'), `#!/bin/bash
echo "$@" >> "${fx}/calls.log"
if [ "$3" = "devices" ]; then echo '{"devices":{"com.apple.CoreSimulator.SimRuntime.iOS-18-0":[{"udid":"SIM-1","name":"iPhone 16","state":"Booted"},{"udid":"SIM-2","name":"iPad","state":"Shutdown"}]}}'; fi
exit 0
`, { mode: 0o755 });
    const before = process.env.XCRUN;
    process.env.XCRUN = path.join(fx, 'xcrun');
    try {
      let list = JSON.parse((await call('GET', '/api/ios/devices')).body);
      eq(list.devices.length, 1);
      eq(list.devices[0].caInstalled.length, 0);
      let r = await call('POST', '/api/devices/setup', { platform: 'ios', id: 'SIM-1', caId: ca.id });
      eq(r.status, 200, r.body);
      ok(fs.readFileSync(path.join(fx, 'calls.log'), 'utf8').includes('simctl keychain SIM-1 add-root-cert'));
      eq(JSON.parse(r.body).state.hosts.entries.map((e) => e.host).join(), 'api.test.local');
      list = JSON.parse((await call('GET', '/api/ios/devices')).body);
      eq(list.devices[0].caInstalled.join(), ca.id, 'remembered in the config');
      ok(store.load().devices.ios['SIM-1'].caIds.includes(ca.id));
      r = await call('POST', '/api/devices/undo', { platform: 'ios', id: 'SIM-1' });
      eq(r.status, 200, r.body);
      ok(fs.readFileSync(path.join(fx, 'calls.log'), 'utf8').includes('simctl keychain SIM-1 reset'));
      eq(JSON.parse(r.body).state.hosts.entries.length, 0);
      eq(store.load().devices.ios['SIM-1'], undefined);
      r = await call('POST', '/api/devices/setup', { platform: 'pager', id: 'x' });
      eq(r.status, 400);
    } finally {
      if (before === undefined) delete process.env.XCRUN;
      else process.env.XCRUN = before;
    }
  });
  await test('groups: same address in dev and uat, one group on at a time', async () => {
    store.save({ ...store.load(), rules: [] });
    let r = await call('POST', '/api/rules', { hostInput: 'https://grp.test.local', upstreamHost: '203.0.113.10', group: 'dev' });
    eq(r.status, 200, r.body);
    r = await call('POST', '/api/rules', { hostInput: 'https://grp.test.local', upstreamHost: '203.0.113.20', group: 'uat' });
    eq(r.status, 400, 'both on at once is refused');
    ok(/Pause it first|switch groups/.test(JSON.parse(r.body).error), r.body);
    r = await call('POST', '/api/rules', { hostInput: 'https://grp.test.local', upstreamHost: '203.0.113.20', group: 'uat', enabled: false });
    eq(r.status, 200, r.body);
    r = await call('POST', '/api/rules', { hostInput: 'https://grp.test.local', upstreamHost: '203.0.113.30', group: 'dev', enabled: false });
    eq(r.status, 400, 'two rules for one address in the same group are refused');
    r = await call('POST', '/api/groups', { group: 'uat', enabled: true });
    eq(r.status, 200, r.body);
    const out = JSON.parse(r.body);
    eq(out.paused.length, 1);
    const on = out.state.rules.filter((x) => x.enabled);
    eq(on.length, 1);
    eq(on[0].group, 'uat');
    eq((await call('POST', '/api/groups', { group: 'nope', enabled: true })).status, 400);
  });
  await test('export and import rules and settings', async () => {
    await call('POST', '/api/settings', { androidHostIp: '10.0.3.2', allowLan: false });
    let r = await call('GET', '/api/export');
    eq(r.status, 200);
    ok(/attachment; filename="cors-bridge-rules-/.test(r.headers['content-disposition']));
    const data = JSON.parse(r.body);
    eq(data.app, 'cors-bridge');
    eq(data.rules.length, 2);
    eq(data.settings.androidHostIp, '10.0.3.2');
    ok(!('allowLan' in data.settings), 'network exposure is not shared');
    ok(!('certId' in data.rules[0]) && !('id' in data.rules[0]), 'local ids are not exported');
    eq((await call('POST', '/api/import', { data: { hello: 1 } })).status, 400);
    // merge: same address + group updates the rule in place instead of adding a copy
    data.rules[0].note = 'from a teammate';
    r = await call('POST', '/api/import', { data, mode: 'merge' });
    let out = JSON.parse(r.body);
    eq(r.status, 200, r.body);
    eq(out.added, 0);
    eq(out.updated, 2);
    eq(out.state.rules.length, 2);
    ok(out.state.rules.some((x) => x.note === 'from a teammate'));
    // replace on an empty setup, plus one broken rule that is skipped with a warning
    store.save({ ...store.load(), rules: [] });
    await call('POST', '/api/settings', { androidHostIp: '10.0.2.2' });
    r = await call('POST', '/api/import', { data: { ...data, rules: [...data.rules, { host: 'bad host!', upstreamHost: '1.2.3.4' }] }, mode: 'replace' });
    out = JSON.parse(r.body);
    eq(out.added, 2);
    eq(out.warnings.length, 1);
    ok(/skipped/.test(out.warnings[0]), out.warnings[0]);
    eq(out.state.settings.androidHostIp, '10.0.3.2');
    eq(out.state.rules.filter((x) => x.enabled).length, 0, 'imported rules arrive paused');
  });
  await test('import preview: nothing is saved, risky rules are flagged, bad header values are refused', async () => {
    store.save({ ...store.load(), rules: [] });
    const file = {
      app: 'cors-bridge',
      format: 1,
      settings: { autoStartProxy: true },
      rules: [
        { enabled: true, host: 'login.test.local', scheme: 'https', listenPort: 443, upstreamHost: '198.51.100.7', upstreamScheme: 'https', upstreamPort: 443, verifyUpstream: false, cors: { origin: 'reflect', policy: 2 } },
        { enabled: true, host: 'plain.test.local', scheme: 'https', listenPort: 443, upstreamHost: '198.51.100.8', upstreamScheme: 'http', upstreamPort: 80 },
        { enabled: true, host: 'inject.test.local', scheme: 'https', listenPort: 443, upstreamHost: '198.51.100.9', cors: { origin: 'custom', customOrigin: 'https://a.example\r\nSet-Cookie: x=1' } },
      ],
    };
    let r = await call('POST', '/api/import', { data: file, mode: 'merge', dryRun: true });
    eq(r.status, 200, r.body);
    const plan = JSON.parse(r.body);
    eq(store.load().rules.length, 0, 'a preview saves nothing');
    eq(store.load().settings.autoStartProxy, false);
    eq(plan.plan.length, 3);
    eq(plan.plan[0].upstream, 'https://198.51.100.7:443', 'the preview shows where each address goes');
    ok(plan.plan[0].warnings.some((w) => /certificate/.test(w)) && plan.plan[0].warnings.some((w) => /any website/i.test(w)), JSON.stringify(plan.plan[0]));
    ok(plan.plan[1].warnings.some((w) => /unencrypted/.test(w)));
    eq(plan.plan[2].action, 'skip');
    ok(/valid origin/.test(plan.plan[2].warnings[0]), plan.plan[2].warnings[0]);
    eq(plan.settings[0].name, 'autoStartProxy');
    r = await call('POST', '/api/import', { data: file, mode: 'merge' });
    const out = JSON.parse(r.body);
    eq(out.added, 2);
    ok(out.state.rules.every((x) => !x.enabled), 'nothing from the file is switched on');
    // files from older versions stored "reflect" as the default; they come in as "your app" origins
    r = await call('POST', '/api/import', { data: { ...file, rules: [{ host: 'old.test.local', upstreamHost: '198.51.100.10', cors: { origin: 'reflect' } }] }, mode: 'merge' });
    eq(JSON.parse(r.body).state.rules.find((x) => x.host === 'old.test.local').cors.origin, 'app');
    store.save({ ...store.load(), rules: [] });
  });
  await test('LAN access needs a list of device addresses', async () => {
    let r = await call('POST', '/api/settings', { allowLan: true, lanClients: '' });
    eq(r.status, 400);
    r = await call('POST', '/api/settings', { allowLan: true, lanClients: '192.168.1.20\r\nx' });
    eq(r.status, 400);
    r = await call('POST', '/api/settings', { allowLan: true, lanClients: '192.168.1.20, 192.168.1.21' });
    eq(r.status, 200, r.body);
    eq(JSON.parse(r.body).settings.lanClients.join(), '192.168.1.20,192.168.1.21');
    const { clientAllowed } = require('../lib/proxy');
    const st = store.load().settings;
    ok(clientAllowed(st, '127.0.0.1') && clientAllowed(st, '::ffff:192.168.1.20'));
    ok(!clientAllowed(st, '192.168.1.99'), 'other devices on the network stay out');
    ok(!clientAllowed({ ...st, allowLan: false }, '192.168.1.20'));
    await call('POST', '/api/settings', { allowLan: false });
  });
  await test('shell scripts are plain LF with no unexpanded template markers', async () => {
    const { caScript, caRemoveScript, hostsBindScript } = require('../lib/devices');
    for (const s of [caScript('abcd1234.0'), caRemoveScript(), hostsBindScript()]) ok(!s.includes('\r') && !s.includes('${') && s.startsWith('#!/system/bin/sh'));
  });

  console.log('\nStartup and shutdown');
  await test('closing the terminal window removes the hosts redirect; LAN access is off after a restart', async () => {
    if (process.platform === 'win32') return console.log('       (skipped on Windows)');
    const home = path.join(tmp, 'life');
    const hostsFile = path.join(tmp, 'life-hosts');
    fs.mkdirSync(home);
    fs.writeFileSync(path.join(home, 'config.json'), JSON.stringify({ settings: { allowLan: true, lanClients: ['192.168.1.20'] }, rules: [] }));
    fs.writeFileSync(hostsFile, hosts.buildContent('127.0.0.1 localhost\n', [{ ip: '127.0.0.1', host: 'api.test.local' }]));
    const { spawn } = require('child_process');
    const child = spawn(process.execPath, [path.join(__dirname, '..', 'server.js'), '--no-open'], {
      env: { ...process.env, CORS_BRIDGE_HOME: home, CORS_BRIDGE_HOSTS_FILE: hostsFile, CORS_BRIDGE_UI_PORT: '17891' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let outText = '';
    child.stdout.on('data', (d) => (outText += d));
    child.stderr.on('data', (d) => (outText += d));
    await new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error(`did not start: ${outText}`)), 10000);
      child.stdout.on('data', () => outText.includes('Dashboard:') && (clearTimeout(t), resolve()));
    });
    eq(JSON.parse(fs.readFileSync(path.join(home, 'config.json'), 'utf8')).settings.allowLan, false);
    const exited = new Promise((resolve) => child.on('exit', resolve));
    child.kill('SIGHUP');
    await exited;
    eq(fs.readFileSync(hostsFile, 'utf8'), '127.0.0.1 localhost\n', outText);
  });

  api.close();
  upstream.close();
  console.log(`\n${passed} passed, ${failed} failed\n`);
  process.exit(failed ? 1 : 0);
})();
