'use strict';
const fs = require('fs');
const crypto = require('crypto');
const net = require('net');
const P = require('./paths');
const { UserError, atomicWrite } = require('./util');

const DEFAULT_CORS = {
  policy: 2, // 2 = "app" exists; older saved rules used "reflect" as the default and are moved to "app"
  origin: 'app', // app = the app's own origins (+ customOrigin list) | custom = only the list | reflect = any origin | *
  customOrigin: '', // extra allowed origins, separated by commas or spaces
  credentials: true,
  methods: 'reflect', // reflect = standard list, or a custom comma list
  headers: 'reflect', // reflect = echo Access-Control-Request-Headers, or a custom list
  exposeHeaders: 'auto', // auto = every response header, '' = none, or a custom list
  maxAge: 86400,
  handlePreflight: true, // answer OPTIONS preflights locally
  overrideUpstream: true, // replace any CORS headers the server sends
  privateNetwork: true, // answer Chrome's Private Network Access preflight
};

const DEFAULT_SETTINGS = {
  uiPort: 7777,
  allowLan: false, // false = only this computer can use the proxy
  cleanupHostsOnExit: true,
  lanClients: [], // IP addresses allowed in when allowLan is on
  autoStartProxy: false,
  androidHostIp: '10.0.2.2', // how the Android emulator reaches this computer
  logLimit: 500,
  settingsVersion: 2,
};

const HOST_RE =
  /^(?=.{1,253}$)[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$/i;

const ORIGIN_MODES = ['app', 'custom', 'reflect', '*'];
const ORIGIN_RE = /^(null|[a-z][a-z0-9+.-]*:\/\/(\[[0-9a-f:.]+\]|[a-z0-9_.-]+)(:\d{1,5})?)$/;
const TOKEN_RE = /^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/;

// Every value here ends up in a response header, so line breaks or other odd characters must never get through.
// strict = throw a readable error (input from the dashboard or an imported file); otherwise fall back to the default.
function cleanOrigins(v, strict) {
  const list = String(v || '')
    .split(/[\s,]+/)
    .map((x) => x.trim().toLowerCase().replace(/\/+$/, ''))
    .filter(Boolean);
  const bad = list.find((x) => !ORIGIN_RE.test(x));
  if (bad && strict) throw new UserError(`"${bad.slice(0, 80)}" is not a valid origin. Write it as scheme://host:port, for example http://localhost:8100.`);
  return [...new Set(list.filter((x) => ORIGIN_RE.test(x)))].join(', ');
}

function cleanTokens(v, keep, label, strict, fallback) {
  const raw = String(v == null ? fallback : v).trim();
  if (keep.includes(raw)) return raw;
  const list = raw.split(',').map((x) => x.trim()).filter(Boolean);
  const bad = list.find((x) => !TOKEN_RE.test(x));
  if (bad !== undefined) {
    if (strict) throw new UserError(`${label}: "${bad.slice(0, 60)}" is not a valid name. Separate names with commas.`.replace(/[\r\n]+/g, ' '));
    return fallback;
  }
  return list.join(', ') || fallback;
}

function normalizeCors(c = {}, { strict = false } = {}) {
  const o = { ...DEFAULT_CORS, ...c };
  const out = { policy: 2 };
  if (!ORIGIN_MODES.includes(o.origin)) {
    if (strict) throw new UserError('Pick which origins are allowed.');
    o.origin = 'app';
  }
  out.origin = o.origin;
  out.customOrigin = cleanOrigins(o.customOrigin, strict);
  if (out.origin === 'custom' && !out.customOrigin) {
    if (strict) throw new UserError('Enter at least one allowed origin, for example http://localhost:8100.');
    out.origin = 'app';
  }
  out.credentials = !!o.credentials && out.origin !== '*'; // browsers reject '*' with credentials
  out.methods = cleanTokens(o.methods, ['reflect'], 'Allowed methods', strict, 'reflect');
  out.headers = cleanTokens(o.headers, ['reflect', '*'], 'Allowed headers', strict, 'reflect');
  out.exposeHeaders = cleanTokens(o.exposeHeaders, ['auto', '', '*'], 'Exposed headers', strict, 'auto');
  const age = parseInt(o.maxAge, 10);
  out.maxAge = Number.isFinite(age) ? Math.min(Math.max(age, 0), 86400) : 86400;
  out.handlePreflight = !!o.handlePreflight;
  out.overrideUpstream = !!o.overrideUpstream;
  out.privateNetwork = !!o.privateNetwork;
  return out;
}

// Rules saved by older versions (or exported by them) stored "reflect" as the default. Move those to "app".
function migrateCors(c) {
  if (c && typeof c === 'object' && c.policy !== 2 && (c.origin === undefined || c.origin === 'reflect')) return { ...c, origin: 'app', policy: 2 };
  return c;
}

// Version 1 saved "remove the hosts redirect on quit" as off for everyone. A redirect left behind sends the API
// host names to this computer after CORS Bridge is gone, so it is turned on once; people can still turn it off.
function migrateSettings(saved) {
  const s = { ...DEFAULT_SETTINGS, ...saved };
  if (saved.settingsVersion !== 2) {
    s.cleanupHostsOnExit = true;
    s.settingsVersion = 2;
  }
  return s;
}

function load() {
  P.ensureDirs();
  let cfg = {};
  try {
    cfg = JSON.parse(fs.readFileSync(P.CONFIG_FILE, 'utf8'));
  } catch {
    cfg = {};
  }
  return {
    version: 1,
    activeCaId: cfg.activeCaId || null,
    settings: migrateSettings(cfg.settings || {}),
    rules: (cfg.rules || []).map((r) => ({ ...r, group: r.group || '', testPath: r.testPath || '/', cors: normalizeCors(migrateCors(r.cors || {})) })),
    // What CORS Bridge installed on each device it cannot ask directly (iOS Simulator, by udid).
    devices: { ios: {}, ...(cfg.devices || {}) },
  };
}

function save(cfg) {
  P.ensureDirs();
  atomicWrite(P.CONFIG_FILE, JSON.stringify(cfg, null, 2));
}

const newId = () => crypto.randomBytes(5).toString('hex');

function parseHostInput(raw) {
  const s = String(raw || '').trim();
  if (!s) throw new UserError('Enter the API address, e.g. https://api.company.com');
  let scheme;
  let port;
  let host = s;
  if (/^[a-z]+:\/\//i.test(s)) {
    let u;
    try {
      u = new URL(s);
    } catch {
      throw new UserError(`"${s}" is not a valid address`);
    }
    scheme = u.protocol.replace(':', '');
    host = u.hostname;
    port = u.port ? Number(u.port) : scheme === 'https' ? 443 : scheme === 'http' ? 80 : undefined;
  } else {
    const m = /^([^:/]+):(\d+)$/.exec(s);
    if (m) {
      host = m[1];
      port = Number(m[2]);
    } else if (s.includes('/')) {
      host = s.split('/')[0];
    }
  }
  host = host.toLowerCase().replace(/^\[|\]$/g, '');
  if (host.startsWith('*.')) throw new UserError('Wildcards are not supported in rules. Add one rule per host name.');
  if (!net.isIP(host) && !HOST_RE.test(host)) throw new UserError(`"${host}" is not a valid host name`);
  return { host, scheme, port };
}

function toPort(v, label) {
  const n = parseInt(v, 10);
  if (!Number.isInteger(n) || n < 1 || n > 65535) throw new UserError(`${label} must be a number between 1 and 65535`);
  return n;
}

const blank = (v) => v === undefined || v === null || v === '';

function normalizeGroup(v) {
  const g = String(v || '').trim().toLowerCase().slice(0, 40);
  if (g && !/^[a-z0-9][a-z0-9 _.-]*$/.test(g)) throw new UserError('A group name can only use letters, numbers, spaces, dots, dashes and underscores.');
  return g;
}

function normalizeTestPath(v) {
  let p = String(v || '').trim() || '/';
  if (/^[a-z]+:\/\//i.test(p)) {
    try {
      const u = new URL(p);
      p = u.pathname + u.search;
    } catch {
      throw new UserError(`"${p}" is not a valid test path`);
    }
  }
  if (!p.startsWith('/')) p = `/${p}`;
  if (/[\s\x00-\x1f]/.test(p)) throw new UserError('The test path cannot contain spaces. Encode them as %20.');
  return p.slice(0, 500);
}

function normalizeRule(input, prev = {}) {
  const parsed = parseHostInput(blank(input.hostInput) ? input.host || prev.host : input.hostInput);
  const scheme = input.scheme || parsed.scheme || prev.scheme || 'https';
  if (!['http', 'https'].includes(scheme)) throw new UserError('Scheme must be http or https');
  const listenPort = toPort(
    !blank(input.listenPort) ? input.listenPort : parsed.port || prev.listenPort || (scheme === 'https' ? 443 : 80),
    'Listen port'
  );
  const upstreamScheme = input.upstreamScheme || prev.upstreamScheme || scheme;
  if (!['http', 'https'].includes(upstreamScheme)) throw new UserError('Upstream scheme must be http or https');
  const upstreamPort = toPort(
    !blank(input.upstreamPort) ? input.upstreamPort : prev.upstreamPort || listenPort,
    'Upstream port'
  );
  const upstreamHost = String(input.upstreamHost !== undefined ? input.upstreamHost : prev.upstreamHost || '').trim();
  return {
    id: prev.id || newId(),
    enabled: input.enabled !== undefined ? !!input.enabled : prev.enabled !== false,
    host: parsed.host,
    scheme,
    listenPort,
    upstreamHost,
    upstreamScheme,
    upstreamPort,
    verifyUpstream: input.verifyUpstream !== undefined ? !!input.verifyUpstream : prev.verifyUpstream !== false,
    stripOrigin: input.stripOrigin !== undefined ? !!input.stripOrigin : !!prev.stripOrigin,
    certId: input.certId !== undefined ? input.certId || null : prev.certId || null,
    note: String(input.note !== undefined ? input.note : prev.note || '').slice(0, 200),
    group: normalizeGroup(input.group !== undefined ? input.group : prev.group),
    testPath: normalizeTestPath(input.testPath !== undefined ? input.testPath : prev.testPath),
    cors: normalizeCors({ ...(prev.cors || {}), ...(input.cors || {}) }, { strict: true }),
  };
}

module.exports = { load, save, newId, normalizeRule, normalizeCors, migrateCors, cleanOrigins, normalizeGroup, normalizeTestPath, parseHostInput, DEFAULT_CORS, DEFAULT_SETTINGS };
