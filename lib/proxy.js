'use strict';
const http = require('http');
const https = require('https');
const tls = require('tls');
const net = require('net');
const { EventEmitter } = require('events');
const certs = require('./certs');
const { UserError, isIp, isLoopbackAddress } = require('./util');

const HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);
const NO_EXPOSE = new Set([...HOP, 'set-cookie', 'set-cookie2']);
const DEFAULT_METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'];

// Origins an Ionic/Capacitor/Cordova app uses: the native WebView schemes and dev servers on this computer
// (10.0.2.2 is this computer as seen from the Android emulator). Public websites can never send these.
const APP_ORIGIN_RE = /^(capacitor|ionic):\/\/localhost$|^https?:\/\/(localhost|127\.0\.0\.1|\[::1\]|10\.0\.2\.2)(:\d{1,5})?$/;
const listed = (rule, origin) => !!origin && rule.cors.customOrigin.split(/[\s,]+/).includes(origin.toLowerCase());
const isAppOrigin = (origin) => APP_ORIGIN_RE.test(String(origin || '').toLowerCase());

// Which Access-Control-Allow-Origin to send, or null when this origin gets no CORS headers.
function allowedOrigin(rule, origin) {
  const mode = rule.cors.origin;
  if (mode === '*') return '*';
  if (mode === 'reflect') return origin || '*';
  if (!origin) return null;
  if (listed(rule, origin)) return origin;
  if (mode === 'app' && isAppOrigin(origin)) return origin;
  return null;
}

// Certificates the real server may be signed by: Node's own list plus the OS trust store, where company CAs are
// usually installed. The single-file executable is not started with NODE_USE_SYSTEM_CA, so the OS store is read here.
// Needs Node 22.15+ / 23.10+; older versions keep Node's default list.
let upstreamCa;
function upstreamCaList() {
  if (upstreamCa === undefined) {
    upstreamCa = null;
    if (typeof tls.getCACertificates === 'function') {
      try {
        upstreamCa = [...new Set([...tls.getCACertificates('default'), ...tls.getCACertificates('system')])];
      } catch {
        upstreamCa = null;
      }
    }
  }
  return upstreamCa;
}

// This computer always; other devices only while "allow LAN" is on and only the IP addresses listed for it.
function clientAllowed(settings, addr) {
  if (isLoopbackAddress(addr)) return true;
  if (!settings.allowLan) return false;
  const ip = String(addr || '').replace(/^::ffff:/, '');
  return (settings.lanClients || []).includes(ip);
}

function mergeVary(existing, add) {
  const cur = Array.isArray(existing) ? existing.join(', ') : existing || '';
  if (cur.trim() === '*') return '*';
  const parts = cur.split(',').map((s) => s.trim()).filter(Boolean);
  if (!parts.some((p) => p.toLowerCase() === add.toLowerCase())) parts.push(add);
  return parts.join(', ');
}

// What the app and the live log are told when the real server is too slow.
const TIMEOUTS = {
  CB_CONNECT_TIMEOUT: {
    error: 'CORS Bridge could not reach the real server',
    detail: (s) => `No connection within ${s} seconds`,
    hint: 'Check that your VPN is connected and that the real server address in the rule is right.',
    note: (s) => `the real server did not accept a connection within ${s} s`,
  },
  CB_ANSWER_TIMEOUT: {
    error: 'The real server did not answer in time',
    detail: (s) => `Nothing received for ${s} seconds`,
    hint: 'The server may be busy or the request may take long. You can wait longer in Settings.',
    note: (s) => `the real server did not answer within ${s} s`,
  },
};
function timeoutError(code) {
  const e = new Error(code);
  e.code = code;
  return e;
}

// Secrets are shortened in the live log so the dashboard never shows a full token or cookie.
const SECRET = new Set(['authorization', 'proxy-authorization', 'cookie', 'set-cookie', 'x-api-key', 'x-auth-token']);
function logHeaders(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers || {})) {
    const val = Array.isArray(v) ? v.join(', ') : String(v);
    out[k] = SECRET.has(k) && val.length > 16 ? `${val.slice(0, 12)}... (${val.length} characters, hidden)` : val;
  }
  return out;
}

class ProxyEngine extends EventEmitter {
  constructor({ getRules, getSettings }) {
    super();
    this.getRules = getRules;
    this.getSettings = getSettings;
    this.servers = new Map();
    this.active = [];
    this.certIds = new Map();
    this.ctxCache = new Map();
    this.logs = [];
    this.seq = 0;
    this.running = false;
    this.lastError = null;
    this.agents = new Map(); // rule id -> keep-alive agent for the real server
  }

  // ------------------------------------------------------------ lifecycle

  async start() {
    if (this.running) return this.status();
    const rules = this.getRules().filter((r) => r.enabled);
    if (!rules.length) throw new UserError('Add and enable at least one rule first.');

    const schemeByPort = new Map();
    const seen = new Set();
    for (const r of rules) {
      const other = schemeByPort.get(r.listenPort);
      if (other && other !== r.scheme)
        throw new UserError(`Port ${r.listenPort} is used by both an http and an https rule. Pick different ports.`);
      schemeByPort.set(r.listenPort, r.scheme);
      const key = `${r.host}:${r.listenPort}`;
      if (seen.has(key)) throw new UserError(`There are two rules for ${r.host} on port ${r.listenPort}.`);
      seen.add(key);
      if (!r.upstreamHost) throw new UserError(`Rule for ${r.host} has no upstream address. Open it and click Resolve.`);
    }

    this.certIds.clear();
    this.ctxCache.clear();
    for (const r of rules) {
      if (r.scheme !== 'https') continue;
      let entry;
      if (r.certId) {
        entry = certs.get(r.certId);
        if (!entry || entry.kind !== 'leaf' || !entry.hasKey)
          throw new UserError(`The certificate chosen for ${r.host} is missing or has no private key.`);
      } else {
        entry = certs.ensureLeafForHost(r.host);
      }
      this.certIds.set(r.id, entry.id);
    }
    this.active = rules;

    const groups = new Map();
    for (const r of rules) {
      const key = `${r.scheme}:${r.listenPort}`;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(r);
    }
    try {
      for (const list of groups.values()) await this._listen(list[0].scheme, list[0].listenPort, list);
    } catch (e) {
      await this._closeAll();
      this.lastError = e.message;
      throw e;
    }
    this.running = true;
    this.lastError = null;
    this.emit('status', this.status()); // lets the dashboard and the tray menu follow along
    return this.status();
  }

  async stop() {
    await this._closeAll();
    const was = this.running;
    this.running = false;
    if (was) this.emit('status', this.status());
    return this.status();
  }

  async reload() {
    await this.stop();
    return this.start();
  }

  async _closeAll() {
    for (const agent of this.agents.values()) agent.destroy();
    this.agents.clear();
    const servers = [...this.servers.values()];
    this.servers.clear();
    await Promise.all(
      servers.map(
        (s) =>
          new Promise((resolve) => {
            const t = setTimeout(resolve, 1500);
            s.close(() => {
              clearTimeout(t);
              resolve();
            });
            if (s.closeAllConnections) s.closeAllConnections();
          })
      )
    );
  }

  status() {
    const listening = [];
    for (const [key, s] of this.servers) {
      const [scheme, port] = key.split(':');
      listening.push({
        scheme,
        port: Number(port),
        hosts: this.active.filter((r) => r.scheme === scheme && String(r.listenPort) === port).map((r) => r.host),
        address: s.address() && s.address().address,
      });
    }
    return { running: this.running, listening, error: this.lastError };
  }

  _listenError(err, port) {
    if (err.code === 'EADDRINUSE')
      return new UserError(
        `Port ${port} is already in use by another program (a web server, Docker, Skype or similar). Stop it, or choose a different listen port for the rule.`
      );
    if (err.code === 'EACCES')
      return new UserError(`Not allowed to listen on port ${port}. On Linux, ports below 1024 need admin rights. Try running with sudo, or use a higher port.`);
    return new UserError(`Could not listen on port ${port}: ${err.message}`);
  }

  _listen(scheme, port, rules) {
    return new Promise((resolve, reject) => {
      const handler = (req, res) => this._handle(req, res, scheme, port);
      let server;
      if (scheme === 'https') {
        const first = certs.tlsOptions(this.certIds.get(rules[0].id));
        server = https.createServer(
          {
            ...first,
            SNICallback: (servername, cb) => {
              try {
                cb(null, this._sniContext(servername, rules));
              } catch (e) {
                cb(e);
              }
            },
          },
          handler
        );
      } else {
        server = http.createServer(handler);
      }
      // Wildcard bind (needed for port 443 on macOS without sudo) but only this computer may connect,
      // unless the user explicitly allowed the LAN. The Android emulator's 10.0.2.2 arrives as 127.0.0.1.
      server.on('connection', (socket) => {
        if (!clientAllowed(this.getSettings(), socket.remoteAddress)) socket.destroy();
        socket.on('error', () => {});
      });
      server.on('upgrade', (req, socket, head) => this._upgrade(req, socket, head, scheme, port));
      server.on('tlsClientError', () => {});
      server.on('clientError', (err, socket) => {
        try {
          socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
        } catch {
          /* ignore */
        }
      });
      server.once('error', (err) => reject(this._listenError(err, port)));
      server.listen(port, '0.0.0.0', () => {
        server.removeAllListeners('error');
        server.on('error', (e) => {
          this.lastError = e.message;
        });
        this.servers.set(`${scheme}:${port}`, server);
        resolve();
      });
    });
  }

  _sniContext(servername, rules) {
    const sn = String(servername || '').toLowerCase();
    const rule = rules.find((r) => r.host === sn) || rules[0];
    const id = this.certIds.get(rule.id);
    if (!this.ctxCache.has(id)) this.ctxCache.set(id, tls.createSecureContext(certs.tlsOptions(id)));
    return this.ctxCache.get(id);
  }

  // ------------------------------------------------------------ logging

  _log(entry) {
    this.logs.push(entry);
    const limit = Math.max(50, Number(this.getSettings().logLimit) || 500);
    if (this.logs.length > limit) this.logs.splice(0, this.logs.length - limit);
    this.emit('log', entry);
  }

  clearLogs() {
    this.logs = [];
  }

  // ------------------------------------------------------------ routing

  _find(hostHeader, scheme, port) {
    const host = String(hostHeader || '')
      .toLowerCase()
      .replace(/:\d+$/, '')
      .replace(/^\[|\]$/g, '');
    return this.active.find((r) => r.host === host && r.scheme === scheme && r.listenPort === port) || null;
  }

  // ------------------------------------------------------------ CORS

  // Returns the CORS headers for this request, or null when the origin is not allowed by the rule.
  _corsHeaders(rule, req, upstreamHeaders, preflight) {
    const c = rule.cors;
    const origin = req.headers.origin;
    const allow = allowedOrigin(rule, origin);
    if (allow === null) return null;
    const h = { 'access-control-allow-origin': allow };
    if (allow !== '*') h.vary = 'Origin';
    if (c.credentials && allow !== '*') h['access-control-allow-credentials'] = 'true';
    if (preflight) {
      let methods = DEFAULT_METHODS;
      if (c.methods !== 'reflect') methods = c.methods.split(',').map((m) => m.trim().toUpperCase()).filter(Boolean);
      const wanted = String(req.headers['access-control-request-method'] || '').toUpperCase();
      if (c.methods === 'reflect' && wanted && !methods.includes(wanted)) methods = [...methods, wanted];
      h['access-control-allow-methods'] = methods.join(', ');
      const reqHeaders = req.headers['access-control-request-headers'];
      if (c.headers === 'reflect') {
        if (reqHeaders) h['access-control-allow-headers'] = reqHeaders;
      } else {
        h['access-control-allow-headers'] = c.headers;
      }
      h['access-control-max-age'] = String(c.maxAge);
      // Chrome asks this before a public website may call this computer. Only the app itself (or an origin
      // listed in the rule) gets a yes, even when the rule allows any origin.
      if (c.privateNetwork && req.headers['access-control-request-private-network'] === 'true' && (isAppOrigin(origin) || listed(rule, origin)))
        h['access-control-allow-private-network'] = 'true';
      h.vary = mergeVary(h.vary, 'Access-Control-Request-Headers');
    } else if (c.exposeHeaders === 'auto') {
      const names = Object.keys(upstreamHeaders || {}).filter((k) => !NO_EXPOSE.has(k) && !k.startsWith('access-control-'));
      if (names.length) h['access-control-expose-headers'] = names.join(', ');
    } else if (c.exposeHeaders) {
      h['access-control-expose-headers'] = c.exposeHeaders;
    }
    return h;
  }

  // Returns the headers that were added: null when the server's own CORS headers were kept,
  // {} when the origin is not allowed (any CORS headers from the server are removed too).
  _applyCors(rule, req, out) {
    if (!rule.cors.overrideUpstream && 'access-control-allow-origin' in out) return null;
    for (const k of Object.keys(out)) if (k.startsWith('access-control-')) delete out[k];
    const h = this._corsHeaders(rule, req, out, false);
    if (rule.cors.origin !== '*') out.vary = mergeVary(out.vary, 'Origin'); // the answer depends on Origin
    if (!h) return {};
    delete h.vary;
    Object.assign(out, h);
    return h;
  }

  // Node refuses some header values (for example with line breaks) by throwing, which would crash the app.
  // Check them first with Node's own rules and answer with a plain error instead.
  _safeWriteHead(res, status, statusMessage, headers, entry) {
    try {
      for (const [k, v] of Object.entries(headers)) {
        http.validateHeaderName(k);
        for (const one of Array.isArray(v) ? v : [v]) http.validateHeaderValue(k, one);
      }
    } catch (e) {
      res.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' });
      res.end(`CORS Bridge: a header could not be sent (${e.code || e.message}). Check the rule's CORS options.`);
      entry.note = `invalid header: ${e.code || e.message}`;
      return false;
    }
    if (statusMessage) res.writeHead(status, statusMessage, headers);
    else res.writeHead(status, headers);
    return true;
  }

  // ------------------------------------------------------------ requests

  _handle(req, res, scheme, port) {
    const start = Date.now();
    const rule = this._find(req.headers.host, scheme, port);
    const entry = {
      id: ++this.seq,
      ts: start,
      host: String(req.headers.host || ''),
      method: req.method,
      path: req.url,
      origin: req.headers.origin || '',
      status: 0,
      ms: 0,
      note: '',
      preflight: false,
      reqHeaders: logHeaders(req.headers),
      resHeaders: null, // as the real server sent them
      corsAdded: null,
    };
    let logged = false;
    const done = (status, note) => {
      if (logged) return;
      logged = true;
      entry.status = status;
      entry.ms = Date.now() - start;
      if (note) entry.note = note;
      this._log(entry);
    };

    if (!rule) {
      res.writeHead(404, { 'content-type': 'text/plain' });
      res.end(`CORS Bridge: no rule for host "${req.headers.host}"`);
      return done(404, 'no matching rule');
    }
    entry.host = rule.host;

    const isPreflight =
      req.method === 'OPTIONS' && req.headers.origin !== undefined && 'access-control-request-method' in req.headers;
    if (isPreflight && rule.cors.handlePreflight) {
      entry.preflight = true;
      const h = this._corsHeaders(rule, req, null, true);
      if (!h) {
        res.writeHead(403, { vary: 'Origin', 'content-type': 'text/plain', 'content-length': '0' });
        res.end();
        return done(403, `origin not allowed: ${req.headers.origin}. Add it to the rule's allowed origins.`);
      }
      entry.corsAdded = { ...h };
      h['content-length'] = '0';
      if (!this._safeWriteHead(res, 204, null, h, entry)) return done(500);
      res.end();
      return done(204, 'preflight answered by CORS Bridge');
    }

    const headers = {};
    for (const [k, v] of Object.entries(req.headers)) if (!HOP.has(k)) headers[k] = v;
    if (rule.stripOrigin) {
      delete headers.origin;
      delete headers.referer;
    }
    const secure = rule.upstreamScheme === 'https';
    const opts = {
      host: rule.upstreamHost,
      port: rule.upstreamPort,
      method: req.method,
      path: req.url,
      headers,
      setHost: false,
      agent: this._agentFor(rule),
    };
    if (secure) {
      if (!isIp(rule.host)) opts.servername = rule.host;
      opts.rejectUnauthorized = rule.verifyUpstream !== false;
      if (upstreamCaList()) opts.ca = upstreamCaList();
    }
    const { connectMs, answerMs } = this._timeouts();
    // A request without a body can be sent again if a kept-alive connection turns out to be closed already.
    const canRetry = ['GET', 'HEAD', 'OPTIONS', 'DELETE'].includes(req.method) && !req.headers['content-length'] && !req.headers['transfer-encoding'];
    let current = null;

    const onResponse = (ur) => {
      const out = {};
      for (const [k, v] of Object.entries(ur.headers)) if (!HOP.has(k)) out[k] = v;
      entry.resHeaders = logHeaders(ur.headers);
      entry.corsAdded = this._applyCors(rule, req, out);
      const notAllowed = entry.corsAdded && !Object.keys(entry.corsAdded).length && req.headers.origin !== undefined;
      if (!this._safeWriteHead(res, ur.statusCode, ur.statusMessage, out, entry)) {
        ur.resume();
        return done(500);
      }
      ur.pipe(res);
      ur.on('end', () => done(ur.statusCode, notAllowed ? `origin not allowed: ${req.headers.origin}. The app cannot read this answer.` : ''));
      ur.on('error', () => done(ur.statusCode, 'upstream response aborted'));
    };

    const fail = (e) => {
      const timeout = TIMEOUTS[e.code];
      const status = timeout ? 504 : 502;
      const hint = timeout
        ? timeout.hint
        : /CERT|SELF_SIGNED|UNABLE_TO_VERIFY/.test(e.code || '')
          ? 'The server certificate is not trusted by this computer. Untick "Verify the real server certificate" in the rule, or run Node with NODE_EXTRA_CA_CERTS pointing to your company CA.'
          : undefined;
      const seconds = Math.round((e.code === 'CB_CONNECT_TIMEOUT' ? connectMs : answerMs) / 100) / 10;
      const note = timeout ? timeout.note(seconds) : `upstream error: ${e.code || e.message}`;
      if (!res.headersSent) {
        const h = { 'content-type': 'application/json' };
        entry.corsAdded = this._corsHeaders(rule, req, null, false) || {};
        Object.assign(h, entry.corsAdded);
        if (rule.cors.origin !== '*') h.vary = 'Origin';
        if (!this._safeWriteHead(res, status, null, h, entry)) return done(500);
        res.end(
          JSON.stringify({
            error: timeout ? timeout.error : 'CORS Bridge could not reach the real server',
            detail: timeout ? timeout.detail(seconds) : e.code || e.message,
            upstream: `${rule.upstreamScheme}://${rule.upstreamHost}:${rule.upstreamPort}`,
            hint,
          })
        );
      } else {
        res.destroy(); // the answer had already started, so the only honest signal left is to cut it off
      }
      done(status, note);
    };

    const send = (attempt) => {
      const upstream = (secure ? https : http).request(opts, onResponse);
      current = upstream;
      let connectTimer = null;
      upstream.on('socket', (sock) => {
        if (!sock.connecting) return; // a kept-alive connection is already open
        connectTimer = setTimeout(() => upstream.destroy(timeoutError('CB_CONNECT_TIMEOUT')), connectMs);
        sock.once(secure ? 'secureConnect' : 'connect', () => clearTimeout(connectTimer));
      });
      // No byte from the real server for this long: waiting for the answer, or in the middle of it.
      upstream.setTimeout(answerMs, () => upstream.destroy(timeoutError('CB_ANSWER_TIMEOUT')));
      upstream.on('error', (e) => {
        clearTimeout(connectTimer);
        if (attempt === 0 && canRetry && upstream.reusedSocket && e.code === 'ECONNRESET' && !res.headersSent) return send(1);
        fail(e);
      });
      if (attempt === 0) req.pipe(upstream);
      else upstream.end();
    };

    req.on('aborted', () => current && current.destroy());
    res.on('close', () => {
      if (!res.writableEnded && current) current.destroy();
    });
    send(0);
  }

  // One keep-alive connection pool per rule, so requests to the real server skip a new TCP and TLS handshake.
  _agentFor(rule) {
    let agent = this.agents.get(rule.id);
    if (!agent) {
      const Agent = rule.upstreamScheme === 'https' ? https.Agent : http.Agent;
      agent = new Agent({ keepAlive: true, keepAliveMsecs: 15000, maxSockets: 64, maxFreeSockets: 16, scheduling: 'lifo' });
      this.agents.set(rule.id, agent);
    }
    return agent;
  }

  // Settings are in seconds; tests may use fractions.
  _timeouts() {
    const s = this.getSettings();
    const sec = (v, d) => (Number(v) > 0 ? Number(v) : d);
    return { connectMs: sec(s.connectTimeoutSec, 10) * 1000, answerMs: sec(s.answerTimeoutSec, 120) * 1000 };
  }

  _upgrade(req, socket, head, scheme, port) {
    const rule = this._find(req.headers.host, scheme, port);
    const entry = {
      id: ++this.seq,
      ts: Date.now(),
      host: rule ? rule.host : String(req.headers.host || ''),
      method: 'WS',
      path: req.url,
      origin: req.headers.origin || '',
      status: 101,
      ms: 0,
      note: 'WebSocket passed through',
      preflight: false,
    };
    if (!rule) {
      socket.destroy();
      return;
    }
    const secure = rule.upstreamScheme === 'https';
    let up;
    const onConnect = () => {
      let raw = `${req.method} ${req.url} HTTP/${req.httpVersion}\r\n`;
      for (let i = 0; i < req.rawHeaders.length; i += 2) {
        if (rule.stripOrigin && /^(origin|referer)$/i.test(req.rawHeaders[i])) continue;
        raw += `${req.rawHeaders[i]}: ${req.rawHeaders[i + 1]}\r\n`;
      }
      up.write(`${raw}\r\n`);
      if (head && head.length) up.write(head);
      socket.pipe(up);
      up.pipe(socket);
      this._log(entry);
    };
    if (secure) {
      up = tls.connect(
        {
          host: rule.upstreamHost,
          port: rule.upstreamPort,
          servername: isIp(rule.host) ? undefined : rule.host,
          rejectUnauthorized: rule.verifyUpstream !== false,
          ca: upstreamCaList() || undefined,
        },
        onConnect
      );
    } else {
      up = net.connect({ host: rule.upstreamHost, port: rule.upstreamPort }, onConnect);
    }
    const { connectMs } = this._timeouts();
    const connectTimer = setTimeout(() => up.destroy(), connectMs);
    up.once(secure ? 'secureConnect' : 'connect', () => clearTimeout(connectTimer));
    up.on('close', () => clearTimeout(connectTimer));
    up.on('error', () => socket.destroy());
    socket.on('error', () => up.destroy());
    socket.on('close', () => up.destroy());
    up.on('close', () => socket.destroy());
  }
}

module.exports = { ProxyEngine, clientAllowed, mergeVary, logHeaders, allowedOrigin, isAppOrigin };
