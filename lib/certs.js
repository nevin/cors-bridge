'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const der = require('./der');
const P = require('./paths');
const store = require('./store');
const { UserError, atomicWrite } = require('./util');

const PEM_CERT_RE = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g;
const DAY = 86400000;
const HOST_RE =
  /^(\*\.)?[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$/i;

const newId = () => crypto.randomBytes(6).toString('hex');
const certFile = (id) => path.join(P.CERT_DIR, `${id}.crt`);
const keyFile = (id) => path.join(P.CERT_DIR, `${id}.key`);

function readIndex() {
  try {
    return JSON.parse(fs.readFileSync(P.CERT_INDEX, 'utf8'));
  } catch {
    return [];
  }
}
function writeIndex(list) {
  P.ensureDirs();
  atomicWrite(P.CERT_INDEX, JSON.stringify(list, null, 2), 0o600);
}
const readChain = (id) => fs.readFileSync(certFile(id), 'utf8');
function readKey(id) {
  try {
    return fs.readFileSync(keyFile(id), 'utf8');
  } catch {
    return null;
  }
}
const splitPem = (pem) => String(pem || '').match(PEM_CERT_RE) || [];
const oneLine = (s) => String(s || '').split('\n').filter(Boolean).reverse().join(', ');

// ---------------------------------------------------------------- inspection

function inspect(pem) {
  const x = new crypto.X509Certificate(pem);
  const cn = (/^CN=(.*)$/m.exec(x.subject) || [])[1] || '';
  const sans = (x.subjectAltName || '')
    .split(/,\s*/)
    .map((s) => s.trim().replace(/^DNS:/, '').replace(/^IP Address:/, '').replace(/^"|"$/g, ''))
    .filter(Boolean);
  return {
    subject: oneLine(x.subject),
    cn,
    issuer: oneLine(x.issuer),
    selfSigned: x.subject === x.issuer,
    isCa: !!x.ca,
    names: sans.length ? sans : cn ? [cn] : [],
    notBefore: new Date(x.validFrom).toISOString(),
    notAfter: new Date(x.validTo).toISOString(),
    fingerprint256: x.fingerprint256,
  };
}

function hostMatches(names, host) {
  host = String(host).toLowerCase();
  return names.some((n) => {
    n = n.toLowerCase();
    if (n.startsWith('*.')) {
      const rest = n.slice(1); // ".example.com"
      return host.endsWith(rest) && host.split('.').length === n.split('.').length;
    }
    return n === host;
  });
}

function describe(entry, activeCaId) {
  try {
    const info = inspect(splitPem(readChain(entry.id))[0]);
    const left = Date.parse(info.notAfter) - Date.now();
    return {
      ...entry,
      hasKey: fs.existsSync(keyFile(entry.id)),
      isActive: entry.id === activeCaId,
      status: left < 0 ? 'expired' : left < 30 * DAY ? 'expiring' : 'valid',
      daysLeft: Math.floor(left / DAY),
      ...info,
    };
  } catch (e) {
    return { ...entry, status: 'unreadable', error: e.message, names: [] };
  }
}

// ---------------------------------------------------------------- keys

function parsePrivateKey(pem, passphrase) {
  if (!passphrase && /ENCRYPTED/.test(pem)) throw new UserError('The private key is encrypted. Enter its passphrase.');
  try {
    return crypto.createPrivateKey({ key: pem, passphrase: passphrase || undefined });
  } catch (e) {
    if (e.code === 'ERR_MISSING_PASSPHRASE') throw new UserError('The private key is encrypted. Enter its passphrase.');
    if (/bad decrypt|BAD_DECRYPT|interrupted or cancelled/i.test(`${e.code} ${e.message}`))
      throw new UserError('Wrong passphrase for the private key.');
    throw new UserError(`Could not read the private key: ${e.message}`);
  }
}
const exportKey = (keyObj) => keyObj.export({ type: 'pkcs8', format: 'pem' });

function genKey() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048, publicExponent: 0x10001 });
  return {
    pem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    keyObj: privateKey,
    spkiDer: publicKey.export({ type: 'spki', format: 'der' }),
  };
}

function serial() {
  const b = crypto.randomBytes(16);
  b[0] &= 0x7f;
  if (b[0] === 0) b[0] = 1;
  return b.toString('hex');
}

function saveEntry(entry, chainPem, keyPem) {
  P.ensureDirs();
  atomicWrite(certFile(entry.id), chainPem.endsWith('\n') ? chainPem : `${chainPem}\n`, 0o644);
  if (keyPem) atomicWrite(keyFile(entry.id), keyPem, 0o600);
  const idx = readIndex();
  idx.push(entry);
  writeIndex(idx);
}

// ---------------------------------------------------------------- generation

function generateCa({ name, days = 3650 } = {}) {
  const id = newId();
  const label = (name || 'CORS Bridge Dev CA').trim();
  const cn = `${label} ${id.slice(0, 4).toUpperCase()}`; // unique subject => unique Android file name
  const { pem, keyObj, spkiDer } = genKey();
  const subjectDer = der.name([
    [der.OID.commonName, cn],
    [der.OID.organizationName, 'CORS Bridge (local development only)'],
  ]);
  const certPem = der.buildCertificate({
    serialHex: serial(),
    issuerDer: subjectDer,
    subjectDer,
    notBefore: new Date(Date.now() - DAY),
    notAfter: new Date(Date.now() + days * DAY),
    spkiDer,
    isCa: true,
    signerKey: keyObj,
  });
  saveEntry(
    { id, kind: 'ca', origin: 'generated', name: label, createdAt: new Date().toISOString(), canSign: true },
    certPem,
    pem
  );
  const cfg = store.load();
  if (!cfg.activeCaId) {
    cfg.activeCaId = id;
    store.save(cfg);
  }
  return get(id);
}

function validateHostName(h) {
  if (!(require('net').isIP(h) || HOST_RE.test(h))) throw new UserError(`"${h}" is not a valid host name`);
}

function issueLeaf({ hosts, caId, days = 365, name } = {}) {
  const list = (Array.isArray(hosts) ? hosts : String(hosts || '').split(/[\s,]+/))
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean);
  if (!list.length) throw new UserError('Enter at least one host name');
  list.forEach(validateHostName);
  const cfg = store.load();
  const useCa = caId || cfg.activeCaId;
  if (!useCa) throw new UserError('There is no signing CA yet. Generate one, or import your company CA together with its private key.');
  const caEntry = readIndex().find((e) => e.id === useCa && e.kind === 'ca');
  if (!caEntry) throw new UserError('That CA no longer exists');
  const caKeyPem = readKey(caEntry.id);
  if (!caEntry.canSign || !caKeyPem)
    throw new UserError('That CA has no usable RSA private key, so it cannot sign certificates. It can still be installed on devices.');
  const caChain = readChain(caEntry.id);
  const caPem = splitPem(caChain)[0];
  const caInfo = inspect(caPem);
  if (Date.parse(caInfo.notAfter) < Date.now()) throw new UserError('The signing CA has expired');
  const caParsed = der.parseCert(der.pemToDer(caPem));
  const skiValue = caParsed.extensions[der.oidHex(der.OID.subjectKeyId)];
  const authorityKeyId = skiValue ? der.readTlv(skiValue).value : der.keyIdFromSpki(caParsed.spki.raw);

  const id = newId();
  const { pem, spkiDer } = genKey();
  const certPem = der.buildCertificate({
    serialHex: serial(),
    issuerDer: caParsed.subject.raw, // exact bytes of the CA subject, so the chain links up
    subjectDer: der.name([
      [der.OID.commonName, list[0]],
      [der.OID.organizationName, 'CORS Bridge (local development only)'],
    ]),
    notBefore: new Date(Date.now() - DAY),
    notAfter: new Date(Math.min(Date.now() + days * DAY, Date.parse(caInfo.notAfter))),
    spkiDer,
    isCa: false,
    hosts: list,
    authorityKeyId,
    signerKey: crypto.createPrivateKey(caKeyPem),
  });
  saveEntry(
    {
      id,
      kind: 'leaf',
      origin: 'generated',
      name: name || list.join(', '),
      createdAt: new Date().toISOString(),
      issuerId: caEntry.id,
    },
    `${certPem}${caChain}`,
    pem
  );
  return get(id);
}

// ---------------------------------------------------------------- import

const PEM_KEY_RE = /-----BEGIN ((?:RSA |EC |ENCRYPTED )?PRIVATE KEY)-----[\s\S]+?-----END \1-----/;

// A combined PEM (for example from "openssl pkcs12 -nodes") holds the key and the certificates in one file.
function splitCombinedPem(text) {
  const s = String(text || '');
  const key = PEM_KEY_RE.exec(s);
  return { certPem: (s.match(PEM_CERT_RE) || []).join('\n'), keyPem: key ? key[0] : '' };
}

function importCert({ name, certPem, keyPem, passphrase } = {}) {
  if (!(keyPem && keyPem.trim())) {
    const split = splitCombinedPem(certPem);
    if (split.keyPem) keyPem = split.keyPem;
  }
  const blocks = splitPem(certPem);
  if (!blocks.length) throw new UserError('No certificate found. Paste or upload a PEM file that contains "-----BEGIN CERTIFICATE-----".');
  let parsed;
  try {
    parsed = blocks.map((b) => new crypto.X509Certificate(b));
  } catch (e) {
    throw new UserError(`Could not read the certificate: ${e.message}`);
  }
  const keyObj = keyPem && keyPem.trim() ? parsePrivateKey(keyPem, passphrase) : null;

  const existing = readIndex().map((e) => describe(e, null));
  const dup = (fp) => existing.find((e) => e.fingerprint256 === fp);

  // CA bundle without a key => one install-only entry per certificate
  if (!keyObj && parsed.every((x) => x.ca)) {
    return parsed.map((x, i) => {
      const found = dup(x.fingerprint256);
      if (found) return found;
      const info = inspect(blocks[i]);
      const id = newId();
      saveEntry(
        {
          id,
          kind: 'ca',
          origin: 'imported',
          name: (parsed.length === 1 && name) || info.cn || `Imported CA ${id}`,
          createdAt: new Date().toISOString(),
          canSign: false,
        },
        blocks[i],
        null
      );
      return get(id);
    });
  }

  let primary = 0;
  if (keyObj) {
    primary = parsed.findIndex((x) => x.checkPrivateKey(keyObj));
    if (primary < 0) throw new UserError('The private key does not match any certificate in that file.');
  } else if (!parsed[0].ca) {
    throw new UserError('A server certificate needs its private key too. Add the key, or import it as a .pfx/.p12 file.');
  }
  const ordered = [blocks[primary], ...blocks.filter((_, i) => i !== primary)];
  const x = parsed[primary];
  const found = dup(x.fingerprint256);
  if (found) throw new UserError(`That certificate is already imported ("${found.name}").`);
  const info = inspect(ordered[0]);
  const isCa = !!x.ca;
  const id = newId();
  saveEntry(
    {
      id,
      kind: isCa ? 'ca' : 'leaf',
      origin: 'imported',
      name: name || info.cn || `Imported ${id}`,
      createdAt: new Date().toISOString(),
      canSign: isCa && keyObj.asymmetricKeyType === 'rsa',
    },
    ordered.join('\n'),
    exportKey(keyObj)
  );
  return [get(id)];
}

// ---------------------------------------------------------------- queries

function list() {
  const cfg = store.load();
  return readIndex().map((e) => describe(e, cfg.activeCaId));
}

function get(id) {
  const e = readIndex().find((x) => x.id === id);
  return e ? describe(e, store.load().activeCaId) : null;
}

function remove(id) {
  const idx = readIndex();
  if (!idx.some((e) => e.id === id)) throw new UserError('Certificate not found', 404);
  writeIndex(idx.filter((e) => e.id !== id));
  for (const f of [certFile(id), keyFile(id)]) {
    try {
      fs.unlinkSync(f);
    } catch {
      /* already gone */
    }
  }
  const cfg = store.load();
  if (cfg.activeCaId === id) {
    cfg.activeCaId = null;
    store.save(cfg);
  }
}

function setActiveCa(id) {
  const e = get(id);
  if (!e || e.kind !== 'ca') throw new UserError('Pick a CA certificate');
  if (!e.canSign) throw new UserError('That CA has no usable RSA private key, so it cannot sign certificates.');
  const cfg = store.load();
  cfg.activeCaId = id;
  store.save(cfg);
}

function findLeafForHost(host) {
  const soon = Date.now() + DAY;
  const candidates = list().filter(
    (c) => c.kind === 'leaf' && c.hasKey && c.status !== 'unreadable' && Date.parse(c.notAfter) > soon && hostMatches(c.names, host)
  );
  candidates.sort((a, b) => (a.origin === b.origin ? Date.parse(b.notAfter) - Date.parse(a.notAfter) : a.origin === 'imported' ? -1 : 1));
  return candidates[0] || null;
}

function ensureLeafForHost(host) {
  const found = findLeafForHost(host);
  if (found) return found;
  const cfg = store.load();
  let ca = cfg.activeCaId ? get(cfg.activeCaId) : null;
  if (!ca || !ca.canSign || ca.status === 'expired') ca = generateCa();
  if (!cfg.activeCaId || cfg.activeCaId !== ca.id) setActiveCa(ca.id);
  return issueLeaf({ hosts: [host], caId: ca.id });
}

function tlsOptions(id) {
  const key = readKey(id);
  if (!key) throw new UserError('That certificate has no private key and cannot be used by the proxy.');
  return { key, cert: readChain(id) };
}

function allCaPems() {
  return list()
    .filter((c) => c.kind === 'ca')
    .map((c) => splitPem(readChain(c.id))[0]);
}

// ---------------------------------------------------------------- Android naming

// OpenSSL "subject_hash_old": MD5 of the DER-encoded subject, first 4 bytes little-endian.
function subjectHashOld(certPem) {
  const subject = der.parseCert(der.pemToDer(certPem)).subject.raw;
  const d = crypto.createHash('md5').update(subject).digest();
  return d.readUInt32LE(0).toString(16).padStart(8, '0');
}

function androidFileName(certPem) {
  return `${subjectHashOld(certPem)}.0`;
}

function exportCert(id, format = 'pem') {
  const e = get(id);
  if (!e) throw new UserError('Certificate not found', 404);
  const pem = splitPem(readChain(id))[0];
  const base = (e.name || 'certificate').replace(/[^a-z0-9._-]+/gi, '_');
  if (format === 'cer') return { filename: `${base}.cer`, type: 'application/x-x509-ca-cert', body: new crypto.X509Certificate(pem).raw };
  if (format === 'android') return { filename: androidFileName(pem), type: 'application/x-pem-file', body: `${pem}\n` };
  return { filename: `${base}.pem`, type: 'application/x-pem-file', body: `${pem}\n` };
}

function firstPem(id) {
  return splitPem(readChain(id))[0];
}

module.exports = {
  splitCombinedPem,
  list,
  get,
  generateCa,
  issueLeaf,
  importCert,
  remove,
  setActiveCa,
  findLeafForHost,
  ensureLeafForHost,
  tlsOptions,
  allCaPems,
  exportCert,
  firstPem,
  subjectHashOld,
  androidFileName,
  hostMatches,
  splitPem,
};
