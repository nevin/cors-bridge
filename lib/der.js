'use strict';
// Minimal DER / X.509 builder and reader, built on Node's crypto only (no dependencies).
const crypto = require('crypto');
const net = require('net');

function len(n) {
  if (n < 0x80) return Buffer.from([n]);
  const bytes = [];
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n = Math.floor(n / 256);
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

const tlv = (tag, content) => Buffer.concat([Buffer.from([tag]), len(content.length), content]);
const seq = (...items) => tlv(0x30, Buffer.concat(items));
const set = (...items) => tlv(0x31, Buffer.concat(items));
const octet = (b) => tlv(0x04, b);
const bool = (v) => tlv(0x01, Buffer.from([v ? 0xff : 0x00]));
const nul = () => Buffer.from([0x05, 0x00]);
const utf8 = (s) => tlv(0x0c, Buffer.from(s, 'utf8'));
const bitString = (buf, unused = 0) => tlv(0x03, Buffer.concat([Buffer.from([unused]), buf]));

function oid(str) {
  const p = str.split('.').map(Number);
  const out = [40 * p[0] + p[1]];
  for (const n of p.slice(2)) {
    const tmp = [n & 0x7f];
    let v = Math.floor(n / 128);
    while (v > 0) {
      tmp.unshift((v & 0x7f) | 0x80);
      v = Math.floor(v / 128);
    }
    out.push(...tmp);
  }
  return tlv(0x06, Buffer.from(out));
}

function time(d) {
  const p = (n, w = 2) => String(n).padStart(w, '0');
  const y = d.getUTCFullYear();
  const rest = `${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
  return y < 2050 ? tlv(0x17, Buffer.from(`${p(y % 100)}${rest}`)) : tlv(0x18, Buffer.from(`${p(y, 4)}${rest}`));
}

const OID = {
  commonName: '2.5.4.3',
  organizationName: '2.5.4.10',
  sha256WithRSA: '1.2.840.113549.1.1.11',
  subjectKeyId: '2.5.29.14',
  keyUsage: '2.5.29.15',
  subjectAltName: '2.5.29.17',
  basicConstraints: '2.5.29.19',
  authorityKeyId: '2.5.29.35',
  extKeyUsage: '2.5.29.37',
  serverAuth: '1.3.6.1.5.5.7.3.1',
};

function name(pairs) {
  return seq(...pairs.map(([o, v]) => set(seq(oid(o), utf8(v)))));
}

function ext(oidStr, critical, valueDer) {
  return seq(oid(oidStr), ...(critical ? [bool(true)] : []), octet(valueDer));
}

function keyUsageValue(bits) {
  // bit positions: 0 digitalSignature, 2 keyEncipherment, 5 keyCertSign, 6 cRLSign
  let b = 0;
  for (const i of bits) b |= 0x80 >> i;
  let unused = 0;
  while (unused < 8 && !(b & (1 << unused))) unused++;
  return bitString(Buffer.from([b]), unused);
}

function sanValue(hosts) {
  return seq(
    ...hosts.map((h) => {
      if (net.isIPv4(h)) return tlv(0x87, Buffer.from(h.split('.').map(Number)));
      if (net.isIPv6(h)) throw new Error('IPv6 addresses are not supported');
      return tlv(0x82, Buffer.from(h, 'ascii'));
    })
  );
}

// ------------------------------------------------------------------ reading

function readTlv(buf, off = 0) {
  const tag = buf[off];
  let l = buf[off + 1];
  let p = off + 2;
  if (l & 0x80) {
    const n = l & 0x7f;
    l = 0;
    for (let i = 0; i < n; i++) l = l * 256 + buf[p++];
  }
  return { tag, valueStart: p, end: p + l, value: buf.subarray(p, p + l), raw: buf.subarray(off, p + l), buf };
}

function children(node) {
  const out = [];
  let o = node.valueStart;
  while (o < node.end) {
    const c = readTlv(node.buf, o);
    out.push(c);
    o = c.end;
  }
  return out;
}

function parseCert(der) {
  const cert = readTlv(der);
  const tbs = children(cert)[0];
  const kids = children(tbs);
  const o = kids[0].tag === 0xa0 ? 1 : 0;
  const result = { subject: kids[o + 4], issuer: kids[o + 2], spki: kids[o + 5], extensions: {} };
  const extWrap = kids.find((k) => k.tag === 0xa3);
  if (extWrap) {
    for (const e of children(children(extWrap)[0])) {
      const parts = children(e);
      result.extensions[parts[0].value.toString('hex')] = parts[parts.length - 1].value;
    }
  }
  return result;
}

const oidHex = (str) => oid(str).subarray(2).toString('hex');

function pemToDer(pem) {
  return Buffer.from(pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64');
}

function derToPem(der) {
  const b64 = der.toString('base64').match(/.{1,64}/g).join('\n');
  return `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n`;
}

// SHA-1 of the public key bits (RFC 5280 method 1)
function keyIdFromSpki(spkiDer) {
  const bits = children(readTlv(spkiDer))[1].value.subarray(1);
  return crypto.createHash('sha1').update(bits).digest();
}

// ------------------------------------------------------------------ building

/**
 * opts: { serialHex, issuerDer, subjectDer, notBefore, notAfter, spkiDer, isCa, hosts, authorityKeyId, signerKey }
 * Returns a certificate PEM signed with sha256WithRSAEncryption.
 */
function buildCertificate(opts) {
  const extensions = [
    ext(OID.basicConstraints, true, opts.isCa ? seq(bool(true)) : seq()),
    ext(OID.keyUsage, true, keyUsageValue(opts.isCa ? [0, 5, 6] : [0, 2])),
  ];
  if (!opts.isCa) {
    extensions.push(ext(OID.extKeyUsage, false, seq(oid(OID.serverAuth))));
    extensions.push(ext(OID.subjectAltName, false, sanValue(opts.hosts)));
  }
  extensions.push(ext(OID.subjectKeyId, false, octet(keyIdFromSpki(opts.spkiDer))));
  if (opts.authorityKeyId) extensions.push(ext(OID.authorityKeyId, false, seq(tlv(0x80, opts.authorityKeyId))));

  const sigAlg = seq(oid(OID.sha256WithRSA), nul());
  const tbs = seq(
    tlv(0xa0, tlv(0x02, Buffer.from([2]))), // version v3
    tlv(0x02, Buffer.from(opts.serialHex, 'hex')),
    sigAlg,
    opts.issuerDer,
    seq(time(opts.notBefore), time(opts.notAfter)),
    opts.subjectDer,
    opts.spkiDer,
    tlv(0xa3, seq(...extensions))
  );
  const signature = crypto.sign('sha256', tbs, opts.signerKey);
  return derToPem(seq(tbs, sigAlg, bitString(signature)));
}

module.exports = { OID, name, parseCert, oidHex, pemToDer, derToPem, readTlv, children, keyIdFromSpki, buildCertificate };
