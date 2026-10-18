'use strict';
const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const { UserError } = require('./util');

const BEGIN = '# >>> cors-bridge (managed block, safe to delete) >>>';
const END = '# <<< cors-bridge <<<';

function hostsPath() {
  if (process.env.CORS_BRIDGE_HOSTS_FILE) return process.env.CORS_BRIDGE_HOSTS_FILE;
  return process.platform === 'win32'
    ? path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'drivers', 'etc', 'hosts')
    : '/etc/hosts';
}

const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function stripBlock(content) {
  return content.replace(new RegExp(`${esc(BEGIN)}[\\s\\S]*?${esc(END)}\\r?\\n?`, 'g'), '');
}

// Pure function: returns the new hosts file text for the given entries ([{ip, host}]). No entries => block removed.
function buildContent(original, entries) {
  const eol = original.includes('\r\n') ? '\r\n' : '\n';
  let base = stripBlock(original);
  if (!entries.length) return base;
  if (base.length && !base.endsWith('\n')) base += eol;
  const block = [BEGIN, ...entries.map((e) => `${e.ip} ${e.host}`), END].join(eol);
  return `${base}${block}${eol}`;
}

function parseBlock(content) {
  const m = new RegExp(`${esc(BEGIN)}([\\s\\S]*?)${esc(END)}`).exec(content);
  if (!m) return [];
  return m[1]
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => {
      const [ip, host] = l.split(/\s+/);
      return { ip, host };
    });
}

function read() {
  try {
    return fs.readFileSync(hostsPath(), 'utf8');
  } catch {
    return '';
  }
}

function status() {
  const p = hostsPath();
  let writable = true;
  try {
    fs.accessSync(p, fs.constants.W_OK);
  } catch {
    writable = false;
  }
  return { path: p, entries: parseBlock(read()), writable };
}

function run(cmd, args) {
  return new Promise((resolve) =>
    execFile(cmd, args, { timeout: 120000, windowsHide: true }, (err, stdout, stderr) =>
      resolve({ ok: !err, stdout: String(stdout), stderr: String(stderr), err })
    )
  );
}

async function flushDns() {
  if (process.env.CORS_BRIDGE_HOSTS_FILE) return;
  if (process.platform === 'darwin') {
    await run('dscacheutil', ['-flushcache']);
    await run('killall', ['-HUP', 'mDNSResponder']);
  } else if (process.platform === 'win32') {
    await run('ipconfig', ['/flushdns']);
  }
}

const shQuote = (v) => `'${String(v).replace(/'/g, `'\\''`)}'`;

// The shell command run as root on macOS. The new text travels inside the command (base64), so there is no
// temp file another program could swap (for example for a link to a root-only file) before root reads it.
// It is written to a root-owned temp file next to the hosts file first, then moved into place in one step.
function darwinWriteCommand(content, target) {
  const b64 = Buffer.from(content, 'utf8').toString('base64');
  const dir = path.dirname(target);
  return [
    `T=$(/usr/bin/mktemp ${shQuote(path.join(dir, '.cors-bridge-hosts.XXXXXX'))})`,
    `/bin/echo ${shQuote(b64)} | /usr/bin/base64 -D > "$T"`,
    '/bin/chmod 644 "$T"',
    `/bin/mv -f "$T" ${shQuote(target)} || { /bin/rm -f "$T"; exit 1; }`,
  ].join(' && ');
}

// The PowerShell run with administrator rights on Windows, passed as -EncodedCommand for the same reason.
function windowsWriteCommand(content, target) {
  const b64 = Buffer.from(content, 'utf8').toString('base64');
  const q = (v) => `'${String(v).replace(/'/g, "''")}'`;
  const inner = [
    `$tmp = ${q(`${target}.cors-bridge`)}`,
    `[IO.File]::WriteAllBytes($tmp, [Convert]::FromBase64String(${q(b64)}))`,
    `Move-Item -Force -LiteralPath $tmp -Destination ${q(target)}`,
    'ipconfig /flushdns | Out-Null',
  ].join('; ');
  return Buffer.from(inner, 'utf16le').toString('base64');
}

// Writes the new content. Tries a normal write first; if the OS denies it, asks for admin rights
// through the native prompt (macOS password dialog / Windows UAC).
async function writeHosts(content) {
  const target = hostsPath();
  try {
    fs.writeFileSync(target, content);
    await flushDns();
    return { elevated: false };
  } catch (e) {
    if (!['EACCES', 'EPERM', 'EBUSY'].includes(e.code)) throw new UserError(`Could not write ${target}: ${e.message}`);
  }
  let r;
  if (process.platform === 'darwin') {
    const sh = `${darwinWriteCommand(content, target)} && dscacheutil -flushcache && killall -HUP mDNSResponder`;
    const script = `do shell script "${sh.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}" with administrator privileges`;
    r = await run('osascript', ['-e', script]);
  } else if (process.platform === 'win32') {
    const encoded = windowsWriteCommand(content, target);
    // Windows limits a command line to about 32,000 characters.
    if (encoded.length > 30000) throw new UserError(`The hosts file is too large to change automatically. Edit ${target} by hand as administrator.`);
    r = await run('powershell', [
      '-NoProfile',
      '-Command',
      `Start-Process -FilePath powershell.exe -Verb RunAs -Wait -WindowStyle Hidden -ArgumentList '-NoProfile','-EncodedCommand','${encoded}'`,
    ]);
  } else {
    throw new UserError(`Permission denied writing ${target}. Run the app with sudo, or edit the file by hand.`);
  }
  if (!r.ok) throw new UserError('Administrator permission was not granted, so the hosts file was not changed.');
  return { elevated: true };
}

async function apply(entries) {
  const original = read();
  const next = buildContent(original, entries);
  if (next === original) return { changed: false, ...status() };
  const info = await writeHosts(next);
  // Windows UAC copy is asynchronous from our point of view; verify what is on disk now.
  const now = status();
  const want = entries.map((e) => `${e.ip} ${e.host}`).sort().join('|');
  const have = now.entries.map((e) => `${e.ip} ${e.host}`).sort().join('|');
  if (want !== have) throw new UserError('The hosts file did not change. Security software may be blocking edits to it.');
  return { changed: true, elevated: info.elevated, ...now };
}

const remove = () => apply([]);

module.exports = { BEGIN, END, darwinWriteCommand, windowsWriteCommand, hostsPath, buildContent, parseBlock, stripBlock, status, apply, remove };
