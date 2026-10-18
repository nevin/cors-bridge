'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFile } = require('child_process');
const { UserError, sleep } = require('./util');
const hosts = require('./hosts');

function run(cmd, args, opts = {}) {
  return new Promise((resolve) => {
    execFile(
      cmd,
      args,
      { timeout: opts.timeout || 30000, maxBuffer: 10 * 1024 * 1024, windowsHide: true },
      (err, stdout, stderr) =>
        resolve({
          ok: !err,
          missing: !!(err && err.code === 'ENOENT'),
          stdout: String(stdout || ''),
          stderr: String(stderr || ''),
        })
    );
  });
}

const tmpFile = (name, content) => {
  const f = path.join(os.tmpdir(), `cors-bridge-${crypto.randomBytes(4).toString('hex')}-${name}`);
  fs.writeFileSync(f, content);
  return f;
};

// ------------------------------------------------------------------ adb

function withSteps(err, steps) {
  err.steps = steps;
  return err;
}

async function findAdb() {
  const exe = process.platform === 'win32' ? 'adb.exe' : 'adb';
  const candidates = [process.env.ADB];
  for (const root of [process.env.ANDROID_SDK_ROOT, process.env.ANDROID_HOME]) {
    if (root) candidates.push(path.join(root, 'platform-tools', exe));
  }
  candidates.push(
    path.join(os.homedir(), 'Library', 'Android', 'sdk', 'platform-tools', exe),
    path.join(process.env.LOCALAPPDATA || '', 'Android', 'Sdk', 'platform-tools', exe),
    path.join(os.homedir(), 'Android', 'Sdk', 'platform-tools', exe)
  );
  for (const c of candidates) if (c && fs.existsSync(c)) return c;
  const r = await run('adb', ['version']);
  return r.missing ? null : 'adb';
}

async function adbOrThrow() {
  const adb = await findAdb();
  if (!adb)
    throw new UserError(
      'adb was not found. Install Android Studio (or the platform-tools), or set the ANDROID_HOME environment variable.'
    );
  return adb;
}

async function androidList() {
  const adb = await findAdb();
  if (!adb) return { available: false, devices: [] };
  const r = await run(adb, ['devices', '-l']);
  const devices = [];
  for (const line of r.stdout.split(/\r?\n/).slice(1)) {
    const m = /^(\S+)\s+(device|offline|unauthorized)\b(.*)$/.exec(line.trim());
    if (!m) continue;
    const d = { serial: m[1], state: m[2], isEmulator: m[1].startsWith('emulator-') };
    const model = /model:(\S+)/.exec(m[3]);
    d.model = model ? model[1] : '';
    if (d.state === 'device') {
      const p = await run(adb, [
        '-s',
        d.serial,
        'shell',
        'getprop ro.build.version.release; getprop ro.build.version.sdk; getprop ro.debuggable; getprop ro.build.type',
      ]);
      const [release, sdk, debuggable, type] = p.stdout.split(/\r?\n/).map((s) => s.trim());
      Object.assign(d, { release, sdk: Number(sdk) || null, rootable: debuggable === '1', buildType: type });
    }
    devices.push(d);
  }
  return { available: true, adb, devices };
}

async function ensureRoot(adb, serial, steps) {
  const r = await run(adb, ['-s', serial, 'root'], { timeout: 30000 });
  const out = `${r.stdout} ${r.stderr}`.toLowerCase();
  if (out.includes('cannot run as root'))
    throw new UserError(
      'This emulator does not allow root. Create an AVD that uses a "Google APIs" system image (not "Google Play") and try again.'
    );
  await run(adb, ['-s', serial, 'wait-for-device'], { timeout: 60000 });
  for (let i = 0; i < 10; i++) {
    const id = await run(adb, ['-s', serial, 'shell', 'id -u']);
    if (id.stdout.trim() === '0') {
      steps.push({ label: 'Root shell on the emulator', ok: true });
      return;
    }
    await sleep(1000);
  }
  throw new UserError('Could not get a root shell on the emulator.');
}

async function push(adb, serial, localContent, remotePath, steps, label) {
  const f = tmpFile('push', localContent);
  const r = await run(adb, ['-s', serial, 'push', f, remotePath]);
  fs.unlinkSync(f);
  steps.push({ label, ok: r.ok, output: (r.stdout + r.stderr).trim() });
  if (!r.ok) throw new UserError(`adb push failed: ${(r.stderr || r.stdout).trim()}`);
}

async function shell(adb, serial, cmd, steps, label) {
  const r = await run(adb, ['-s', serial, 'shell', cmd], { timeout: 60000 });
  steps.push({ label, ok: r.ok, output: (r.stdout + r.stderr).trim() });
  return r;
}

// Runs a command inside the mount namespace of zygote and every app process so apps that are already
// running (and apps started later) see the change.
const NS_HELPER = [
  'zygote_ns_each() {',
  '  ZYGOTE_PID=$(pidof zygote || true)',
  '  ZYGOTE64_PID=$(pidof zygote64 || true)',
  '  for Z in $ZYGOTE_PID $ZYGOTE64_PID; do',
  '    nsenter --mount=/proc/$Z/ns/mnt -- "$@" >/dev/null 2>&1 || true',
  '  done',
  '  ps -A -o PID,PPID | while read P PP; do',
  '    case "$P" in ""|*[!0-9]*) continue;; esac',
  '    if [ "$PP" = "$ZYGOTE_PID" ] || [ "$PP" = "$ZYGOTE64_PID" ]; then',
  '      nsenter --mount=/proc/$P/ns/mnt -- "$@" >/dev/null 2>&1 || true',
  '    fi',
  '  done',
  '}',
];

function caScript(hashName) {
  return [
    '#!/system/bin/sh',
    'SYS=/system/etc/security/cacerts',
    'APEX=/apex/com.android.conscrypt/cacerts',
    'TMPD=/data/local/tmp/cb-ca-copy',
    `CERT=/data/local/tmp/${hashName}`,
    ...NS_HELPER,
    'rm -rf $TMPD; mkdir -p -m 700 $TMPD || exit 1',
    'if [ -d $APEX ]; then cp $APEX/* $TMPD/; else cp $SYS/* $TMPD/; fi',
    'mount -t tmpfs tmpfs $SYS || exit 2',
    'cp $TMPD/* $SYS/',
    'cp $CERT $SYS/',
    'chown root:root $SYS/*',
    'chmod 644 $SYS/*',
    'chcon u:object_r:system_file:s0 $SYS/* 2>/dev/null',
    'if [ -d $APEX ]; then',
    '  mount --bind $SYS $APEX 2>/dev/null',
    '  zygote_ns_each mount --bind $SYS $APEX',
    'fi',
    'rm -rf $TMPD',
    'echo installed',
    '',
  ].join('\n');
}

async function androidInstallCa(serial, caPem, hashName) {
  const adb = await adbOrThrow();
  const steps = [];
  await ensureRoot(adb, serial, steps);
  await push(adb, serial, caPem.endsWith('\n') ? caPem : `${caPem}\n`, `/data/local/tmp/${hashName}`, steps, 'Copied certificate to the emulator');
  await push(adb, serial, caScript(hashName), '/data/local/tmp/cb-install-ca.sh', steps, 'Copied install script');
  const r = await shell(adb, serial, 'sh /data/local/tmp/cb-install-ca.sh', steps, 'Installed into the system trust store');
  const check = await shell(adb, serial, `ls /system/etc/security/cacerts/${hashName}`, steps, 'Checked the certificate is present');
  const ok = r.ok && check.ok && check.stdout.includes(hashName);
  if (!ok) throw withSteps(new UserError('The certificate could not be installed. See the details below.', 500), steps);
  return {
    ok: true,
    steps,
    note: 'Installed until the emulator does a cold boot. Restart the app under test so it picks up the new certificate.',
  };
}

function caRemoveScript() {
  return [
    '#!/system/bin/sh',
    'SYS=/system/etc/security/cacerts',
    'APEX=/apex/com.android.conscrypt/cacerts',
    ...NS_HELPER,
    'if [ -d $APEX ]; then',
    '  zygote_ns_each umount $APEX',
    '  umount $APEX 2>/dev/null',
    'fi',
    'zygote_ns_each umount $SYS',
    'umount $SYS 2>/dev/null',
    'echo removed',
    '',
  ].join('\n');
}

// Undoes androidInstallCa: drops the temporary trust store so the emulator is back to its built-in CAs.
async function androidRemoveCa(serial) {
  const adb = await adbOrThrow();
  const steps = [];
  await ensureRoot(adb, serial, steps);
  await push(adb, serial, caRemoveScript(), '/data/local/tmp/cb-remove-ca.sh', steps, 'Copied script');
  await shell(adb, serial, 'sh /data/local/tmp/cb-remove-ca.sh', steps, 'Removed the added certificates');
  return { ok: true, steps };
}

// Reads what is set up on an emulator without changing anything (no root needed).
// hashNames are Android CA file names such as "a1b2c3d4.0". Returns the ones present and the redirect entries.
async function androidProbe(serial, hashNames) {
  const adb = await findAdb();
  if (!adb) return { caPresent: [], hostsEntries: [] };
  const names = hashNames.filter((n) => /^[0-9a-f]{8}\.\d+$/.test(n));
  let caPresent = [];
  if (names.length) {
    const r = await run(adb, ['-s', serial, 'shell', `ls ${names.map((n) => `/system/etc/security/cacerts/${n}`).join(' ')}`]);
    const found = new Set(r.stdout.split(/\s+/).map((w) => w.split('/').pop()));
    caPresent = names.filter((n) => found.has(n));
  }
  const h = await run(adb, ['-s', serial, 'shell', 'cat /system/etc/hosts']);
  return { caPresent, hostsEntries: hosts.parseBlock(h.stdout) };
}

const HOSTS_REMOVE_SCRIPT = [
  '#!/system/bin/sh',
  'H=/system/etc/hosts',
  ...NS_HELPER,
  'umount $H 2>/dev/null',
  'zygote_ns_each umount $H',
  'echo removed',
  '',
].join('\n');

function hostsBindScript() {
  return [
    '#!/system/bin/sh',
    'H=/system/etc/hosts',
    'NEW=/data/local/tmp/cb-hosts',
    ...NS_HELPER,
    'chmod 644 $NEW',
    'chcon u:object_r:system_file:s0 $NEW 2>/dev/null',
    'mount -o bind $NEW $H || exit 2',
    'zygote_ns_each mount -o bind $NEW $H',
    'echo applied',
    '',
  ].join('\n');
}

async function androidApplyHosts(serial, entries) {
  const adb = await adbOrThrow();
  const steps = [];
  await ensureRoot(adb, serial, steps);
  await push(adb, serial, HOSTS_REMOVE_SCRIPT, '/data/local/tmp/cb-hosts-remove.sh', steps, 'Copied script');
  await shell(adb, serial, 'sh /data/local/tmp/cb-hosts-remove.sh', steps, 'Cleared any earlier redirect');
  const orig = await shell(adb, serial, 'cat /system/etc/hosts', steps, 'Read the emulator hosts file');
  const content = hosts.buildContent(orig.stdout.replace(/\r\n/g, '\n'), entries);
  await push(adb, serial, content, '/data/local/tmp/cb-hosts', steps, 'Copied new hosts file');
  await push(adb, serial, hostsBindScript(), '/data/local/tmp/cb-hosts-apply.sh', steps, 'Copied script');
  const r = await shell(adb, serial, 'sh /data/local/tmp/cb-hosts-apply.sh', steps, 'Applied the redirect');
  const check = await shell(adb, serial, 'cat /system/etc/hosts', steps, 'Checked the result');
  if (!r.ok || !entries.every((e) => check.stdout.includes(e.host)))
    throw withSteps(new UserError('The redirect could not be applied. See the details below.', 500), steps);
  return { ok: true, steps, note: 'Applied until the emulator does a cold boot. Restart the app under test.' };
}

async function androidRemoveHosts(serial) {
  const adb = await adbOrThrow();
  const steps = [];
  await ensureRoot(adb, serial, steps);
  await push(adb, serial, HOSTS_REMOVE_SCRIPT, '/data/local/tmp/cb-hosts-remove.sh', steps, 'Copied script');
  await shell(adb, serial, 'sh /data/local/tmp/cb-hosts-remove.sh', steps, 'Removed the redirect');
  return { ok: true, steps };
}

// ------------------------------------------------------------------ iOS Simulator

const xcrun = () => process.env.XCRUN || 'xcrun';
const iosSupported = () => process.platform === 'darwin' || !!process.env.XCRUN;

async function iosList() {
  if (!iosSupported()) return { supported: false, reason: 'The iOS Simulator only exists on macOS.', devices: [] };
  const r = await run(xcrun(), ['simctl', 'list', 'devices', '--json']);
  if (!r.ok) return { supported: true, available: false, reason: 'Xcode command line tools were not found (xcrun).', devices: [] };
  let data;
  try {
    data = JSON.parse(r.stdout);
  } catch {
    return { supported: true, available: false, reason: 'Could not read the simulator list.', devices: [] };
  }
  const devices = [];
  for (const [runtime, list] of Object.entries(data.devices || {})) {
    for (const d of list) {
      if (d.state === 'Booted') devices.push({ udid: d.udid, name: d.name, runtime: runtime.split('.').pop().replace(/-/g, ' '), state: d.state });
    }
  }
  return { supported: true, available: true, devices };
}

async function iosInstallCa(udid, caPem) {
  if (!iosSupported()) throw new UserError('The iOS Simulator only exists on macOS.');
  const f = tmpFile('ca.pem', caPem.endsWith('\n') ? caPem : `${caPem}\n`);
  const r = await run(xcrun(), ['simctl', 'keychain', udid || 'booted', 'add-root-cert', f]);
  fs.unlinkSync(f);
  if (!r.ok) throw new UserError(`simctl failed: ${(r.stderr || r.stdout).trim() || 'unknown error'}`, 500);
  return {
    ok: true,
    steps: [{ label: 'Added the CA to the simulator keychain', ok: true, output: (r.stdout + r.stderr).trim() }],
    note: 'If the app still shows a certificate error, restart the app (or reboot the simulator).',
  };
}

// The simulator has no command to remove one root certificate, so undo resets its keychain.
async function iosResetKeychain(udid) {
  if (!iosSupported()) throw new UserError('The iOS Simulator only exists on macOS.');
  const r = await run(xcrun(), ['simctl', 'keychain', udid || 'booted', 'reset']);
  if (!r.ok) throw new UserError(`simctl failed: ${(r.stderr || r.stdout).trim() || 'unknown error'}`, 500);
  return { ok: true, steps: [{ label: 'Reset the simulator keychain (removes the CA)', ok: true, output: (r.stdout + r.stderr).trim() }] };
}

module.exports = {
  findAdb,
  androidList,
  androidProbe,
  androidInstallCa,
  androidRemoveCa,
  androidApplyHosts,
  androidRemoveHosts,
  iosList,
  iosInstallCa,
  iosResetKeychain,
  caScript,
  caRemoveScript,
  hostsBindScript,
};
