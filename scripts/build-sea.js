#!/usr/bin/env node
'use strict';
// Builds CORS Bridge as a single executable (Node "SEA") per operating system, so users do not need Node installed.
//
//   node scripts/build-sea.js                 build for this computer
//   node scripts/build-sea.js win-x64 linux-x64 darwin-arm64
//   node scripts/build-sea.js all
//
// Every binary contains the Node version that runs this script. Binaries for other platforms are made from the
// official Node download for that platform (checked against nodejs.org's SHASUMS256.txt). macOS binaries must be
// built on a Mac, because they have to be code-signed to run.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const BUILD = path.join(ROOT, 'build');
const CACHE = path.join(BUILD, 'node-cache');
const DIST = path.join(ROOT, 'dist');
const VERSION = process.version;
const POSTJECT = 'postject@1.0.0-alpha.6';
const FUSE = 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2';
const TARGETS = ['darwin-arm64', 'darwin-x64', 'linux-x64', 'linux-arm64', 'win-x64', 'win-arm64'];

const hostTarget = `${process.platform === 'win32' ? 'win' : process.platform}-${process.arch}`;
const isWin = (t) => t.startsWith('win');
const isMac = (t) => t.startsWith('darwin');

function run(cmd, args, opts = {}) {
  execFileSync(cmd, args, { stdio: 'inherit', shell: process.platform === 'win32' && cmd === 'npx', ...opts });
}

// ------------------------------------------------------------------ bundle

// Puts server.js and lib/*.js into one script. Relative requires are served from the bundle, everything else
// (Node's built-in modules) goes to the real require. The project has no npm dependencies, so nothing else is needed.
function bundle() {
  const files = ['server.js', ...fs.readdirSync(path.join(ROOT, 'lib')).filter((f) => f.endsWith('.js')).map((f) => `lib/${f}`)];
  const mods = files
    .map((f) => {
      const src = fs.readFileSync(path.join(ROOT, f), 'utf8').replace(/^#!.*\n/, '');
      return `${JSON.stringify(f)}: function (module, exports, require, __filename, __dirname) {\n${src}\n}`;
    })
    .join(',\n');
  const out = `'use strict';
const __realRequire = require;
const __path = require('path');
const __mods = {
${mods}
};
const __cache = {};
function __load(id) {
  if (__cache[id]) return __cache[id].exports;
  if (!__mods[id]) throw new Error('Module not in bundle: ' + id);
  const module = { exports: {} };
  __cache[id] = module;
  const dir = __path.posix.dirname(id);
  const req = (p) => {
    if (!p.startsWith('.')) return __realRequire(p);
    let rid = __path.posix.normalize(__path.posix.join(dir, p));
    if (!rid.endsWith('.js')) rid += '.js';
    return __load(rid);
  };
  __mods[id].call(module.exports, module, module.exports, req, id, dir);
  return module.exports;
}
__load('server.js');
`;
  fs.writeFileSync(path.join(BUILD, 'bundle.js'), out);
}

// ------------------------------------------------------------------ blob

function makeBlob() {
  const assets = {};
  for (const f of fs.readdirSync(path.join(ROOT, 'public'))) assets[`public/${f}`] = path.join(ROOT, 'public', f);
  const config = {
    main: path.join(BUILD, 'bundle.js'),
    output: path.join(BUILD, 'sea-prep.blob'),
    disableExperimentalSEAWarning: true,
    // Without code cache and snapshot the blob is the same for every platform, so one blob serves all targets.
    useCodeCache: false,
    useSnapshot: false,
    assets,
  };
  const cfgFile = path.join(BUILD, 'sea-config.json');
  fs.writeFileSync(cfgFile, JSON.stringify(config, null, 2));
  run(process.execPath, ['--experimental-sea-config', cfgFile]);
  return config.output;
}

// ------------------------------------------------------------------ node binaries

async function download(url, file) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`Download failed (${r.status}): ${url}`);
  fs.writeFileSync(file, Buffer.from(await r.arrayBuffer()));
}

let shasums;
async function expectedSha(name) {
  if (!shasums) {
    const r = await fetch(`https://nodejs.org/dist/${VERSION}/SHASUMS256.txt`);
    if (!r.ok) throw new Error(`Could not get SHASUMS256.txt for Node ${VERSION}`);
    shasums = await r.text();
  }
  const line = shasums.split('\n').find((l) => l.trim().endsWith(`  ${name}`));
  if (!line) throw new Error(`nodejs.org has no ${name} for Node ${VERSION}`);
  return line.split(/\s+/)[0];
}

// Returns the path of a Node executable for the target.
async function nodeFor(target) {
  if (target === hostTarget) return process.execPath;
  const base = `node-${VERSION}-${target}`;
  const exe = isWin(target) ? path.join(CACHE, base, 'node.exe') : path.join(CACHE, base, 'bin', 'node');
  if (fs.existsSync(exe)) return exe;
  const archive = `${base}.${isWin(target) ? 'zip' : 'tar.gz'}`;
  const file = path.join(CACHE, archive);
  console.log(`  downloading ${archive}`);
  await download(`https://nodejs.org/dist/${VERSION}/${archive}`, file);
  const sha = crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
  if (sha !== (await expectedSha(archive))) {
    fs.unlinkSync(file);
    throw new Error(`Checksum mismatch for ${archive}, the download was deleted`);
  }
  const inner = isWin(target) ? `${base}/node.exe` : `${base}/bin/node`;
  if (isWin(target) && process.platform === 'linux') run('unzip', ['-o', '-q', file, inner, '-d', CACHE]);
  else run('tar', ['-xf', file, '-C', CACHE, inner]);
  fs.unlinkSync(file);
  return exe;
}

// ------------------------------------------------------------------ build

async function buildTarget(target, blob) {
  if (isMac(target) && process.platform !== 'darwin') throw new Error(`${target}: macOS binaries must be built on a Mac (they need codesign).`);
  console.log(`\n${target}`);
  const src = await nodeFor(target);
  const out = path.join(DIST, `cors-bridge-${target.replace('darwin', 'macos')}${isWin(target) ? '.exe' : ''}`);
  fs.copyFileSync(src, out);
  fs.chmodSync(out, 0o755);
  if (isMac(target)) run('codesign', ['--remove-signature', out]);
  const args = ['--yes', POSTJECT, out, 'NODE_SEA_BLOB', blob, '--sentinel-fuse', FUSE];
  if (isMac(target)) args.push('--macho-segment-name', 'NODE_SEA');
  run('npx', args);
  if (isMac(target)) run('codesign', ['--sign', '-', out]); // ad-hoc signature; use a Developer ID to distribute
  console.log(`  -> ${path.relative(ROOT, out)}`);
}

async function main() {
  let targets = process.argv.slice(2);
  if (!targets.length) targets = [hostTarget];
  if (targets.includes('all')) targets = TARGETS.filter((t) => process.platform === 'darwin' || !isMac(t));
  for (const t of targets) if (!TARGETS.includes(t)) throw new Error(`Unknown target "${t}". Use one of: ${TARGETS.join(', ')}, all`);

  fs.mkdirSync(CACHE, { recursive: true });
  fs.mkdirSync(DIST, { recursive: true });
  console.log(`Building CORS Bridge with Node ${VERSION}`);
  bundle();
  const blob = makeBlob();
  for (const t of targets) await buildTarget(t, blob);
  console.log('\nDone.');
}

main().catch((e) => {
  console.error(`\nBuild failed: ${e.message}`);
  process.exit(1);
});
