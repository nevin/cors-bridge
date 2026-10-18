'use strict';
// What CORS Bridge needs when it runs as an app, without a terminal window to print to.
const fs = require('fs');
const util = require('util');
const { spawn, spawnSync } = require('child_process');

// True when nobody can see the output: started from Finder or Explorer, or as the windowless Windows app.
// --console keeps messages on the standard output anyway (for scripts and tests).
const headless = (args = process.argv.slice(2)) => !process.stdout.isTTY && !args.includes('--console');

function openBrowser(url) {
  try {
    if (process.platform === 'darwin') spawn('open', [url], { stdio: 'ignore', detached: true }).unref();
    else if (process.platform === 'win32') spawn('cmd', ['/c', 'start', '""', url], { stdio: 'ignore', detached: true, windowsHide: true }).unref();
    else spawn('xdg-open', [url], { stdio: 'ignore', detached: true }).unref();
  } catch {
    /* the URL is printed (or logged) anyway */
  }
}

// Sends console output to a log file in the data folder. The file starts fresh once it passes 1 MB.
function useLogFile(file) {
  try {
    if (fs.statSync(file).size > 1024 * 1024) fs.writeFileSync(file, '', { mode: 0o600 });
  } catch {
    /* no log yet */
  }
  const write = (level, args) => {
    try {
      fs.appendFileSync(file, `${new Date().toISOString()} ${level} ${util.format(...args)}\n`, { mode: 0o600 });
    } catch {
      /* nowhere left to report it */
    }
  };
  console.log = (...a) => write('info ', a);
  console.info = console.log;
  console.warn = (...a) => write('warn ', a);
  console.error = (...a) => write('error', a);
  write('info ', ['--- CORS Bridge started']);
}

// A native message box, for errors that happen before the dashboard can show anything. Waits until it is closed.
function showError(title, message) {
  const opts = { stdio: 'ignore', windowsHide: true };
  try {
    if (process.platform === 'darwin') {
      const q = (s) => `"${String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
      spawnSync('osascript', ['-e', `display alert ${q(title)} message ${q(message)} as critical`], opts);
    } else if (process.platform === 'win32') {
      const q = (s) => `'${String(s).replace(/'/g, "''")}'`;
      const ps = `Add-Type -AssemblyName PresentationFramework; [System.Windows.MessageBox]::Show(${q(message)}, ${q(title)}, 'OK', 'Error') | Out-Null`;
      spawnSync('powershell', ['-NoProfile', '-Command', ps], opts);
    } else {
      spawnSync('zenity', ['--error', `--title=${title}`, `--text=${message}`], opts);
    }
  } catch {
    /* the log file still has it */
  }
}

module.exports = { headless, openBrowser, useLogFile, showError };
