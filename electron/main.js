'use strict';
// The desktop app: runs CORS Bridge (the same code as the command-line program) and shows the dashboard in its own
// window, with a menu-bar / tray icon. Closing the window keeps the proxy running; Quit stops everything.
const path = require('path');
const { app, BrowserWindow, Tray, Menu, dialog, session, shell, nativeTheme, Notification } = require('electron');

// Where the app really is, for portable mode. A Windows portable .exe runs from a temporary copy and passes its
// real folder in PORTABLE_EXECUTABLE_DIR. Must be set before lib/ is loaded.
function appFolder() {
  if (process.env.PORTABLE_EXECUTABLE_DIR) return process.env.PORTABLE_EXECUTABLE_DIR;
  const exe = app.getPath('exe');
  const m = /^(.*\.app)[/\\]Contents[/\\]MacOS[/\\][^/\\]+$/.exec(exe);
  return m ? path.dirname(m[1]) : path.dirname(exe);
}
if (app.isPackaged && !process.env.CORS_BRIDGE_APP_DIR) process.env.CORS_BRIDGE_APP_DIR = appFolder();

const P = require('../lib/paths');
const instance = require('../lib/instance');
const desktop = require('../lib/desktop');
const { startCorsBridge } = require('../lib/app');

const ASSETS = path.join(__dirname, '..', 'assets');
const isMac = process.platform === 'darwin';

let bridge = null;
let win = null;
let tray = null;
let quitting = false;
let toldAboutTray = false;

// ------------------------------------------------------------------ one copy only

if (!app.requestSingleInstanceLock()) {
  app.quit(); // the running copy gets 'second-instance' and shows its window
} else {
  app.on('second-instance', () => showWindow());
  app.whenReady().then(start, fail);
}

function fail(e) {
  console.error(e && e.stack ? e.stack : e);
  dialog.showErrorBox('CORS Bridge could not start', `${(e && e.message) || e}\n\nDetails are in ${P.LOG_FILE}`);
  app.exit(1);
}

// ------------------------------------------------------------------ start

async function start() {
  P.ensureDirs();
  if (app.isPackaged) desktop.useLogFile(P.LOG_FILE);

  // The command-line program may already be running with the same data folder.
  const other = await instance.findRunning();
  if (other) {
    dialog.showErrorBox('CORS Bridge is already running', 'It was started from a terminal. Quit that copy first (Ctrl+C, or Quit in its dashboard), then open the app again.');
    app.exit(0);
    return;
  }

  lockDown();
  // macOS needs an Edit menu for copy and paste in text fields; Quit in the app menu runs the clean-up below.
  Menu.setApplicationMenu(isMac ? Menu.buildFromTemplate([{ role: 'appMenu' }, { role: 'editMenu' }, { role: 'viewMenu' }, { role: 'windowMenu' }]) : null);
  bridge = await startCorsBridge({ onQuit: () => quit() });
  if (P.PORTABLE) console.log(`  Portable mode: data is kept in ${P.DATA_DIR}`);

  // Sign the window in with the dashboard token as a cookie, so the token never appears in an address.
  await session.defaultSession.cookies.set({ url: bridge.origin, name: 'cb_token', value: bridge.token, httpOnly: true, sameSite: 'strict' });

  bridge.engine.on('status', updateTray);
  createTray();
  showWindow();
}

// ------------------------------------------------------------------ security

// The window only ever shows the local dashboard: no other sites, no new windows, no browser permissions.
function lockDown() {
  session.defaultSession.setPermissionRequestHandler((wc, permission, callback) => callback(false));
  session.defaultSession.setPermissionCheckHandler(() => false);
  app.on('web-contents-created', (event, contents) => {
    contents.on('will-attach-webview', (e) => e.preventDefault());
    contents.setWindowOpenHandler(({ url }) => {
      if (/^https?:\/\//.test(url) && !url.startsWith(bridge.origin)) shell.openExternal(url);
      return { action: 'deny' };
    });
    contents.on('will-navigate', (e, url) => {
      if (!url.startsWith(`${bridge.origin}/`)) e.preventDefault();
    });
  });
}

// ------------------------------------------------------------------ window

function showWindow() {
  if (!bridge) return;
  if (isMac && app.dock) app.dock.show();
  if (win) {
    if (win.isMinimized()) win.restore();
    win.show();
    win.focus();
    return;
  }
  win = new BrowserWindow({
    width: 1100,
    height: 820,
    minWidth: 640,
    minHeight: 480,
    title: 'CORS Bridge',
    show: false,
    backgroundColor: nativeTheme.shouldUseDarkColors ? '#0f1a22' : '#eef2f5',
    autoHideMenuBar: true,
    webPreferences: { contextIsolation: true, nodeIntegration: false, sandbox: true, spellcheck: false },
  });
  win.loadURL(`${bridge.origin}/`);
  win.once('ready-to-show', () => win.show());
  // Closing the window keeps CORS Bridge running in the menu bar / tray, so the proxy keeps working.
  win.on('close', (e) => {
    if (quitting) return;
    e.preventDefault();
    win.hide();
    if (isMac && app.dock) app.dock.hide();
    if (!toldAboutTray && Notification.isSupported()) {
      toldAboutTray = true;
      new Notification({
        title: 'CORS Bridge is still running',
        body: `The proxy keeps working. Use the CORS Bridge icon in the ${isMac ? 'menu bar' : 'taskbar tray'} to open it again or to quit.`,
      }).show();
    }
  });
  win.on('closed', () => {
    win = null;
  });
}

// ------------------------------------------------------------------ tray

function trayIcon() {
  return path.join(ASSETS, isMac ? 'trayTemplate.png' : 'tray-windows.png');
}

function createTray() {
  tray = new Tray(trayIcon());
  if (!isMac) tray.on('click', () => showWindow()); // on macOS a click opens the menu
  updateTray();
}

function updateTray() {
  if (!tray || !bridge) return;
  const running = bridge.engine.running;
  tray.setToolTip(`CORS Bridge: proxy ${running ? 'running' : 'stopped'}`);
  tray.setContextMenu(
    Menu.buildFromTemplate([
      { label: 'Open CORS Bridge', click: showWindow },
      { type: 'separator' },
      { label: running ? 'Proxy running' : 'Proxy stopped', enabled: false },
      running ? { label: 'Stop proxy', click: () => bridge.engine.stop() } : { label: 'Start proxy', click: startProxy },
      { type: 'separator' },
      { label: 'Quit CORS Bridge', click: () => quit() },
    ])
  );
}

async function startProxy() {
  try {
    await bridge.engine.start();
  } catch (e) {
    showWindow();
    dialog.showMessageBox(win, { type: 'warning', message: 'The proxy could not start', detail: e.message });
  }
}

// ------------------------------------------------------------------ quit

// Stops the proxy and removes the hosts redirect (if that setting is on) before the app ends.
async function quit() {
  if (quitting) return;
  quitting = true;
  try {
    if (bridge) await bridge.stop();
  } finally {
    if (tray) tray.destroy();
    app.exit(0);
  }
}

app.on('before-quit', (e) => {
  // Cmd+Q, the app menu, logging out: run the same clean-up first.
  if (!quitting) {
    e.preventDefault();
    quit();
  }
});
app.on('activate', () => showWindow()); // Dock icon clicked
app.on('window-all-closed', () => {
  /* keep running in the menu bar / tray */
});
