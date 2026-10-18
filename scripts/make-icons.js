'use strict';
// Makes the PNG icons in assets/ from SVG, with transparent backgrounds. Run after changing an icon:
//   npx electron scripts/make-icons.js
// electron-builder turns assets/icon.png into the macOS .icns and the Windows .ico when packaging.
const fs = require('fs');
const path = require('path');
const { app, BrowserWindow } = require('electron');

const ASSETS = path.join(__dirname, '..', 'assets');

// The logo (public/logo.svg) is the one source. Its <style> only switches colours for dark mode, so dropping it
// gives the light colours, which is what an app icon needs.
const logo = fs.readFileSync(path.join(__dirname, '..', 'public', 'logo.svg'), 'utf8').replace(/<style>[\s\S]*?<\/style>/, '');
const logoBox = /viewBox="([^"]+)"/.exec(logo)[1].split(/\s+/).map(Number);
const logoInner = logo.replace(/^[\s\S]*?<svg[^>]*>/, '').replace(/<\/svg>\s*$/, '');

// App icon: the logo on a light rounded tile, the shape macOS uses for app icons.
const appIcon = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024">
  <defs><linearGradient id="tile" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#ffffff"/><stop offset="1" stop-color="#e9eff4"/></linearGradient></defs>
  <rect x="100" y="100" width="824" height="824" rx="185" fill="url(#tile)" stroke="#d3dde6" stroke-width="4"/>
  <svg x="172" y="262" width="680" height="${Math.round((680 * logoBox[3]) / logoBox[2])}" viewBox="${logoBox.join(' ')}">${logoInner}</svg>
</svg>`;
fs.writeFileSync(path.join(ASSETS, 'icon.svg'), `${appIcon}\n`);

// Logo with the name under it, for the README. Keeps the dark-mode colours of the logo.
const logoStyle = /<style>[\s\S]*?<\/style>/.exec(fs.readFileSync(path.join(__dirname, '..', 'public', 'logo.svg'), 'utf8'))[0]
  .replace('.cut-fill { fill: #16242e; }', '.cut-fill { fill: #16242e; }\n      .word-navy { fill: #9cc3ea; }');
const wordmark = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 900 560" role="img" aria-label="CORS Bridge">
  ${logoStyle}
  <svg x="190" y="20" width="520" height="${Math.round((520 * logoBox[3]) / logoBox[2])}" viewBox="${logoBox.join(' ')}">${logoInner}</svg>
  <text x="450" y="525" text-anchor="middle" font-family="'Arial Black','Helvetica Neue',Arial,sans-serif" font-weight="900" font-size="92" letter-spacing="1"><tspan class="word-navy" fill="#0f2742">CORS </tspan><tspan fill="#0e9f6e">BRIDGE</tspan></text>
</svg>`;
fs.writeFileSync(path.join(ASSETS, 'logo.svg'), `${wordmark}\n`);

// Menu-bar icon: a "template" (black on transparent; macOS colours it for light and dark menu bars).
// Simplified so it still reads at 16 pixels: an outlined back window and a solid front window with the two
// arrows cut out of it.
const trayTemplate = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 40 40">
  <defs>
    <mask id="gap"><rect width="40" height="40" fill="#fff"/><rect x="14" y="12" width="24" height="25" rx="4" fill="#000" stroke="#000" stroke-width="5"/></mask>
    <mask id="arrows"><rect width="40" height="40" fill="#fff"/>
      <g fill="none" stroke="#000" stroke-width="2.8" stroke-linecap="round" stroke-linejoin="round">
        <path d="M18.5 20.5h13M28 17l3.5 3.5L28 24"/><path d="M33.5 29h-13M24 25.5L20.5 29l3.5 3.5"/>
      </g>
    </mask>
  </defs>
  <rect x="2.5" y="4" width="21" height="23" rx="4" fill="none" stroke="#000" stroke-width="2.8" mask="url(#gap)"/>
  <rect x="14" y="12" width="24" height="25" rx="4" fill="#000" mask="url(#arrows)"/>
</svg>`;

const outputs = [
  { svg: appIcon, size: 1024, file: 'icon.png' },
  { svg: appIcon, size: 32, file: 'tray-windows.png' },
  { svg: trayTemplate, size: 16, file: 'trayTemplate.png' },
  { svg: trayTemplate, size: 32, file: 'trayTemplate@2x.png' },
];

async function render(win, svg, size) {
  const sized = svg.replace('<svg ', `<svg width="${size}" height="${size}" `);
  const html = `<!doctype html><html><body style="margin:0;background:transparent;overflow:hidden">${sized}</body></html>`;
  win.setContentSize(size, size);
  await win.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(html)}`);
  await new Promise((r) => setTimeout(r, 150));
  const img = await win.webContents.capturePage({ x: 0, y: 0, width: size, height: size });
  return img.resize({ width: size, height: size, quality: 'best' }).toPNG();
}

app.disableHardwareAcceleration();
app.whenReady().then(async () => {
  const win = new BrowserWindow({ show: false, frame: false, transparent: true, useContentSize: true, webPreferences: { offscreen: true } });
  for (const o of outputs) {
    fs.writeFileSync(path.join(ASSETS, o.file), await render(win, o.svg, o.size));
    console.log(`  assets/${o.file} (${o.size}x${o.size})`);
  }
  app.quit();
});
