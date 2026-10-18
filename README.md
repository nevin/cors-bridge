<p align="center"><img src="assets/logo.svg" width="380" alt="CORS Bridge"></p>

# CORS Bridge

A small local app that removes CORS errors when you test an app in the **Android emulator** or **iOS Simulator**,
without changing the app or the server. Works on Windows and macOS (the iOS Simulator is Mac-only).

It runs a reverse proxy on your computer. Your app keeps calling `https://api.company.com`, but on the simulator
that name points at the proxy. The proxy forwards each request to the real server (over your normal network/VPN)
and adds the CORS headers the browser/WebView needs. It also manages the certificates the proxy uses.

```
App (simulator) --> CORS Bridge (this computer) --> real server
                      adds CORS headers
```

## Requirements

- The desktop app and the command-line programs need nothing installed. Running from source needs Node.js 18 or
  newer (https://nodejs.org); the app itself has no runtime dependencies.
- Android: Android Studio (for `adb`) and an emulator image labelled **Google APIs** (not "Google Play"), because only
  those allow root.
- iOS: Xcode with a simulator (macOS only).

## Start

**Desktop app (recommended).** Nothing to install. Download the file for your system from the
[latest release](https://github.com/nevin/cors-bridge/releases/latest) (or take it from `dist/app` after building),
put it in any folder, also on a USB stick, and open it:

| System | File | How to open |
| --- | --- | --- |
| Mac with Apple silicon (M1 or later) | `CORS-Bridge-<version>-mac-arm64.zip` | Unzip, then see *Opening the app on macOS* below |
| Mac with an Intel processor | `CORS-Bridge-<version>-mac-x64.zip` | Unzip, then see *Opening the app on macOS* below |
| Windows, any PC (Intel/AMD or ARM) | `CORS-Bridge-<version>-windows-portable.exe` | Double-click |
| Windows, faster start | `CORS-Bridge-<version>-win-x64.zip` (ARM PCs: `-win-arm64.zip`) | Unzip, open `CORS Bridge.exe` |

Not sure which Mac you have? Apple menu > **About This Mac**: "Chip: Apple M…" means Apple silicon, "Processor: Intel"
means Intel.

The dashboard opens in its own window, and a CORS Bridge icon appears in the menu bar (macOS) or the taskbar tray
(Windows) with **Start proxy**, **Stop proxy** and **Quit**. Closing the window keeps the proxy running; open it again
from that icon or by opening the app again. **Quit** (in the icon's menu, in the dashboard, or Cmd+Q) stops the proxy
and removes the hosts redirect if that is turned on in Settings. Messages go to `cors-bridge.log` in the data folder
(shown in Settings).

### Opening the app on macOS

CORS Bridge is not signed with an Apple Developer ID yet, so macOS blocks it the first time you open it. You only do
this once per Mac (and again after downloading a new version):

1. Double-click the downloaded zip. Drag **CORS Bridge.app** into **Applications** (or any other folder; for portable
   mode, next to your `cors-bridge-data` folder). Do this before the first start, see *Portable mode*.
2. Double-click **CORS Bridge.app**. macOS says it "Not Opened" or "cannot be opened because Apple cannot check it".
   Click **Done** (not *Move to Trash*).
3. Open **System Settings > Privacy & Security**. Scroll down to the message saying CORS Bridge was blocked and click
   **Open Anyway**. Enter your password, then click **Open Anyway** (or **Open**) once more.

From then on it opens with a double-click. On macOS 14 (Sonoma) and earlier you can instead right-click the app, choose
**Open**, then **Open** again.

If you are comfortable with Terminal, this does the same in one step (it removes the "downloaded from the internet"
mark that macOS checks):

```bash
xattr -dr com.apple.quarantine "/Applications/CORS Bridge.app"
```

Only do this for a copy you downloaded from this project's GitHub releases. To make sure the download is the original,
compare its checksum with the one in `SHA256SUMS.txt` on the release page:

```bash
shasum -a 256 ~/Downloads/CORS-Bridge-*-mac-*.zip
```

If macOS says the app "is damaged and can't be opened", the download was changed or incomplete: delete it and download
it again.

### Opening the app on Windows

Windows SmartScreen may show "Windows protected your PC": choose **More info**, then **Run anyway**. This happens because
the files are not signed with a code-signing certificate yet (see *Building*). To check the download in PowerShell:
`Get-FileHash .\CORS-Bridge-*-windows-portable.exe` and compare with `SHA256SUMS.txt`. The portable `.exe` unpacks
itself to a temporary folder each time it starts, so it takes a few seconds; the zip version starts faster.

### Command-line program

For Linux, or if you prefer a terminal: `cors-bridge-linux-x64`, `cors-bridge-macos-arm64`,
`cors-bridge-win-x64.exe` and the other files in `dist/` after `npm run build:all`. They run in a terminal and open the
dashboard in your browser. Add `--no-open` to stop the browser from opening, and `--console` to keep messages on the
terminal even when the output is redirected. Press Ctrl+C or **Quit** in the dashboard to stop.

### Portable mode

Your rules, certificates and private keys are normally kept in `~/.cors-bridge`
(`%USERPROFILE%\.cors-bridge` on Windows). To keep them next to the app instead, for example on a USB stick, create a
folder named `cors-bridge-data` in the same folder as the app (next to `CORS Bridge.app` on macOS, next to the `.exe`
on Windows) and start the app. Settings shows which folder is in use. Keep in mind that this folder then holds your CA
private key: anyone who copies it can read the traffic of every simulator that trusts your CA, so keep it on a drive
only you use. On macOS, move the app out of the folder you unzipped it in (or into Applications) first; otherwise
macOS runs it from a temporary copy and the folder next to it cannot be found. `CORS_BRIDGE_HOME` overrides both.

### Running from source (with Node)


- Windows: double-click `start.bat`
- macOS: double-click `start.command` (or run `./start.command` in a terminal)
- Anywhere: `node server.js`

A browser tab opens with the dashboard. Keep the terminal window open while you test, or press **Quit** in the
dashboard. With Node, portable mode uses a `cors-bridge-data` folder in the project folder. To run the desktop app from
source: `npm install`, then `npm run app`.

## Use

1. Connect to your VPN, then **Rules > Add rule**. Enter the address your app calls. The real server's IP is found and kept.
2. **Start proxy** (top right). Use **Test** on the rule to check the CORS headers.
3. In **Set up a device** at the top of the Rules tab, press **Set up this device**. It installs the CA (so the
   device trusts the proxy's certificate) and applies the redirect (so the API host name points at this computer).
   **Undo** reverses both. The same steps are also on the **Devices** tab, one at a time.
5. Restart the app and use it. Requests show up in **Live log**.

The checklist shows each step's live state per emulator or simulator. On Android it is read from the emulator itself.
On the iOS Simulator, CORS Bridge remembers what it installed, because the simulator cannot be asked. If you change
rules while a redirect is active, an **Update redirect** banner appears. Undo on the iOS Simulator resets the
simulator's keychain, which also removes other certificates you added to it.

### Tips

- **Test path:** Test calls `GET /` by default, which many APIs answer with 401 or 404. Set a Test path in the rule
  (for example `/health`) that answers without signing in.
- **Groups:** give rules a group such as `dev` or `uat` and switch a whole group on or off at the top of the rule list.
  Groups can hold rules for the same address. Turning one group on pauses the others for that address.
- **Sharing with the team:** **Export** saves your rules and settings as JSON. **Import** loads such a file (keep and
  update your rules, or replace them). Certificates and the "other devices on my network" setting are not included.
  Before anything is saved, the import shows where each address will be forwarded and flags rules that skip the
  certificate check, use plain http, or let any website read the answers. Imported rules arrive paused. Only import
  files from people you trust: a rule can send an address to any server.
- **Who may read the answers:** by default only your app gets CORS headers: `capacitor://localhost`,
  `ionic://localhost`, and `http(s)://localhost`, `127.0.0.1` or `10.0.2.2` on any port. Add other origins (for example
  a dev server on your LAN IP) in the rule's CORS options. Other websites get no CORS headers, so a page you happen to
  visit while the redirect is on cannot read your API with your cookies. "Any website, with cookies" exists for short
  tests only. Rules saved by older versions move to the app-only setting.
- **Live log:** click a row to see the request headers, the real server's response headers and the CORS headers
  CORS Bridge added. Tokens and cookies are shortened. **Pause** holds new requests until you resume.

### Using your company's certificate

On the **Certificates** tab, **Import certificate**:

- *Company CA certificate only* (no key): saved as install-only, so you can install it on devices.
- *Server certificate + private key* for your API host name (PEM): the proxy serves it for that host. If the
  device already trusts your company CA, nothing needs installing.
- *Company CA certificate + its private key* (RSA): choose **Use for signing** and CORS Bridge issues server
  certificates from it.

Get security approval before using any company key. Ask for a dedicated development certificate or CA, never a
production signing key. A password-protected `.pfx` must first be converted to PEM:
`openssl pkcs12 -in file.pfx -nodes -out all.pem` (OpenSSL ships with Git for Windows).

## What it changes on your computer

- **Network, VPN, DNS servers, routes, system proxy:** nothing.
- **Hosts file (iOS Simulator only):** one clearly marked block in `/etc/hosts` pointing your rule host names at
  `127.0.0.1`. Apply and remove it from the Devices tab. While it is active, those host names on this Mac also go
  through the proxy. The proxy is stopped = those names will not reach the real server from this Mac until you
  remove the block. Your company's security tools may monitor or block hosts-file edits.
- **Android emulator:** only the emulator's own files change (hosts file and trust store), and they reset on a cold boot.
- **Certificates:** nothing is added to the Mac or Windows trust store. The CA goes into the simulators only.
- **Files:** rules, certificates and private keys are in `~/.cors-bridge` (`%USERPROFILE%\.cors-bridge` on Windows).

The proxy only accepts connections from this computer (the Android emulator's `10.0.2.2` counts as this computer).
For a real phone, **Settings > Let other devices on my network use the proxy** lets in only the IP addresses you list.
It turns itself off when CORS Bridge restarts, because those devices reach your company servers through your VPN.
The dashboard only listens on `127.0.0.1` and needs the one-time token from the startup link.

The hosts-file redirect is removed when CORS Bridge quits: with Ctrl+C, by closing its window, or after a crash
(you may be asked for the administrator password). You can turn this off in Settings. When the hosts file needs
administrator rights, the new text is passed inside the administrator command itself rather than through a temporary
file, so another program cannot swap what gets written.

## Limits

- If the app **pins** the server certificate, no proxy can intercept it. That needs a change in the app.
- HTTP/1.1 only (fine for WebViews and REST). WebSockets pass through.
- Android CA and redirect are applied in memory and are lost when the emulator cold-boots. Apply them again.
- The device helpers (adb/simctl, administrator prompts for the hosts file) are tested against stand-ins, not
  against every Android/macOS/Windows version. If one fails, the dashboard shows the exact step and message.

## Troubleshooting

- *Port 443 is already in use:* stop the program using it (`netstat -ano | findstr :443` on Windows,
  `sudo lsof -i :443` on macOS), or give the rule another listen port.
- *Certificate error in the app:* the CA is not installed on that device, or the app pins certificates.
- *Nothing in Live log:* the redirect is not applied on that device, or the app was not restarted afterwards.
- *504 in the app or the Live log:* the real server did not accept a connection within 10 seconds (check your VPN
  and the server address in the rule), or sent nothing for 120 seconds. Both times can be changed in **Settings**.
- *Real server certificate not trusted by Node:* the start scripts already trust your OS certificates. Otherwise
  untick "Verify the real server certificate" in the rule, or set `NODE_EXTRA_CA_CERTS` to your company CA file.

## Building

**Desktop app** (Electron, built with electron-builder; run `npm install` once):

```
npm run app:mac      # macOS zips, Apple silicon and Intel (on a Mac)
npm run app:win      # Windows portable .exe and zips, x64 and ARM (works on a Mac too)
npm run app:all      # both
```

Output goes to `dist/app`. The app runs the same code as the command-line program in a separate engine process
(`electron/engine.js`, an Electron utility process), so a crash or slow work in the proxy cannot freeze or close the
window; if the engine stops unexpectedly, the app starts it again and switches the proxy back on. The window is locked to the local dashboard (no other sites, no new windows, no browser
permissions). Electron's "fuses" are set so the packaged app cannot be used as a general Node runtime (`ELECTRON_RUN_AS_NODE`, `NODE_OPTIONS` and `--inspect` are
off) and it checks that its own code archive has not been changed. Icons come from `public/logo.svg`; after changing
the logo, run `npm run icons` to remake `assets/icon.png`, the tray icons and `assets/logo.svg`.

Signing before sharing the files:

- **macOS:** the build is signed ad hoc, which runs on your own Mac; on other Macs people use right-click > Open once.
  To distribute without that, sign with an Apple Developer ID, set `"hardenedRuntime": true` under `build.mac` in
  `package.json`, and notarize.
- **Windows:** the `.exe` files are unsigned, so SmartScreen warns. Sign them with your company's code-signing
  certificate (electron-builder reads it from `CSC_LINK` / `CSC_KEY_PASSWORD`).

Rebuild when Electron publishes security updates (`npm install --save-exact --save-dev electron@<version>`), the same
way you would update Node.

**Command-line programs** (Node "single executable", no npm packages needed):

```
npm run build        # this computer only
npm run build:all    # all six (macOS ones only when building on a Mac)
```

Output goes to `dist/`. Each executable contains the Node version that runs the build, so build with a supported LTS
release, for example `npx -y node@24 scripts/build-sea.js all`. The script bundles `server.js` and `lib/`, embeds
`public/`, and injects them into Node with `postject` (fetched through `npx`). For other platforms it downloads the
official Node build from nodejs.org and checks it against `SHASUMS256.txt`; downloads are cached in `build/node-cache`.
The macOS ones are signed ad hoc; the Windows ones are unsigned.

## Tests

`npm test` runs 47 checks, including connection reuse and the waiting times to the real server: certificates (verified with OpenSSL), the proxy and CORS behaviour, WebSockets, the
hosts-file editing, dashboard security, import/export, the Android and iOS flows against a fake `adb` and `xcrun`,
portable mode, the single running copy and Quit. `npm run test:electron` runs the same checks with the Node inside
Electron (which uses BoringSSL instead of OpenSSL), the way the desktop app runs them.
