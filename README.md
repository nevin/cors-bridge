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

- Node.js 18 or newer (https://nodejs.org). Nothing else to install, there are no dependencies.
- Android: Android Studio (for `adb`) and an emulator image labelled **Google APIs** (not "Google Play"), because only
  those allow root.
- iOS: Xcode with a simulator (macOS only).

## Start

**Without Node (standalone executable):** run the file for your system from `dist/` (see *Building the executables*).

| System | File |
| --- | --- |
| Windows (Intel/AMD, ARM) | `cors-bridge-win-x64.exe`, `cors-bridge-win-arm64.exe` |
| macOS (Apple silicon, Intel) | `cors-bridge-macos-arm64`, `cors-bridge-macos-x64` |
| Linux (x64, ARM) | `cors-bridge-linux-x64`, `cors-bridge-linux-arm64` |

The executables trust the certificates installed in your operating system for the real server, like the start
scripts below. Add `--no-open` to stop the browser from opening.

**With Node:**

- Windows: double-click `start.bat`
- macOS: double-click `start.command` (or run `./start.command` in a terminal)
- Anywhere: `node server.js`

A browser tab opens with the dashboard. Keep the terminal window open while you test.

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
- *Real server certificate not trusted by Node:* the start scripts already trust your OS certificates. Otherwise
  untick "Verify the real server certificate" in the rule, or set `NODE_EXTRA_CA_CERTS` to your company CA file.

## Building the executables

```
npm run build        # this computer only
npm run build:all    # all six (macOS ones only when building on a Mac)
```

Output goes to `dist/`. Each executable contains the Node version that runs the build, so build with a supported LTS
release (currently Node 22). The script bundles `server.js` and `lib/`, embeds `public/`, and injects them into Node
with `postject` (fetched through `npx`). For other platforms it downloads the official Node build from nodejs.org and
checks it against `SHASUMS256.txt`; downloads are cached in `build/node-cache`.

Signing before sharing the files:

- **macOS:** the build signs ad hoc, which runs on your own Mac. A copy downloaded on another Mac is blocked by
  Gatekeeper until you right-click > Open (or `xattr -d com.apple.quarantine <file>`). To distribute properly, sign with
  a Developer ID and notarize.
- **Windows:** injecting breaks Node's own signature, so the `.exe` is unsigned and SmartScreen may warn. Sign it with
  your company's code-signing certificate (`signtool sign ...`).
- **Linux:** nothing needed; `chmod +x` if the permission was lost in transfer.

## Tests

`npm test` runs 21 checks: certificates (verified with OpenSSL), the proxy and CORS behaviour, WebSockets, the
hosts-file editing, dashboard security and the Android flow against a fake `adb`.
