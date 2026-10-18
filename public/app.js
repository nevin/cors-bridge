(() => {
  'use strict';

  // ---------------------------------------------------------------- helpers
  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    let value;
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === false || v == null) continue;
      if (k === 'class') el.className = v;
      else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else if (k === 'value') value = v;
      else if (['checked', 'disabled', 'selected', 'open'].includes(k)) el[k] = !!v;
      else el.setAttribute(k, v === true ? '' : v);
    }
    for (const kid of kids.flat(Infinity)) {
      if (kid == null || kid === false) continue;
      el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
    }
    if (value !== undefined) el.value = value;
    return el;
  }

  async function api(method, path, body) {
    let r;
    try {
      r = await fetch(path, {
        method,
        headers: { 'content-type': 'application/json' },
        body: body ? JSON.stringify(body) : undefined,
      });
    } catch {
      setOffline('down');
      throw new Error('CORS Bridge is not running. Start it again, then try once more.');
    }
    if (r.status === 401) setOffline('expired');
    else if (ui.offline) setOffline(null);
    let data = {};
    try {
      data = await r.json();
    } catch {
      /* not json */
    }
    if (!r.ok) {
      const e = new Error(data.error || (r.status === 401 ? 'Session expired. Open the address printed in the terminal window again.' : `Request failed (${r.status})`));
      e.data = data;
      throw e;
    }
    return data;
  }

  // action = { label, fn } adds a button (for example Undo) and keeps the toast up a little longer.
  const toastBox = document.getElementById('toast');
  function toast(msg, kind, action) {
    const box = toastBox;
    if (!document.getElementById('dlg').open && box.parentElement !== document.body) document.body.append(box);
    const el = h('div', { class: kind || '' }, h('span', null, msg));
    if (action)
      el.append(h('button', { type: 'button', class: 'toast-btn', onclick: () => { el.remove(); action.fn(); } }, action.label));
    box.append(el);
    setTimeout(() => el.remove(), action ? UNDO_MS : kind === 'bad' ? 9000 : 3500);
    return el;
  }
  const UNDO_MS = 7000;

  async function act(btn, fn) {
    if (btn) btn.disabled = true;
    try {
      return await fn();
    } catch (e) {
      toast(e.message, 'bad');
      if (e.data && e.data.steps) ui.output = { steps: e.data.steps, error: e.message };
      render();
      return undefined;
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  const fmtDate = (iso) => new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  const portSuffix = (scheme, port) => ((scheme === 'https' && port === 443) || (scheme === 'http' && port === 80) ? '' : `:${port}`);
  const ruleUrl = (r) => `${r.scheme}://${r.host}${portSuffix(r.scheme, r.listenPort)}`;

  // ---------------------------------------------------------------- state
  let S = null;
  let tab = location.hash.slice(1) || 'rules';
  const ui = {
    tests: {},
    android: null,
    ios: null,
    output: null,
    logs: [],
    logFilter: '',
    logPaused: false,
    logQueue: [],
    logOpen: new Set(),
    caChoice: null,
    loadingDevices: false,
    offline: null, // null | 'down' | 'expired'
    pending: new Map(), // deletes waiting for Undo: key -> { timer, run }
    setupAt: {}, // device key -> time of the last setup, to tell when the app sends requests again
  };

  function setOffline(kind) {
    if (ui.offline === kind) return;
    const was = ui.offline;
    ui.offline = kind;
    if (kind === 'down') pollUntilBack();
    if (was && !kind) refresh().catch(() => {});
    else render();
  }

  let polling = false;
  async function pollUntilBack() {
    if (polling) return;
    polling = true;
    while (ui.offline === 'down') {
      await new Promise((r) => setTimeout(r, 3000));
      try {
        const r = await fetch('/api/state', { cache: 'no-store' });
        if (r.status === 401) setOffline('expired');
        else if (r.ok) {
          S = await r.json();
          setOffline(null);
          loadDevices();
        }
      } catch {
        /* still down */
      }
    }
    polling = false;
  }

  // ---------------------------------------------------------------- derived state
  const isPending = (key) => ui.pending.has(key);
  const rules = () => S.rules.filter((r) => !isPending(`rule:${r.id}`));
  const enabledRules = () => rules().filter((r) => r.enabled);
  const allCerts = () => S.certs.filter((c) => !isPending(`cert:${c.id}`));
  const wantEntries = (ip) => enabledRules().map((r) => ({ ip, host: r.host }));
  const entryKey = (list) => [...new Set(list.map((e) => `${e.ip} ${e.host}`))].sort().join('|');
  const sameEntries = (a, b) => entryKey(a) === entryKey(b);
  const androidIp = () => S.settings.androidHostIp || '10.0.2.2';
  const signingCa = () => {
    const cas = allCerts().filter((c) => c.kind === 'ca');
    return cas.find((c) => c.isActive) || cas[0] || null;
  };
  const groupsOf = (list) => [...new Set(list.map((r) => r.group).filter(Boolean))].sort();

  function setState(s) {
    if (s) S = s;
  }

  async function refresh() {
    S = await api('GET', '/api/state');
    render();
  }

  // ---------------------------------------------------------------- shell
  function logo() {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 40 40');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '2.6');
    svg.setAttribute('stroke-linecap', 'round');
    svg.setAttribute('aria-hidden', 'true');
    const p = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    p.setAttribute('d', 'M3 28h34M7 28c0-9 5-14 13-14s13 5 13 14M12 28v-6M20 28V14M28 28v-6');
    svg.append(p);
    return svg;
  }

  function bridgeStrip() {
    const enabled = enabledRules();
    const on = S.proxy.running;
    return h(
      'section',
      { class: `bridge${on ? ' on' : ''}`, 'aria-label': 'How requests flow' },
      h('div', { class: 'node' }, h('h3', null, 'Your app'), h('div', { class: 'muted small' }, 'Android emulator or iOS Simulator calls the API address as usual.')),
      h('div', { class: 'span' }, h('i')),
      h(
        'div',
        { class: 'node mid' },
        h('h3', null, 'CORS Bridge'),
        on
          ? h('div', { class: 'small' }, S.proxy.listening.map((l) => h('div', { class: 'mono' }, `${l.scheme}:// port ${l.port}  (${l.hosts.length} host${l.hosts.length === 1 ? '' : 's'})`)))
          : h('div', { class: 'muted small' }, enabled.length ? 'Stopped. Press Start proxy.' : 'Stopped. Add a rule first.')
      ),
      h('div', { class: 'span' }, h('i')),
      h(
        'div',
        { class: 'node' },
        h('h3', null, 'Real server'),
        enabled.length
          ? h('div', { class: 'small' }, enabled.slice(0, 3).map((r) => h('div', { class: 'mono' }, `${r.host} → ${r.upstreamHost}`)), enabled.length > 3 ? h('div', { class: 'muted' }, `and ${enabled.length - 3} more`) : null)
          : h('div', { class: 'muted small' }, 'Reached over your normal network or VPN, exactly as before.')
      )
    );
  }

  function lanBanner() {
    if (!S.settings.allowLan) return null;
    return h('div', { class: 'notice warn banner' }, h('strong', null, `Other devices can use the proxy: ${(S.settings.lanClients || []).join(', ')}.`),
      h('div', { class: 'small' }, 'They reach your real servers through this computer and your VPN. Turn this off when you are done.'),
      h('div', { class: 'actions' }, h('button', { class: 'btn small', onclick: (e) => act(e.target, async () => { setState(await api('POST', '/api/settings', { allowLan: false })); render(); toast('Only this computer can use the proxy now'); }) }, 'Turn off')));
  }

  function offlineBanner() {
    if (!ui.offline) return null;
    if (ui.offline === 'expired')
      return h('div', { class: 'notice bad banner', role: 'alert' }, h('strong', null, 'This dashboard session has ended.'), h('div', { class: 'small' }, 'CORS Bridge was probably restarted. Open the address printed in its terminal window (the line that starts with Dashboard:).'));
    return h('div', { class: 'notice bad banner', role: 'alert' }, h('strong', null, 'CORS Bridge is not running.'), h('div', { class: 'small' }, 'Start it again (start.command, start.bat or node server.js). This page reconnects by itself.'));
  }

  function render() {
    const app = document.getElementById('app');
    if (!S) {
      app.replaceChildren(h('div', { class: 'shell' }, offlineBanner()));
      return;
    }
    const scroll = window.scrollY;
    const tabs = [
      ['rules', 'Rules'],
      ['certs', 'Certificates'],
      ['devices', 'Devices'],
      ['log', 'Live log'],
      ['settings', 'Settings'],
      ['help', 'Help'],
    ];
    const running = S.proxy.running;
    const panel = { rules: rulesPanel, certs: certsPanel, devices: devicesPanel, log: logPanel, settings: settingsPanel, help: helpPanel }[tab] || rulesPanel;
    app.replaceChildren(
      h(
        'div',
        { class: 'shell' },
        h(
          'header',
          { class: 'top' },
          h('div', { class: 'brand' }, logo(), h('div', null, h('h1', null, 'CORS Bridge'), h('div', { class: 'muted small' }, 'Fix CORS errors in simulators without changing the app or the server'))),
          h(
            'div',
            { class: 'top-actions' },
            ui.offline ? h('span', { class: 'chip bad' }, h('span', { class: 'dot' }), 'Not connected') : h('span', { class: `chip ${running ? 'ok' : ''}` }, h('span', { class: 'dot' }), running ? 'Proxy running' : 'Proxy stopped'),
            ui.offline
              ? null
              : running
              ? h('button', { class: 'btn', onclick: (e) => act(e.target, async () => { setState(await api('POST', '/api/proxy/stop')); render(); }) }, 'Stop proxy')
              : startButton()
          )
        ),
        offlineBanner(),
        lanBanner(),
        bridgeStrip(),
        h('nav', { class: 'tabs', role: 'tablist' }, tabs.map(([id, label]) => h('button', { role: 'tab', 'aria-selected': String(tab === id), onclick: () => go(id) }, label))),
        h('main', null, panel())
      )
    );
    window.scrollTo(0, scroll);
  }

  function startButton(small) {
    return h('button', { class: `btn primary${small ? ' small' : ''}`, disabled: !enabledRules().length, onclick: (e) => act(e.target, async () => { setState(await api('POST', '/api/proxy/start')); render(); toast('Proxy started'); }) }, 'Start proxy');
  }

  function go(id) {
    tab = id;
    location.hash = id;
    refresh().catch(() => {}); // pick up changes made elsewhere (another tab, the terminal)
    if (id === 'devices' || id === 'rules') loadDevices();
    if (id === 'log') loadLogs();
    render();
  }

  // ---------------------------------------------------------------- delete with undo
  // The item disappears at once and is only deleted after the Undo toast is gone.
  function deleteLater(key, label, run) {
    const timer = setTimeout(() => finishDelete(key), UNDO_MS);
    ui.pending.set(key, { timer, run });
    render();
    toast(`Deleted ${label}`, '', {
      label: 'Undo',
      fn: () => {
        const p = ui.pending.get(key);
        if (!p) return;
        clearTimeout(p.timer);
        ui.pending.delete(key);
        render();
        toast(`Restored ${label}`);
      },
    });
  }

  async function finishDelete(key) {
    const p = ui.pending.get(key);
    if (!p) return;
    try {
      const out = await p.run();
      if (out && out.state) setState(out.state);
      if (out && out.warning) toast(out.warning, 'bad');
    } catch (e) {
      toast(`Could not delete: ${e.message}`, 'bad');
    }
    ui.pending.delete(key);
    render();
  }

  // Leaving the page must not lose a delete the user already confirmed.
  window.addEventListener('pagehide', () => {
    for (const key of ui.pending.keys()) {
      const [kind, id] = key.split(':');
      fetch(`/api/${kind === 'rule' ? 'rules' : 'certs'}/${id}`, { method: 'DELETE', keepalive: true }).catch(() => {});
    }
  });

  // ---------------------------------------------------------------- device setup state
  // Every booted emulator or simulator, with the state of each setup step.
  function deviceList() {
    const out = [];
    for (const d of (ui.android && ui.android.devices) || []) {
      if (d.state !== 'device') continue;
      out.push({ key: `android:${d.serial}`, platform: 'android', id: d.serial, name: d.model ? `${d.model.replace(/_/g, ' ')} (${d.serial})` : d.serial, sub: `Android ${d.release || '?'}${d.rootable ? '' : ' · root not available on this image'}`, caInstalled: d.caInstalled || [], redirect: d.hostsEntries || [], want: wantEntries(androidIp()), raw: d });
    }
    for (const d of (ui.ios && ui.ios.devices) || []) {
      out.push({ key: `ios:${d.udid}`, platform: 'ios', id: d.udid, name: d.name, sub: d.runtime, caInstalled: d.caInstalled || [], redirect: S.hosts.entries, want: wantEntries('127.0.0.1'), raw: d });
    }
    return out;
  }

  function caState(dev) {
    const ca = signingCa();
    if (ca && dev.caInstalled.includes(ca.id)) return { done: true, text: ca.name };
    if (dev.caInstalled.length) return { warn: true, text: 'A different CA is installed. Set up again to install the signing CA.' };
    return { text: dev.platform === 'android' ? 'Not installed on this emulator.' : 'Not installed by CORS Bridge on this simulator.' };
  }

  function redirectState(dev) {
    if (!dev.redirect.length) return { text: dev.platform === 'ios' ? 'This Mac does not redirect the API host names yet.' : 'The emulator still reaches the real server directly.' };
    if (!dev.want.length) return { warn: true, text: 'Redirect is on, but no rule is on.' };
    if (!sameEntries(dev.redirect, dev.want)) return { warn: true, text: 'Out of date: it does not match the rules that are on.' };
    return { done: true, text: dev.want.map((e) => e.host).join(', ') };
  }

  function trafficSince(ts) {
    const hostsOn = new Set(enabledRules().map((r) => r.host));
    return ui.logs.some((l) => l.ts > ts && hostsOn.has(l.host) && l.status);
  }

  function setupSteps(dev) {
    const on = enabledRules();
    const ca = dev ? caState(dev) : { text: 'Waiting for a device.' };
    const rd = dev ? redirectState(dev) : { text: 'Waiting for a device.' };
    const since = dev && ui.setupAt[dev.key];
    // Requests cannot be traced to one device, so they only count once this device is set up.
    const traffic = !!dev && !!ca.done && !!rd.done && trafficSince(since || 0);
    return [
      { label: 'Rule added', done: on.length > 0, text: on.length ? `${on.length} rule${on.length === 1 ? '' : 's'} on` : rules().length ? 'All rules are paused.' : 'Add the address your app calls.' },
      { label: 'Proxy running', done: S.proxy.running, text: S.proxy.running ? 'Listening on this computer' : 'Press Start proxy.' },
      { label: 'CA installed', ...ca },
      { label: 'Redirect applied', ...rd },
      { label: 'App restarted', done: traffic, text: traffic ? 'Requests are reaching the proxy.' : since ? 'Restart the app, then use it.' : 'Restart the app after setup. Done when its requests show up.' },
    ];
  }

  function stepList(steps) {
    return h('ol', { class: 'checklist' }, steps.map((st, i) =>
      h('li', { class: st.done ? 'done' : st.warn ? 'warn' : '' },
        h('span', { class: 'tick', 'aria-hidden': 'true' }, st.done ? '✓' : st.warn ? '!' : String(i + 1)),
        h('div', null, h('div', { class: 'step-label' }, st.label, h('span', { class: 'sr' }, st.done ? ' (done)' : st.warn ? ' (needs attention)' : ' (to do)')), h('div', { class: 'small muted' }, st.text)))));
  }

  async function runSetup(btn, dev, undo) {
    await act(btn, async () => {
      ui.output = { steps: [{ label: undo ? 'Undoing...' : 'Setting up...', ok: true }] };
      render();
      const out = await api('POST', `/api/devices/${undo ? 'undo' : 'setup'}`, { platform: dev.platform, id: dev.id, caId: undo ? undefined : (signingCa() || {}).id });
      setState(out.state);
      ui.output = out;
      if (!undo) ui.setupAt[dev.key] = Date.now();
      else delete ui.setupAt[dev.key];
      toast(undo ? `${dev.name} is back to normal` : `${dev.name} is set up. Restart the app.`);
      await loadDevices();
    });
  }

  function setupSection() {
    const devs = deviceList();
    const head = h('div', { class: 'setup-head' }, h('h3', null, 'Set up a device'), h('button', { class: 'btn small', onclick: loadDevices }, ui.loadingDevices ? 'Looking...' : 'Refresh'));
    const hint = (steps) => {
      if (!steps[0].done) return h('button', { class: 'btn small primary', onclick: () => ruleDialog() }, 'Add rule');
      if (!steps[1].done) return startButton(true);
      return null;
    };
    if (!devs.length) {
      const steps = setupSteps(null);
      const looking = ui.loadingDevices || !ui.android || !ui.ios;
      return h('section', { class: 'card setup' }, head,
        h('p', { class: 'small muted' }, looking ? 'Looking for emulators and simulators...' : 'No emulator or booted simulator found. Start one, then press Refresh.'),
        stepList(steps), h('div', { class: 'actions start' }, hint(steps)));
    }
    return h('section', { class: 'card setup' }, head, outputBox(), devs.map((dev) => {
      const steps = setupSteps(dev);
      const ready = steps[2].done && steps[3].done;
      const anything = dev.caInstalled.length || dev.redirect.length;
      const blocked = !enabledRules().length || (dev.platform === 'android' && !dev.raw.rootable);
      return h('div', { class: 'device' },
        h('div', { class: 'device-head' },
          h('div', null, h('div', { class: 'title' }, dev.name), h('div', { class: 'small muted' }, dev.platform === 'ios' ? `iOS Simulator · ${dev.sub}` : dev.sub)),
          h('div', { class: 'actions' },
            hint(steps),
            h('button', { class: `btn small${ready || hint(steps) ? '' : ' primary'}`, disabled: blocked, title: blocked && dev.platform === 'android' && !dev.raw.rootable ? 'This emulator image does not allow root. Use a Google APIs image.' : null, onclick: (e) => runSetup(e.target, dev, false) }, ready ? 'Set up again' : 'Set up this device'),
            h('button', { class: 'btn small', disabled: !anything, onclick: (e) => runSetup(e.target, dev, true) }, 'Undo'))),
        stepList(steps),
        dev.platform === 'ios' && anything ? h('p', { class: 'small muted' }, 'Undo removes this Mac\'s redirect and resets the simulator keychain, which also removes other certificates you added to it.') : null);
    }));
  }

  // ---------------------------------------------------------------- redirect drift
  async function updateMacRedirect(btn) {
    await act(btn, async () => {
      const want = wantEntries('127.0.0.1');
      const out = await api('POST', want.length ? '/api/hosts/apply' : '/api/hosts/remove');
      setState(out.state);
      render();
      toast(want.length ? 'Redirect updated' : 'Redirect removed');
    });
  }

  async function updateAndroidRedirect(btn, serial) {
    await act(btn, async () => {
      const want = wantEntries(androidIp());
      ui.output = await api('POST', want.length ? '/api/android/apply-hosts' : '/api/android/remove-hosts', { serial });
      toast(want.length ? 'Redirect updated' : 'Redirect removed');
      await loadDevices();
    });
  }

  // Shown when the rules that are on and an active redirect no longer agree.
  function driftBanners() {
    const out = [];
    const diff = (have, want) => {
      const w = new Set(want.map((e) => e.host));
      const hv = new Set(have.map((e) => e.host));
      const add = [...w].filter((x) => !hv.has(x));
      const drop = [...hv].filter((x) => !w.has(x));
      return [add.length ? `Missing: ${add.join(', ')}.` : '', drop.length ? `No longer needed: ${drop.join(', ')}.` : ''].filter(Boolean).join(' ') || 'The addresses differ.';
    };
    const mac = wantEntries('127.0.0.1');
    if (S.hosts.entries.length && !sameEntries(S.hosts.entries, mac))
      out.push(h('div', { class: 'notice warn' }, h('strong', null, 'This computer\'s redirect does not match your rules.'), h('div', { class: 'small' }, diff(S.hosts.entries, mac)),
        h('div', { class: 'actions' }, h('button', { class: 'btn small', onclick: (e) => updateMacRedirect(e.target) }, mac.length ? 'Update redirect' : 'Remove redirect'))));
    for (const d of (ui.android && ui.android.devices) || []) {
      const want = wantEntries(androidIp());
      if (!d.hostsEntries || !d.hostsEntries.length || sameEntries(d.hostsEntries, want)) continue;
      out.push(h('div', { class: 'notice warn' }, h('strong', null, `The redirect on ${d.model ? d.model.replace(/_/g, ' ') : d.serial} does not match your rules.`), h('div', { class: 'small' }, diff(d.hostsEntries, want)),
        h('div', { class: 'actions' }, h('button', { class: 'btn small', onclick: (e) => updateAndroidRedirect(e.target, d.serial) }, want.length ? 'Update redirect' : 'Remove redirect'))));
    }
    return out;
  }

  // ---------------------------------------------------------------- rules
  function hostsWarning() {
    if (!S.hosts.entries.length || !sameEntries(S.hosts.entries, wantEntries('127.0.0.1'))) return null;
    if (S.proxy.running) return null; // the checklist already shows it as applied
    return h(
      'div',
      { class: 'notice warn' },
      h('strong', null, 'This computer redirects ' + S.hosts.entries.map((e) => e.host).join(', ') + ' to the proxy.'),
      h('div', { class: 'small' }, 'The proxy is stopped, so these names will not reach the real server from this computer until you remove the redirect.'),
      h('div', { class: 'actions' }, h('button', { class: 'btn small', onclick: (e) => act(e.target, async () => { const r = await api('POST', '/api/hosts/remove'); setState(r.state); render(); toast('Redirect removed'); }) }, 'Remove redirect'))
    );
  }

  function testBox(rule) {
    const t = ui.tests[rule.id];
    if (!t) return null;
    if (t.pending) return h('div', { class: 'test' }, 'Testing...');
    if (t.error) return h('div', { class: 'test' }, h('span', { class: 'verdict status-bad' }, t.error));
    const p = t.preflight;
    const a = t.actual;
    const hd = (r, k) => (r && r.headers && r.headers[k]) || 'not set';
    return h(
      'div',
      { class: 'test' },
      h('div', { class: `verdict ${t.corsOk ? 'status-ok' : 'status-bad'}` }, t.corsOk ? 'CORS headers are being added.' : 'CORS headers were not added. See details.'),
      h(
        'table',
        null,
        h('tr', null, h('td', { class: 'muted' }, 'Preflight (OPTIONS)'), h('td', null, p.error ? p.error : `${p.status}, allow-origin: ${hd(p, 'access-control-allow-origin')}`)),
        h('tr', null, h('td', { class: 'muted' }, `Real request (GET ${t.path || '/'})`), h('td', null, a.error ? a.error : `${a.status}, allow-origin: ${hd(a, 'access-control-allow-origin')}`)),
        h('tr', null, h('td', { class: 'muted' }, 'Certificate'), h('td', null, a.trusted === true ? 'Trusted by the CORS Bridge CA.' : a.trusted === false ? `Not trusted by this computer (${a.trustError}). Install the CA on the device, or pick a certificate your device already trusts.` : 'Plain http, no certificate.')),
        a.status === 401 || a.status === 403 || a.status === 404 ? h('tr', null, h('td', { class: 'muted' }, 'Tip'), h('td', null, `The server answered ${a.status} for ${t.path || '/'}. That is normal for some APIs. Set a Test path in the rule (for example /health) to check an address that answers without signing in.`)) : null,
        a.status >= 500 ? h('tr', null, h('td', { class: 'muted' }, 'Server said'), h('td', { class: 'mono' }, a.body)) : null
      )
    );
  }

  function groupSwitches() {
    const list = rules();
    const groups = groupsOf(list);
    if (!groups.length) return null;
    return h('div', { class: 'groups', role: 'group', 'aria-label': 'Rule groups' },
      h('span', { class: 'small muted' }, 'Groups'),
      groups.map((g) => {
        const members = list.filter((r) => r.group === g);
        const on = members.every((r) => r.enabled);
        const some = !on && members.some((r) => r.enabled);
        return h('button', { class: `chip chip-btn${on ? ' ok' : some ? ' warn' : ''}`, 'aria-pressed': String(on), title: on ? `Turn off every rule in ${g}` : `Turn on every rule in ${g} (rules for the same addresses in other groups are paused)`, onclick: (e) => act(e.target, async () => {
          const out = await api('POST', '/api/groups', { group: g, enabled: !on });
          setState(out.state);
          render();
          toast(out.warning ? `Switched, but the proxy could not restart: ${out.warning}` : on ? `${g} is off` : `${g} is on${out.paused.length ? `, paused ${out.paused.length} other rule${out.paused.length === 1 ? '' : 's'}` : ''}`, out.warning ? 'bad' : '');
        }) }, h('span', { class: 'dot' }), g, h('span', { class: 'muted' }, ` ${members.filter((r) => r.enabled).length}/${members.length}`));
      }));
  }

  function rulesPanel() {
    const list = rules();
    const head = h(
      'div',
      { class: 'panel-head' },
      h('div', null, h('h2', null, 'Rules'), h('p', { class: 'muted' }, 'A rule takes the requests your app sends to an API address and forwards them to the real server with CORS headers added.')),
      h('div', { class: 'actions' },
        h('button', { class: 'btn', onclick: importRulesDialog }, 'Import'),
        list.length ? h('a', { class: 'btn', href: '/api/export', download: '' }, 'Export') : null,
        h('button', { class: 'btn primary', onclick: () => ruleDialog() }, 'Add rule'))
    );
    if (!list.length) {
      return h(
        'div',
        null,
        setupSection(),
        head,
        driftBanners(),
        hostsWarning(),
        h(
          'div',
          { class: 'card empty' },
          h('h3', null, 'No rules yet'),
          h('p', { class: 'muted' }, 'Paste the address your app calls, for example https://api.company.com. Connect to your VPN first so the real server can be found. If a teammate shared a rules file, use Import.'),
          h('button', { class: 'btn primary', onclick: () => ruleDialog() }, 'Add your first rule')
        )
      );
    }
    return h(
      'div',
      null,
      setupSection(),
      head,
      driftBanners(),
      hostsWarning(),
      groupSwitches(),
      h(
        'div',
        { class: 'card' },
        list.map((r) => {
          const cert = r.certId ? S.certs.find((c) => c.id === r.certId) : null;
          return h(
            'div',
            null,
            h(
              'div',
              { class: 'row rule-row' },
              h('div', null, h('div', { class: 'title mono' }, ruleUrl(r), r.group ? h('span', { class: 'chip span group-chip' }, r.group) : null), h('div', { class: 'small muted' }, r.scheme === 'https' ? `Certificate: ${cert ? cert.name : 'automatic, issued by CORS Bridge'}` : 'Plain http'), r.note ? h('div', { class: 'small muted' }, r.note) : null),
              h('div', null, h('div', { class: 'small muted' }, 'Forwards to'), h('div', { class: 'mono small' }, `${r.upstreamScheme}://${r.upstreamHost}:${r.upstreamPort}`), r.enabled ? null : h('span', { class: 'chip' }, 'Paused')),
              h(
                'div',
                { class: 'actions' },
                h('button', { class: 'btn small', onclick: (e) => act(e.target, async () => { ui.tests[r.id] = { pending: true }; render(); try { ui.tests[r.id] = await api('POST', `/api/rules/${r.id}/test`); } catch (err) { ui.tests[r.id] = { error: err.message }; } render(); }) }, 'Test'),
                h('button', { class: 'btn small', onclick: () => ruleDialog(r) }, 'Edit'),
                h('button', { class: 'btn small', onclick: (e) => act(e.target, async () => { const out = await api('POST', '/api/rules', { id: r.id, hostInput: r.host, enabled: !r.enabled }); setState(out.state); render(); }) }, r.enabled ? 'Pause' : 'Resume'),
                h('button', { class: 'btn small danger', onclick: () => deleteLater(`rule:${r.id}`, `the rule for ${r.host}`, () => api('DELETE', `/api/rules/${r.id}`)) }, 'Delete')
              )
            ),
            testBox(r)
          );
        })
      ),
      S.proxy.running ? null : h('p', { class: 'muted small', style: 'margin-top:12px' }, 'Press Start proxy (top right) to apply your rules. Changes to rules apply immediately while it is running.')
    );
  }

  const SETTING_NAMES = { androidHostIp: 'Address the Android emulator uses', autoStartProxy: 'Start the proxy when CORS Bridge opens', cleanupHostsOnExit: 'Remove the hosts redirect when CORS Bridge quits' };

  const onOff = (v) => (v === true ? 'on' : v === false ? 'off' : v);

  function importPreview(out) {
    const rows = out.plan.map((p) => h('tr', { class: p.action === 'skip' ? 'skip' : p.warnings.length ? 'risky' : '' },
      h('td', null, { add: 'Add', update: 'Replace', skip: 'Skip' }[p.action]),
      h('td', { class: 'mono' }, p.address || p.host, p.group ? h('span', { class: 'chip span group-chip' }, p.group) : null),
      h('td', { class: 'mono' }, p.upstream || '?'),
      h('td', null, p.warnings.length ? h('ul', { class: 'warn-list' }, p.warnings.map((w) => h('li', null, w))) : h('span', { class: 'muted' }, 'Nothing unusual'))));
    return h('div', null,
      h('table', { class: 'preview' }, h('thead', null, h('tr', null, ['', 'Address your app calls', 'Forwards to', 'Check'].map((t) => h('th', null, t)))), h('tbody', null, rows)),
      out.settings.length ? h('div', { class: 'small', style: 'margin-top:10px' }, h('strong', null, 'Settings that change: '), out.settings.map((x) => `${SETTING_NAMES[x.name] || x.name}: ${onOff(x.from)} → ${onOff(x.to)}`).join('; ')) : null,
      h('p', { class: 'small muted', style: 'margin-top:10px' }, 'Imported rules arrive paused. Check where each one forwards to, then turn them on with Resume or the group switch. Only import files from people you trust: a rule can send an address to any server.'));
  }

  function importRulesDialog() {
    let data = null;
    let fileName = '';
    const summary = h('div', { class: 'small muted' }, 'Choose or drop a .json file exported from CORS Bridge.');
    const preview = h('div', { class: 'import-preview' });
    const mode = { merge: null, replace: null };
    const submit = h('button', { type: 'submit', class: 'btn primary', disabled: true }, 'Import');
    const currentMode = () => (mode.replace.checked ? 'replace' : 'merge');
    // Asks the server what the import would do, without saving anything.
    const showPlan = async () => {
      if (!data) return;
      submit.disabled = true;
      preview.replaceChildren(h('p', { class: 'small muted' }, 'Checking the file...'));
      try {
        const out = await api('POST', '/api/import', { data, mode: currentMode(), dryRun: true });
        const ok = out.plan.filter((p) => p.action !== 'skip').length;
        summary.className = 'small';
        summary.replaceChildren(h('strong', null, fileName), `: ${ok} rule${ok === 1 ? '' : 's'} to import`, data.exportedAt ? `, exported ${fmtDate(data.exportedAt)}` : '', '.');
        preview.replaceChildren(importPreview(out));
        submit.disabled = !ok;
      } catch (e) {
        preview.replaceChildren(h('p', { class: 'small status-bad' }, e.message));
      }
    };
    const readFile = (file) => {
      if (!file) return;
      const rd = new FileReader();
      rd.onload = () => {
        try {
          const d = JSON.parse(String(rd.result));
          if (d.app !== 'cors-bridge' || !Array.isArray(d.rules)) throw new Error('x');
          data = d;
          fileName = file.name;
          showPlan();
        } catch {
          data = null;
          submit.disabled = true;
          preview.replaceChildren();
          summary.className = 'small status-bad';
          summary.textContent = `${file.name} is not a CORS Bridge rules file.`;
        }
      };
      rd.readAsText(file);
    };
    const input = h('input', { type: 'file', accept: '.json,application/json', class: 'sr', onchange: (e) => readFile(e.target.files[0]) });
    const form = h('form', { method: 'dialog', class: 'wide' },
      h('div', { class: 'dlg-body' },
        h('h2', null, 'Import rules'),
        h('p', { class: 'muted' }, 'Load rules and settings a teammate exported. Certificates are not part of the file, so each person keeps their own CA.'),
        dropZone(input, 'Drop the rules file here, or', 'choose a file', (files) => readFile(files[0])),
        summary,
        h('fieldset', { class: 'field plain' }, h('legend', null, 'What to do with your current rules'),
          h('label', { class: 'check' }, (mode.merge = h('input', { type: 'radio', name: 'mode', value: 'merge', checked: true, onchange: showPlan })), h('span', null, 'Keep them and add or update from the file', h('div', { class: 'small muted' }, 'A rule with the same address, port and group is replaced.'))),
          h('label', { class: 'check' }, (mode.replace = h('input', { type: 'radio', name: 'mode', value: 'replace', onchange: showPlan })), h('span', null, 'Replace them with the file'))),
        preview),
      h('div', { class: 'dlg-foot' }, h('button', { type: 'button', class: 'btn', onclick: closeDialog }, 'Cancel'), submit));
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      if (!data) return;
      await act(submit, async () => {
        const out = await api('POST', '/api/import', { data, mode: currentMode() });
        setState(out.state);
        closeDialog();
        render();
        const parts = [out.added ? `added ${out.added}` : '', out.updated ? `replaced ${out.updated}` : ''].filter(Boolean).join(', ');
        toast(`Imported: ${parts || 'nothing changed'}. The rules are paused until you turn them on.`);
        for (const w of out.warnings) toast(w, 'bad');
        if (out.warning) toast(`The proxy could not restart: ${out.warning}`, 'bad');
        loadDevices();
      });
    });
    openDialog(form);
  }

  // A drop target with a file picker inside. onFiles gets a FileList-like array.
  function dropZone(input, text, linkText, onFiles) {
    const zone = h('label', { class: 'drop' }, input, h('span', null, `${text} `, h('span', { class: 'link' }, linkText), '.'));
    const stop = (e) => { e.preventDefault(); e.stopPropagation(); };
    zone.addEventListener('dragenter', (e) => { stop(e); zone.classList.add('over'); });
    zone.addEventListener('dragover', (e) => { stop(e); zone.classList.add('over'); });
    zone.addEventListener('dragleave', (e) => { stop(e); if (!zone.contains(e.relatedTarget)) zone.classList.remove('over'); });
    zone.addEventListener('drop', (e) => { stop(e); zone.classList.remove('over'); if (e.dataTransfer.files.length) onFiles([...e.dataTransfer.files]); });
    return zone;
  }

  function openDialog(content) {
    const dlg = document.getElementById('dlg');
    dlg.replaceChildren(content);
    if (!dlg.open) dlg.showModal();
    // A modal dialog sits above the page, so messages must live inside it to be readable.
    dlg.append(toastBox);
    return dlg;
  }
  const closeDialog = () => {
    document.getElementById('dlg').close();
    document.body.append(toastBox);
  };
  document.getElementById('dlg').addEventListener('close', () => document.body.append(toastBox)); // also for Esc

  function ruleDialog(rule) {
    const editing = !!rule;
    const r = rule || { scheme: 'https', listenPort: '', upstreamHost: '', upstreamScheme: 'https', upstreamPort: '', verifyUpstream: true, stripOrigin: false, certId: null, enabled: true, note: '', group: '', testPath: '/', cors: { origin: 'app', customOrigin: '', credentials: true, handlePreflight: true, overrideUpstream: true, exposeHeaders: 'auto' } };
    const c = r.cors;
    const f = {};
    const leafs = allCerts().filter((x) => x.kind === 'leaf' && x.hasKey);
    const groups = groupsOf(rules());
    const resolveBtn = h('button', { type: 'button', class: 'btn', onclick: () => act(resolveBtn, async () => { const host = f.address.value.replace(/^[a-z]+:\/\//i, '').split(/[/:]/)[0]; const out = await api('GET', `/api/resolve?host=${encodeURIComponent(host)}`); f.upstreamHost.value = out.ip; toast(`Found ${out.ip}`); }) }, 'Find it');
    const form = h(
      'form',
      { method: 'dialog' },
      h(
        'div',
        { class: 'dlg-body' },
        h('h2', null, editing ? `Edit rule for ${r.host}` : 'Add rule'),
        h('label', { class: 'field' }, h('span', null, 'API address your app calls'), (f.address = h('input', { type: 'text', required: true, placeholder: 'https://api.company.com', value: editing ? ruleUrl(r) : '', autocomplete: 'off' })), h('small', null, 'A full address, or just the host name. A port is optional.')),
        h('label', { class: 'field' }, h('span', null, 'Real server IP address'), h('div', { class: 'inline' }, (f.upstreamHost = h('input', { type: 'text', placeholder: 'Leave empty to find it automatically', value: r.upstreamHost || '', autocomplete: 'off' })), resolveBtn), h('small', null, 'Found while your VPN is connected and kept fixed, so the redirect can never loop back to itself. Click Find it again if the server moves.')),
        h('div', { class: 'grid2' },
          h('label', { class: 'field' }, h('span', null, 'Group'), (f.group = h('input', { type: 'text', list: 'cb-groups', maxlength: 40, placeholder: 'Optional, for example dev or uat', value: r.group || '', autocomplete: 'off' })), h('datalist', { id: 'cb-groups' }, groups.map((g) => h('option', { value: g }))), h('small', null, 'Turn a whole group on or off at once. Groups can hold rules for the same address.')),
          h('label', { class: 'field' }, h('span', null, 'Test path'), (f.testPath = h('input', { type: 'text', placeholder: '/', value: r.testPath && r.testPath !== '/' ? r.testPath : '', autocomplete: 'off' })), h('small', null, 'What Test calls, for example /health. Pick one that answers without signing in.'))),
        h('details', { open: false }, h('summary', null, 'Ports, certificate and CORS options'),
          h('div', { class: 'grid2' },
            h('label', { class: 'field' }, h('span', null, 'Listen port'), (f.listenPort = h('input', { type: 'number', min: 1, max: 65535, placeholder: 'Same as the address', value: editing ? r.listenPort : '' }))),
            h('label', { class: 'field' }, h('span', null, 'Real server port'), (f.upstreamPort = h('input', { type: 'number', min: 1, max: 65535, placeholder: 'Same as listen port', value: editing ? r.upstreamPort : '' })))
          ),
          h('div', { class: 'grid2' },
            h('label', { class: 'field' }, h('span', null, 'Real server uses'), (f.upstreamScheme = h('select', { value: r.upstreamScheme }, h('option', { value: 'https' }, 'https'), h('option', { value: 'http' }, 'http')))),
            h('label', { class: 'field' }, h('span', null, 'Certificate shown to the app'), (f.certId = h('select', { value: r.certId || '' }, h('option', { value: '' }, 'Automatic (issued by CORS Bridge)'), leafs.map((x) => h('option', { value: x.id }, `${x.name} (${x.origin})`)))))
          ),
          h('label', { class: 'check' }, (f.verifyUpstream = h('input', { type: 'checkbox', checked: r.verifyUpstream })), h('span', null, 'Verify the real server certificate', h('div', { class: 'small muted' }, 'Untick only if the real server uses an internal CA this computer does not trust.'))),
          h('label', { class: 'check' }, (f.stripOrigin = h('input', { type: 'checkbox', checked: r.stripOrigin })), h('span', null, 'Hide the Origin header from the real server', h('div', { class: 'small muted' }, 'Helps when the server rejects requests from unknown origins.'))),
          h('div', { class: 'grid2' },
            h('label', { class: 'field' }, h('span', null, 'Who may read the answers'), (f.origin = h('select', { value: c.origin },
              h('option', { value: 'app' }, 'Your app (localhost, capacitor://, ionic://)'),
              h('option', { value: 'custom' }, 'Only the origins listed'),
              h('option', { value: 'reflect' }, 'Any website, with cookies (less safe)'),
              h('option', { value: '*' }, 'Any website (*), no cookies')))),
            h('label', { class: 'field' }, h('span', null, 'Also allow these origins'), (f.customOrigin = h('input', { type: 'text', placeholder: 'http://192.168.1.20:8100', value: c.customOrigin || '', autocomplete: 'off' })), h('small', null, 'Separate several with commas.'))
          ),
          (f.originHint = h('p', { class: 'small muted' })),
          h('label', { class: 'check' }, (f.credentials = h('input', { type: 'checkbox', checked: c.credentials })), h('span', null, 'Allow cookies and authorization headers (credentials)', (f.credHint = h('div', { class: 'small muted' })))),
          h('label', { class: 'check' }, (f.handlePreflight = h('input', { type: 'checkbox', checked: c.handlePreflight })), h('span', null, 'Answer preflight (OPTIONS) requests directly', h('div', { class: 'small muted' }, 'Turn off only if the real server must see them.'))),
          h('label', { class: 'check' }, (f.overrideUpstream = h('input', { type: 'checkbox', checked: c.overrideUpstream })), h('span', null, 'Replace CORS headers the real server sends')),
          h('label', { class: 'field' }, h('span', null, 'Note'), (f.note = h('input', { type: 'text', maxlength: 200, value: r.note || '', placeholder: 'Optional' })))
        )
      ),
      h('div', { class: 'dlg-foot' }, h('button', { type: 'button', class: 'btn', onclick: closeDialog }, 'Cancel'), h('button', { type: 'submit', class: 'btn primary' }, editing ? 'Save rule' : 'Add rule'))
    );
    // Only the choices that mean something for the selected origin stay editable.
    let credWanted = c.credentials;
    const syncOrigin = () => {
      const o = f.origin.value;
      f.customOrigin.disabled = o === 'reflect' || o === '*';
      f.customOrigin.required = o === 'custom';
      f.originHint.className = o === 'reflect' ? 'small status-bad' : 'small muted';
      f.originHint.textContent = {
        app: 'Covers Ionic, Capacitor and Cordova apps and dev servers on this computer. Other websites get no CORS headers.',
        custom: 'Only these exact origins get CORS headers.',
        reflect: 'Any website open in a browser that uses this redirect could read this API with your cookies. Use only for a short test.',
        '*': 'Any website can read answers, but cookies and authorization headers are not allowed.',
      }[o];
      if (o === '*') {
        f.credentials.checked = false;
        f.credentials.disabled = true;
        f.credHint.textContent = 'Browsers do not allow credentials with Any origin (*).';
      } else {
        if (f.credentials.disabled) f.credentials.checked = credWanted;
        f.credentials.disabled = false;
        f.credHint.textContent = '';
      }
    };
    f.credentials.addEventListener('change', () => { credWanted = f.credentials.checked; });
    f.origin.addEventListener('change', syncOrigin);
    syncOrigin();
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const btn = form.querySelector('button[type=submit]');
      await act(btn, async () => {
        const body = {
          id: rule && rule.id,
          hostInput: f.address.value,
          upstreamHost: f.upstreamHost.value.trim(),
          listenPort: f.listenPort.value,
          upstreamPort: f.upstreamPort.value,
          upstreamScheme: f.upstreamScheme.value,
          certId: f.certId.value || null,
          verifyUpstream: f.verifyUpstream.checked,
          stripOrigin: f.stripOrigin.checked,
          note: f.note.value,
          group: f.group.value,
          testPath: f.testPath.value,
          cors: { origin: f.origin.value, customOrigin: f.customOrigin.value, credentials: f.credentials.checked, handlePreflight: f.handlePreflight.checked, overrideUpstream: f.overrideUpstream.checked },
        };
        const out = await api('POST', '/api/rules', body);
        setState(out.state);
        closeDialog();
        render();
        toast(out.warning ? `Saved, but the proxy could not restart: ${out.warning}` : editing ? 'Rule saved' : `Rule added. Real server found at ${out.rule.upstreamHost}`, out.warning ? 'bad' : '');
      });
    });
    openDialog(form);
    f.address.focus();
  }

  // ---------------------------------------------------------------- certificates
  const dl = (id, fmt, label) => h('a', { class: 'btn small', href: `/api/certs/${id}/download?format=${fmt}`, download: '' }, label);

  function certName(c) {
    return h('div', null, h('div', { class: 'title' }, c.name, ' ', c.isActive ? h('span', { class: 'chip span' }, 'Signing CA') : null, ' ', c.origin === 'imported' ? h('span', { class: 'chip' }, 'Imported') : null), h('div', { class: 'small muted' }, c.subject));
  }
  const expiry = (c) => h('span', { class: `chip ${c.status === 'valid' ? 'ok' : c.status === 'expiring' ? 'warn' : 'bad'}` }, c.status === 'expired' ? `Expired ${fmtDate(c.notAfter)}` : `Valid until ${fmtDate(c.notAfter)}`);

  function certsPanel() {
    const cas = allCerts().filter((c) => c.kind === 'ca');
    const leafs = allCerts().filter((c) => c.kind === 'leaf');
    const issueInput = h('input', { type: 'text', placeholder: 'api.company.com, other.company.com', autocomplete: 'off' });
    return h(
      'div',
      null,
      h('div', { class: 'panel-head' }, h('div', null, h('h2', null, 'Certificates'), h('p', { class: 'muted' }, 'Your app needs to trust the certificate the proxy shows. Install a CA on the simulator once (Devices tab) and every certificate it signs is trusted.')),
        h('div', { class: 'actions' }, h('button', { class: 'btn', onclick: importDialog }, 'Import certificate'), h('button', { class: 'btn primary', onclick: (e) => act(e.target, async () => { const out = await api('POST', '/api/certs/generate-ca', {}); setState(out.state); render(); toast('Created a new CA'); }) }, 'Create CA'))),
      h('section', { class: 'section' },
        h('h3', { style: 'margin-bottom:8px' }, 'Certificate authorities'),
        cas.length
          ? h('div', { class: 'card' }, cas.map((c) => h('div', { class: 'row cert-row' },
              certName(c),
              h('div', null, expiry(c), h('div', { class: 'small muted', style: 'margin-top:4px' }, c.canSign ? 'Can sign server certificates' : 'Install on devices only (no private key)')),
              h('div', { class: 'actions' }, dl(c.id, 'pem', '.pem'), dl(c.id, 'cer', '.cer'), dl(c.id, 'android', 'Android'),
                c.canSign && !c.isActive ? h('button', { class: 'btn small', onclick: (e) => act(e.target, async () => { setState(await api('POST', `/api/certs/${c.id}/activate`)); render(); }) }, 'Use for signing') : null,
                h('button', { class: 'btn small danger', onclick: () => delCert(c) }, 'Delete')))))
          : h('div', { class: 'card empty' }, h('p', { class: 'muted' }, 'No CA yet. One is created automatically when you start the proxy with an https rule. You can also create one now, or import your company CA.'))
      ),
      h('section', { class: 'section' },
        h('h3', { style: 'margin-bottom:8px' }, 'Server certificates'),
        leafs.length
          ? h('div', { class: 'card' }, leafs.map((c) => h('div', { class: 'row cert-row' },
              certName(c),
              h('div', null, expiry(c), h('div', { class: 'small muted mono', style: 'margin-top:4px' }, c.names.join(', '))),
              h('div', { class: 'actions' }, h('button', { class: 'btn small danger', onclick: () => delCert(c) }, 'Delete')))))
          : h('div', { class: 'card empty' }, h('p', { class: 'muted' }, 'None yet. They are issued automatically for each https rule, or you can import one from your company.')),
        h('div', { class: 'card', style: 'margin-top:12px;padding:14px 16px' },
          h('label', { class: 'field', style: 'margin:0' }, h('span', null, 'Issue a certificate now'), h('div', { class: 'inline' }, issueInput, h('button', { class: 'btn', onclick: (e) => act(e.target, async () => { const out = await api('POST', '/api/certs/issue', { hosts: issueInput.value }); setState(out.state); render(); toast('Certificate issued'); }) }, 'Issue')), h('small', null, 'Host names separated by commas. Signed by the CA marked Signing CA.')))
      )
    );
  }

  function delCert(c) {
    const used = rules().filter((r) => r.certId === c.id).length;
    deleteLater(`cert:${c.id}`, `"${c.name}"${c.hasKey ? ' and its private key' : ''}${used ? ` (${used} rule${used === 1 ? '' : 's'} will use an automatic certificate)` : ''}`, () => api('DELETE', `/api/certs/${c.id}`));
  }

  const PEM_CERT = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g;
  const PEM_KEY = /-----BEGIN ((?:RSA |EC |ENCRYPTED )?PRIVATE KEY)-----[\s\S]+?-----END \1-----/;

  function importDialog() {
    const f = {};
    const files = h('div', { class: 'small muted' });
    // Puts certificates and a private key from any text into the right fields. Returns what it found.
    const place = (text, name) => {
      const certsFound = String(text).match(PEM_CERT) || [];
      const key = PEM_KEY.exec(text);
      if (certsFound.length) f.cert.value = certsFound.join('\n') + '\n';
      if (key) f.key.value = key[0] + '\n';
      if (/ENCRYPTED PRIVATE KEY|Proc-Type: 4,ENCRYPTED/.test(text)) f.pass.focus();
      const what = [certsFound.length ? `${certsFound.length} certificate${certsFound.length === 1 ? '' : 's'}` : '', key ? 'a private key' : ''].filter(Boolean).join(' and ');
      if (name) files.append(h('div', null, what ? `${name}: ${what}` : `${name}: nothing usable`));
      return { certs: certsFound.length, key: !!key };
    };
    const readFiles = (list) => {
      files.replaceChildren();
      for (const file of list) {
        const rd = new FileReader();
        rd.onload = () => {
          const text = String(rd.result);
          const got = place(text, file.name);
          if (!got.certs && !got.key) {
            if (/\.(pfx|p12)$/i.test(file.name)) toast('Password-protected .pfx/.p12 files must be converted first: openssl pkcs12 -in file.pfx -nodes -out all.pem', 'bad');
            else toast(`${file.name} is not in PEM text format. Export it as "Base-64 encoded X.509" or convert it with OpenSSL.`, 'bad');
          }
        };
        rd.readAsText(file);
      }
    };
    const picker = h('input', { type: 'file', multiple: true, accept: '.pem,.crt,.cer,.key,.txt', class: 'sr', onchange: (e) => readFiles([...e.target.files]) });
    // Pasting a combined PEM into the certificate box moves the key to its own box.
    const splitPasted = () => {
      const text = f.cert.value;
      if (!PEM_KEY.test(text)) return;
      place(text);
      toast('Moved the private key to its own field');
    };
    const form = h('form', { method: 'dialog' },
      h('div', { class: 'dlg-body' },
        h('h2', null, 'Import certificate'),
        h('p', { class: 'muted' }, 'Import your company CA to install it on a device, or a server certificate together with its private key to serve it from the proxy. Everything stays on this computer.'),
        dropZone(picker, 'Drop .pem, .crt, .cer or .key files here (one combined file is fine), or', 'choose files', readFiles),
        files,
        h('label', { class: 'field' }, h('span', null, 'Name'), (f.name = h('input', { type: 'text', placeholder: 'Optional' }))),
        h('label', { class: 'field' }, h('span', null, 'Certificate (PEM)'), (f.cert = h('textarea', { placeholder: '-----BEGIN CERTIFICATE-----', required: true, oninput: splitPasted }))),
        h('label', { class: 'field' }, h('span', null, 'Private key (PEM), if you have it'), (f.key = h('textarea', { placeholder: '-----BEGIN PRIVATE KEY-----' })), h('small', null, 'Needed for server certificates and for a CA that should sign new certificates.')),
        h('label', { class: 'field' }, h('span', null, 'Key passphrase'), (f.pass = h('input', { type: 'password', autocomplete: 'off', placeholder: 'Only if the key is encrypted' })))
      ),
      h('div', { class: 'dlg-foot' }, h('button', { type: 'button', class: 'btn', onclick: closeDialog }, 'Cancel'), h('button', { type: 'submit', class: 'btn primary' }, 'Import')));
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      await act(form.querySelector('button[type=submit]'), async () => {
        const out = await api('POST', '/api/certs/import', { name: f.name.value, certPem: f.cert.value, keyPem: f.key.value, passphrase: f.pass.value });
        setState(out.state);
        closeDialog();
        render();
        toast(`Imported ${out.imported.length} certificate${out.imported.length === 1 ? '' : 's'}`);
      });
    });
    openDialog(form);
  }

  // ---------------------------------------------------------------- devices
  let devicesLoading = null;
  function loadDevices() {
    if (devicesLoading) return devicesLoading;
    ui.loadingDevices = true;
    render();
    devicesLoading = (async () => {
      const [a, i] = await Promise.allSettled([api('GET', '/api/android/devices'), api('GET', '/api/ios/devices')]);
      if (!ui.offline) {
        ui.android = a.status === 'fulfilled' ? a.value : { available: false, devices: [], error: a.reason.message };
        ui.ios = i.status === 'fulfilled' ? i.value : { supported: false, devices: [], reason: i.reason.message };
      }
      ui.loadingDevices = false;
      devicesLoading = null;
      render();
    })();
    return devicesLoading;
  }

  function outputBox() {
    if (!ui.output) return null;
    const o = ui.output;
    const text = (o.steps || []).map((s) => `${s.ok ? '✓' : '✗'} ${s.label}${s.output ? `\n    ${s.output.split('\n').join('\n    ')}` : ''}`).join('\n');
    const working = !o.error && !o.note && !o.ok;
    return h('div', { class: `notice ${o.error ? 'bad' : 'ok'} output` },
      h('div', { class: 'output-head' }, h('strong', null, o.error ? o.error : o.note || (working ? 'Working...' : 'Done.')), working ? null : h('button', { class: 'btn small', onclick: () => { ui.output = null; render(); } }, 'Close')),
      text && !working ? h('details', { open: !!o.error }, h('summary', { class: 'small' }, o.error ? 'Details' : 'Show details'), h('pre', { class: 'out' }, text)) : null);
  }

  function devicesPanel() {
    const cas = allCerts().filter((c) => c.kind === 'ca');
    if (!ui.caChoice || !cas.some((c) => c.id === ui.caChoice)) ui.caChoice = (cas.find((c) => c.isActive) || cas[0] || {}).id || null;
    const caSelect = h('select', { value: ui.caChoice || '', onchange: (e) => { ui.caChoice = e.target.value; render(); } }, cas.map((c) => h('option', { value: c.id }, c.name)));
    const noCa = !cas.length;
    const runDevice = (btn, path, body, okMsg) => act(btn, async () => {
      ui.output = { steps: [{ label: 'Working...', ok: true }] };
      render();
      const r = await api('POST', path, body);
      ui.output = r;
      toast(okMsg);
      await loadDevices();
    });
    const done = (text) => h('span', { class: 'chip ok' }, '✓ ', text);
    const anyOn = enabledRules().length > 0;
    const androidActions = (d) => {
      if (d.state !== 'device') return [];
      const caOn = (d.caInstalled || []).includes(ui.caChoice);
      const want = wantEntries(androidIp());
      const have = d.hostsEntries || [];
      const current = have.length && sameEntries(have, want);
      return [
        caOn ? done('CA installed') : h('button', { class: 'btn small', disabled: noCa, onclick: (e) => runDevice(e.target, '/api/android/install-ca', { serial: d.serial, caId: ui.caChoice }, 'CA installed') }, 'Install CA'),
        caOn ? h('button', { class: 'btn small', onclick: (e) => runDevice(e.target, '/api/android/remove-ca', { serial: d.serial }, 'CA removed') }, 'Remove CA') : null,
        current ? done('Redirect applied') : h('button', { class: 'btn small', disabled: !anyOn, onclick: (e) => runDevice(e.target, '/api/android/apply-hosts', { serial: d.serial }, have.length ? 'Redirect updated' : 'Redirect applied') }, have.length ? 'Update redirect' : 'Apply redirect'),
        have.length ? h('button', { class: 'btn small', onclick: (e) => runDevice(e.target, '/api/android/remove-hosts', { serial: d.serial }, 'Redirect removed') }, 'Remove redirect') : null,
      ];
    };
    const iosActions = (d) => {
      const caOn = (d.caInstalled || []).includes(ui.caChoice);
      return [
        caOn ? done('CA installed') : null,
        h('button', { class: 'btn small', disabled: noCa, title: caOn ? 'Installed earlier by CORS Bridge. Install again if the simulator was erased.' : null, onclick: (e) => runDevice(e.target, '/api/ios/install-ca', { udid: d.udid, caId: ui.caChoice }, 'CA installed') }, caOn ? 'Install again' : 'Install CA'),
      ];
    };
    const macWant = wantEntries('127.0.0.1');
    const macCurrent = S.hosts.entries.length && sameEntries(S.hosts.entries, macWant);
    const a = ui.android;
    const ios = ui.ios;
    return h('div', null,
      h('div', { class: 'panel-head' }, h('div', null, h('h2', null, 'Devices'), h('p', { class: 'muted' }, 'Two steps per device: install the CA so the device trusts the proxy, then point your API host names at this computer.')), h('button', { class: 'btn', onclick: loadDevices }, ui.loadingDevices ? 'Looking...' : 'Refresh')),
      outputBox(),
      driftBanners(),
      h('div', { class: 'card', style: 'padding:14px 16px;margin-bottom:24px' }, h('label', { class: 'field', style: 'margin:0' }, h('span', null, 'CA to install on devices'), caSelect, noCa ? h('small', null, 'There is no CA yet. Create or import one on the Certificates tab.') : null)),
      h('section', { class: 'section' },
        h('h3', { style: 'margin-bottom:8px' }, 'Android emulator'),
        !a ? h('div', { class: 'card empty muted' }, 'Looking for emulators...')
          : !a.available ? h('div', { class: 'card empty' }, h('p', null, 'adb was not found.'), h('p', { class: 'muted' }, 'Install Android Studio or the platform-tools, or set the ANDROID_HOME environment variable, then press Refresh.'))
          : !a.devices.length ? h('div', { class: 'card empty' }, h('p', null, 'No emulator is running.'), h('p', { class: 'muted' }, 'Start an emulator from Android Studio, then press Refresh. Use an image labelled "Google APIs" (not "Google Play"), because only those allow root.'))
          : h('div', { class: 'card' }, a.devices.map((d) => h('div', { class: 'row dev-row' },
              h('div', null, h('div', { class: 'title' }, d.serial, d.model ? ` (${d.model})` : ''), h('div', { class: 'small muted' }, d.state !== 'device' ? `State: ${d.state}` : `Android ${d.release || '?'}`, d.state === 'device' ? (d.rootable ? ' · root available' : ' · root not available on this image') : '')),
              h('div', { class: 'actions' }, androidActions(d)))))
      ),
      h('section', { class: 'section' },
        h('h3', { style: 'margin-bottom:8px' }, 'iOS Simulator'),
        !ios ? h('div', { class: 'card empty muted' }, 'Looking for simulators...')
          : !ios.supported ? h('div', { class: 'card empty muted' }, ios.reason)
          : !ios.available ? h('div', { class: 'card empty' }, h('p', null, ios.reason), h('p', { class: 'muted' }, 'Run xcode-select --install in a terminal, then press Refresh.'))
          : !ios.devices.length ? h('div', { class: 'card empty' }, h('p', null, 'No simulator is booted.'), h('p', { class: 'muted' }, 'Start one from Xcode or Simulator, then press Refresh.'))
          : h('div', { class: 'card' }, ios.devices.map((d) => h('div', { class: 'row dev-row' },
              h('div', null, h('div', { class: 'title' }, d.name), h('div', { class: 'small muted' }, d.runtime)),
              h('div', { class: 'actions' }, iosActions(d))))),
        h('p', { class: 'muted small', style: 'margin-top:8px' }, 'The iOS Simulator uses this Mac\'s hosts file, so it needs the redirect below.')
      ),
      h('section', { class: 'section' },
        h('h3', { style: 'margin-bottom:8px' }, 'This computer\'s hosts file'),
        h('div', { class: 'card', style: 'padding:14px 16px' },
          h('p', { class: 'small' }, 'Only the iOS Simulator needs this. It adds one marked block to ', h('code', null, S.hosts.path), ' that points your rule host names at 127.0.0.1. Your VPN, DNS servers and routes are not touched.'),
          S.hosts.entries.length ? h('pre', { class: 'out' }, S.hosts.entries.map((e) => `${e.ip}  ${e.host}`).join('\n')) : h('p', { class: 'muted small' }, 'No redirect is active.'),
          h('div', { class: 'actions', style: 'justify-content:flex-start' },
            macCurrent ? done('Redirect applied') : h('button', { class: 'btn', disabled: !anyOn, onclick: (e) => act(e.target, async () => { const out = await api('POST', '/api/hosts/apply'); setState(out.state); render(); toast(out.result.elevated ? 'Redirect applied (with administrator permission)' : 'Redirect applied'); }) }, S.hosts.entries.length ? 'Update redirect' : 'Apply redirect'),
            h('button', { class: 'btn', disabled: !S.hosts.entries.length, onclick: (e) => act(e.target, async () => { const out = await api('POST', '/api/hosts/remove'); setState(out.state); render(); toast('Redirect removed'); }) }, 'Remove redirect')),
          h('p', { class: 'muted small', style: 'margin-top:10px' }, S.hosts.writable ? '' : 'Changing this file needs administrator permission. You will be asked for it.'))));
  }

  // ---------------------------------------------------------------- log
  async function loadLogs() {
    try {
      ui.logs = (await api('GET', '/api/logs')).logs.slice().reverse();
    } catch {
      /* ignore */
    }
    render();
  }

  const statusClass = (l) => (l.status >= 500 ? 'status-bad' : l.status >= 400 ? 'status-warn' : l.preflight ? 'status-pre' : 'status-ok');

  function headerTable(title, headers, empty, mark) {
    const list = Object.entries(headers || {});
    return h('div', { class: 'hdrs' }, h('h4', null, title),
      list.length
        ? h('dl', null, list.map(([k, v]) => [h('dt', { class: mark && mark(k) ? 'mark' : null }, k), h('dd', { class: mark && mark(k) ? 'mark' : null }, v)]))
        : h('p', { class: 'small muted' }, empty));
  }

  function logDetail(l) {
    const added = l.corsAdded || {};
    const replaced = Object.keys(l.resHeaders || {}).filter((k) => k.startsWith('access-control-'));
    return h('tr', { class: 'log-detail' }, h('td', { colspan: 6 },
      h('div', { class: 'small', style: 'margin-bottom:8px' }, h('span', { class: 'mono' }, `${l.method} ${l.path}`), l.origin ? ` from origin ${l.origin}` : ' (no Origin header)', l.note ? ` · ${l.note}` : ''),
      h('div', { class: 'hdr-grid' },
        headerTable('Request headers', l.reqHeaders, 'Not recorded.'),
        headerTable(l.preflight ? 'Real server' : 'Response headers from the real server', l.resHeaders, l.preflight ? 'Not asked. CORS Bridge answered the preflight itself.' : l.status === 502 ? 'No answer. The real server could not be reached.' : 'Not recorded.', (k) => k.startsWith('access-control-')),
        headerTable('CORS headers added by CORS Bridge', l.corsAdded, l.resHeaders && !l.corsAdded ? 'None. The server sent its own CORS headers and the rule keeps them.' : 'None.')),
      replaced.length && Object.keys(added).length ? h('p', { class: 'small muted', style: 'margin:8px 0 0' }, `Replaced the server's own ${replaced.join(', ')}.`) : null));
  }

  function logRows() {
    const q = ui.logFilter.toLowerCase();
    const out = [];
    for (const l of ui.logs.filter((x) => !q || `${x.host} ${x.path} ${x.method} ${x.status}`.toLowerCase().includes(q)).slice(0, 300)) {
      const open = ui.logOpen.has(l.id);
      const toggle = () => {
        if (open) ui.logOpen.delete(l.id);
        else ui.logOpen.add(l.id);
        redrawLog();
        const row = document.querySelector(`tr[data-id="${l.id}"]`);
        if (row) row.focus();
      };
      out.push(h('tr', { class: `log-row${l.status >= 500 ? ' row-bad' : l.status >= 400 ? ' row-warn' : ''}${open ? ' open' : ''}`, 'data-id': l.id, tabindex: 0, 'aria-expanded': String(open), onclick: toggle, onkeydown: (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); } } },
        h('td', { class: 'mono' }, h('span', { class: 'caret', 'aria-hidden': 'true' }, open ? '▾' : '▸'), ' ', new Date(l.ts).toLocaleTimeString()),
        h('td', null, l.preflight ? 'OPTIONS (preflight)' : l.method),
        h('td', { class: 'mono' }, `${l.host}${l.path}`),
        h('td', { class: statusClass(l) }, l.status || '...'),
        h('td', { class: 'muted' }, `${l.ms} ms`),
        h('td', { class: 'muted' }, l.note || l.origin)));
      if (open) out.push(logDetail(l));
    }
    return out;
  }

  function redrawLog() {
    const tb = document.getElementById('logbody');
    if (tb) tb.replaceChildren(...logRows());
    else render();
  }

  function setLogPaused(paused) {
    ui.logPaused = paused;
    if (!paused && ui.logQueue.length) {
      ui.logs.unshift(...ui.logQueue);
      ui.logQueue = [];
      if (ui.logs.length > 500) ui.logs.length = 500;
    }
    render();
  }

  function logPanel() {
    const counts = ui.logs.reduce((n, l) => ({ c4: n.c4 + (l.status >= 400 && l.status < 500), c5: n.c5 + (l.status >= 500) }), { c4: 0, c5: 0 });
    return h('div', null,
      h('div', { class: 'panel-head' }, h('div', null, h('h2', null, 'Live log'), h('p', { class: 'muted' }, 'Requests passing through the proxy. Click a row to see its headers. If nothing appears when you use the app, the redirect or certificate is not set up on that device yet.')),
        h('div', { class: 'actions' },
          h('input', { type: 'text', placeholder: 'Filter', 'aria-label': 'Filter the log', value: ui.logFilter, style: 'width:160px', oninput: (e) => { ui.logFilter = e.target.value; redrawLog(); } }),
          h('button', { id: 'logpause', class: `btn${ui.logPaused ? ' primary' : ''}`, 'aria-pressed': String(ui.logPaused), onclick: () => setLogPaused(!ui.logPaused) }, ui.logPaused ? `Resume${ui.logQueue.length ? ` (${ui.logQueue.length} new)` : ''}` : 'Pause'),
          h('button', { class: 'btn', onclick: () => act(null, async () => { await api('DELETE', '/api/logs'); ui.logs = []; ui.logQueue = []; ui.logOpen.clear(); render(); }) }, 'Clear'))),
      ui.logPaused ? h('div', { class: 'notice' }, h('strong', null, 'Paused. '), h('span', { class: 'small' }, 'New requests are kept and shown when you resume.')) : null,
      counts.c4 || counts.c5 ? h('p', { class: 'small muted' }, [counts.c5 ? h('span', { class: 'status-bad' }, `${counts.c5} server error${counts.c5 === 1 ? '' : 's'} (5xx)`) : null, counts.c4 && counts.c5 ? ' · ' : null, counts.c4 ? h('span', { class: 'status-warn' }, `${counts.c4} client error${counts.c4 === 1 ? '' : 's'} (4xx)`) : null]) : null,
      h('div', { class: 'card logwrap' }, ui.logs.length ? h('table', { class: 'log' }, h('thead', null, h('tr', null, ['Time', 'Method', 'Address', 'Status', 'Time taken', 'Note'].map((t) => h('th', null, t)))), h('tbody', { id: 'logbody' }, logRows())) : h('div', { class: 'empty muted' }, 'No requests yet.')));
  }

  let rulesRedraw = null;
  function startEvents() {
    const es = new EventSource('/api/events');
    es.onopen = () => {
      if (ui.offline) setOffline(null);
    };
    es.onerror = () => {
      // The browser retries by itself; find out whether the server is gone or the session ended.
      fetch('/api/state', { cache: 'no-store' }).then(
        (r) => {
          if (r.status === 401) {
            es.close();
            setOffline('expired');
          }
        },
        () => setOffline('down')
      );
    };
    es.onmessage = (m) => {
      let entry;
      try {
        entry = JSON.parse(m.data);
      } catch {
        return;
      }
      if (ui.logPaused) {
        ui.logQueue.unshift(entry);
        if (ui.logQueue.length > 500) ui.logQueue.length = 500;
        if (tab === 'log') {
          const b = document.getElementById('logpause');
          if (b) b.textContent = `Resume (${ui.logQueue.length} new)`;
        }
        return;
      }
      ui.logs.unshift(entry);
      if (ui.logs.length > 500) ui.logs.length = 500;
      if (tab === 'log') redrawLog();
      else if (tab === 'rules' && !rulesRedraw) rulesRedraw = setTimeout(() => { rulesRedraw = null; if (tab === 'rules' && !document.getElementById('dlg').open) render(); }, 1000);
    };
  }

  // ---------------------------------------------------------------- settings & help
  function settingsPanel() {
    const s = S.settings;
    const save = (patch) => act(null, async () => { setState(await api('POST', '/api/settings', patch)); render(); toast('Saved'); });
    const ip = h('input', { type: 'text', value: s.androidHostIp });
    const lanIps = h('input', { type: 'text', value: (s.lanClients || []).join(', '), placeholder: '192.168.1.20', autocomplete: 'off' });
    return h('div', null,
      h('div', { class: 'panel-head' }, h('div', null, h('h2', null, 'Settings'))),
      h('div', { class: 'card', style: 'padding:16px' },
        h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: s.autoStartProxy, onchange: (e) => save({ autoStartProxy: e.target.checked }) }), h('span', null, 'Start the proxy when CORS Bridge opens')),
        h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: s.cleanupHostsOnExit, onchange: (e) => save({ cleanupHostsOnExit: e.target.checked }) }), h('span', null, 'Remove this computer\'s hosts redirect when CORS Bridge quits', h('div', { class: 'small muted' }, 'You may be asked for an administrator password again.'))),
        h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: s.allowLan, onchange: (e) => { if (e.target.checked) { e.target.checked = false; lanIps.focus(); toast('Enter the device IP address, then press Allow.'); } else save({ allowLan: false }); } }), h('span', null, 'Let other devices on my network use the proxy', h('div', { class: 'small muted' }, 'Only needed for a real phone. Only the addresses below get in, and it turns off when CORS Bridge restarts. Those devices reach your real server through your VPN.'))),
        h('label', { class: 'field', style: 'margin-left:24px' }, h('span', null, 'IP addresses of those devices'), h('div', { class: 'inline' }, lanIps, h('button', { class: 'btn', onclick: () => save({ lanClients: lanIps.value, allowLan: true }) }, s.allowLan ? 'Save' : 'Allow')), h('small', null, 'Find it in the phone\'s Wi-Fi settings, for example 192.168.1.20. Separate several with commas.')),
        h('label', { class: 'field' }, h('span', null, 'Address the Android emulator uses to reach this computer'), h('div', { class: 'inline' }, ip, h('button', { class: 'btn', onclick: () => save({ androidHostIp: ip.value }) }, 'Save')), h('small', null, '10.0.2.2 for the standard emulator.'))),
      h('p', { class: 'muted small', style: 'margin-top:14px' }, 'Your data (rules, certificates and private keys) is stored in ', h('code', null, S.platform.dataDir), '.'));
  }

  function helpPanel() {
    return h('div', null,
      h('div', { class: 'panel-head' }, h('h2', null, 'How to use this')),
      h('ol', { class: 'steps' },
        h('li', null, h('strong', null, 'Connect to your VPN, then add a rule. '), 'Use the address your app calls. CORS Bridge finds the real server and remembers its IP.'),
        h('li', null, h('strong', null, 'Start the proxy. '), 'It listens on this computer only, on the port in the rule (443 for https).'),
        h('li', null, h('strong', null, 'Set up the device. '), 'Rules tab, Set up this device. It installs the CA so the device trusts the proxy, and points the host names at this computer. Android changes only the emulator. iOS needs the Mac\'s hosts file. Undo reverses both.'),
        h('li', null, h('strong', null, 'Keep the redirect up to date. '), 'When you change rules, press Update redirect in the banner that appears. Groups (dev, uat) switch several rules at once.'),
        h('li', null, h('strong', null, 'Restart the app and use it. '), 'Requests appear in the Live log. Use Test on a rule to check the CORS headers.')),
      h('h3', { style: 'margin:22px 0 6px' }, 'If something does not work'),
      h('ul', { class: 'steps' },
        h('li', null, 'Still a certificate error in the app: the app may pin its server certificate. Pinning cannot be bypassed without changing the app.'),
        h('li', null, 'Nothing in the Live log: the redirect is not applied on that device, or the app was not restarted afterwards.'),
        h('li', null, '"origin not allowed" in the Live log: the page calling the API is not your app (for example a dev server on your LAN IP). Add its origin in the rule, under Ports, certificate and CORS options.'),
        h('li', null, '"Port 443 is already in use": stop the other program, or use another port in the rule (the app must then call that port).'),
        h('li', null, 'Android install fails with "root": create the emulator with a Google APIs image, not Google Play.'),
        h('li', null, 'After a cold boot of the emulator the CA and redirect are gone. Apply them again.')));
  }

  // ---------------------------------------------------------------- start
  window.addEventListener('hashchange', () => {
    const id = location.hash.slice(1);
    if (id && id !== tab) go(id);
  });
  refresh()
    .then(() => {
      if (tab === 'devices' || tab === 'rules') loadDevices();
      loadLogs();
      startEvents();
    })
    .catch((e) => {
      if (!ui.offline) document.getElementById('app').replaceChildren(h('div', { class: 'shell' }, h('div', { class: 'notice bad' }, e.message)));
    });
  // A file dropped outside a drop area must not replace the dashboard.
  for (const ev of ['dragover', 'drop']) window.addEventListener(ev, (e) => e.preventDefault());
})();
