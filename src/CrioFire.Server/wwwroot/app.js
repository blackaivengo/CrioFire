'use strict';

// CrioFire Server console. Plain JavaScript, no build step. Everything shown from the server is
// put on the page as text (never as HTML), because computer names and paths come from PCs.
(() => {
  const app = document.getElementById('app');
  const state = {
    me: null,
    server: '',
    view: 'overview',
    devices: [],
    policies: [],
    selected: new Set(),
    editing: null,   // the policy open in the editor
    filter: { text: '', status: 'all', policy: 'all' },
    refreshTimer: 0,
  };

  // ---------- small helpers ----------

  function h(tag, props, ...children) {
    const el = document.createElement(tag);
    for (const [key, value] of Object.entries(props || {})) {
      if (value === undefined || value === null || value === false) continue;
      if (key === 'class') el.className = value;
      else if (key === 'text') el.textContent = value;
      else if (key.startsWith('on')) el.addEventListener(key.slice(2), value);
      else if (key === 'value') el.value = value;
      else if (key === 'style') el.style.cssText = value;   // the CSP forbids style attributes, not CSSOM
      else if (key === 'checked') el.checked = true;
      else el.setAttribute(key, value === true ? '' : value);
    }
    for (const child of children.flat(Infinity)) {
      if (child === null || child === undefined || child === false) continue;
      el.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return el;
  }

  /** replaceChildren that, like h(), flattens arrays and skips null and false. */
  function fill(el, ...children) {
    el.replaceChildren(...children.flat(Infinity).filter((c) => c !== null && c !== undefined && c !== false));
    return el;
  }

  async function api(method, path, body) {
    const headers = { 'X-CrioFire': '1' };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    const res = await fetch('/api/admin' + path, {
      method,
      headers,
      credentials: 'same-origin',
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (res.status === 401 && path !== '/signin') {
      state.me = null;
      renderSignIn();
      throw new Error('Please sign in again.');
    }
    if (res.status === 204) return null;
    const data = await res.json().catch(() => null);
    if (!res.ok) throw new Error((data && data.error) || `The server answered ${res.status}.`);
    return data;
  }

  function toast(text, bad) {
    const t = h('div', { class: 'toast' + (bad ? ' bad' : ''), text });
    document.getElementById('toasts').append(t);
    setTimeout(() => t.remove(), bad ? 7000 : 4000);
  }

  async function attempt(work, success) {
    try {
      const result = await work();
      if (success) toast(typeof success === 'function' ? success(result) : success);
      return result;
    } catch (e) {
      toast(e.message, true);
      return undefined;
    }
  }

  function modal(build, center = true) {
    const veil = h('div', { class: 'veil' + (center ? ' center' : '') });
    const close = () => { veil.remove(); document.removeEventListener('keydown', onKey); };
    const onKey = (e) => { if (e.key === 'Escape') close(); };
    veil.addEventListener('mousedown', (e) => { if (e.target === veil) close(); });
    document.addEventListener('keydown', onKey);
    veil.append(build(close));
    document.body.append(veil);
    const first = veil.querySelector('input, select, button.primary');
    if (first) first.focus();
    return close;
  }

  function confirmDialog(title, text, okText, danger) {
    return new Promise((resolve) => {
      modal((close) => {
        const done = (answer) => { close(); resolve(answer); };
        return h('div', { class: 'dialog', role: 'dialog', 'aria-label': title },
          h('h2', { text: title }),
          h('p', { class: 'hint', style: 'margin-top:8px', text }),
          h('div', { class: 'buttons' },
            h('button', { class: 'ghost', text: 'Cancel', onclick: () => done(false) }),
            h('button', { class: danger ? 'danger' : 'primary', text: okText, onclick: () => done(true) })));
      });
    });
  }

  const fmt = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });
  const when = (iso) => (iso ? fmt.format(new Date(iso)) : 'never');
  function ago(iso) {
    if (!iso) return 'never';
    const s = (Date.now() - new Date(iso).getTime()) / 1000;
    if (s < 90) return 'just now';
    if (s < 5400) return `${Math.round(s / 60)} min ago`;
    if (s < 172800) return `${Math.round(s / 3600)} h ago`;
    return `${Math.round(s / 86400)} days ago`;
  }

  const statusText = { ok: 'OK', attention: 'Needs attention', offline: 'Offline', new: 'Not checked in' };
  const modeText = { learning: 'Learning', ask: 'Ask', allowlist: 'Allow-list' };
  const statusChip = (s) => h('span', { class: 'chip ' + s, text: statusText[s] || s });

  function download(name, text) {
    const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
    const a = h('a', { href: url, download: name });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  // ---------- sign-in ----------

  async function start() {
    try {
      const s = await api('GET', '/state');
      state.server = s.server;
      if (!s.adminsExist) return renderNoAdmins(s);
      const me = await fetch('/api/admin/me', { credentials: 'same-origin' });
      if (me.ok) {
        state.me = (await me.json()).name;
        go(location.hash.slice(1) || 'overview');
      } else {
        renderSignIn();
      }
    } catch (e) {
      app.replaceChildren(h('div', { class: 'signin' }, h('div', { class: 'dialog' }, h('h2', { text: 'CrioFire Server' }), h('p', { class: 'error', text: e.message }))));
    }
  }

  /** A new server: the first administrator is created here when the browser runs on the server itself. */
  function renderNoAdmins(s) {
    const brand = h('div', { class: 'brand', style: 'padding:0' }, h('img', { src: 'favicon.svg', alt: '' }),
      h('div', {}, h('b', { text: 'CrioFire Server' }), h('span', { text: state.server })));
    if (!s.canSetUpHere) {
      app.replaceChildren(h('div', { class: 'signin' }, h('div', { class: 'dialog' }, brand,
        h('h2', { text: 'Set up the first administrator' }),
        h('p', { class: 'hint', style: 'margin-top:10px', text: `For safety, the first administrator is created on the server itself: open https://localhost:${s.port}/ there, or run this from an administrator prompt on the server:` }),
        h('div', { class: 'copy' }, h('code', { text: 'criofire-server admin add <your name>' })),
        h('p', { class: 'hint', style: 'margin-top:10px', text: 'Then reload this page and sign in.' }))));
      return;
    }
    const error = h('p', { class: 'error', hidden: true });
    const name = h('input', { autocomplete: 'username', required: true, maxlength: 40 });
    const password = h('input', { type: 'password', autocomplete: 'new-password', required: true, minlength: 10 });
    const again = h('input', { type: 'password', autocomplete: 'new-password', required: true });
    const submit = h('button', { class: 'primary', type: 'submit', text: 'Create and sign in' });
    const form = h('form', {
      onsubmit: async (e) => {
        e.preventDefault();
        error.hidden = true;
        if (password.value !== again.value) {
          error.textContent = 'The two passwords are not the same.';
          error.hidden = false;
          return;
        }
        submit.disabled = true;
        try {
          const me = await api('POST', '/setup', { name: name.value, password: password.value });
          state.me = me.name;
          go('overview');
          toast('Welcome. Next: create a policy, then add computers.');
        } catch (err) {
          error.textContent = err.message;
          error.hidden = false;
          submit.disabled = false;
        }
      },
    },
    h('label', { class: 'field' }, h('span', { text: 'Your name (letters, digits, . - _ @)' }), name),
    h('label', { class: 'field' }, h('span', { text: 'Password (at least 10 characters)' }), password),
    h('label', { class: 'field' }, h('span', { text: 'The same password again' }), again),
    error, submit);
    app.replaceChildren(h('div', { class: 'signin' }, h('div', { class: 'dialog' }, brand,
      h('h2', { text: 'Welcome to CrioFire Server' }),
      h('p', { class: 'hint', style: 'margin-top:6px', text: 'Create the first administrator. You can add more later, under Administrators.' }),
      form)));
    name.focus();
  }

  function renderSignIn() {
    clearInterval(state.refreshTimer);
    const error = h('p', { class: 'error', hidden: true });
    const name = h('input', { autocomplete: 'username', required: true });
    const password = h('input', { type: 'password', autocomplete: 'current-password', required: true });
    const submit = h('button', { class: 'primary', type: 'submit', text: 'Sign in' });
    const form = h('form', {
      onsubmit: async (e) => {
        e.preventDefault();
        submit.disabled = true;
        error.hidden = true;
        try {
          const me = await api('POST', '/signin', { name: name.value, password: password.value });
          state.me = me.name;
          go(location.hash.slice(1) || 'overview');
        } catch (err) {
          error.textContent = err.message;
          error.hidden = false;
          submit.disabled = false;
          password.select();
        }
      },
    },
    h('label', { class: 'field' }, h('span', { text: 'Name' }), name),
    h('label', { class: 'field' }, h('span', { text: 'Password' }), password),
    error, submit);
    app.replaceChildren(h('div', { class: 'signin' }, h('div', { class: 'dialog' },
      h('div', { class: 'brand', style: 'padding:0' }, h('img', { src: 'favicon.svg', alt: '' }),
        h('div', {}, h('b', { text: 'CrioFire Server' }), h('span', { text: state.server }))),
      form)));
    name.focus();
  }

  // ---------- shell and navigation ----------

  const views = [
    ['overview', 'Overview'],
    ['computers', 'Computers'],
    ['policies', 'Policies'],
    ['enroll', 'Add computers'],
    ['license', 'License'],
    ['admins', 'Administrators'],
  ];

  function go(view) {
    state.editing = null;
    state.view = views.some(([v]) => v === view) ? view : 'overview';
    if (location.hash.slice(1) !== state.view) history.replaceState(null, '', '#' + state.view);
    renderShell();
  }

  window.addEventListener('hashchange', () => { if (state.me) go(location.hash.slice(1)); });

  function renderShell() {
    clearInterval(state.refreshTimer);
    const attention = state.devices.filter((d) => d.status === 'attention' || d.status === 'offline').length;
    const main = h('main', { class: 'main' });
    app.replaceChildren(h('div', { class: 'shell' },
      h('nav', { class: 'side', 'aria-label': 'Sections' },
        h('div', { class: 'brand' }, h('img', { src: 'favicon.svg', alt: '' }),
          h('div', {}, h('b', { text: 'CrioFire Server' }), h('span', { text: state.server }))),
        views.map(([v, label]) => h('button', {
          class: 'nav',
          'data-view': v,
          'aria-current': state.view === v ? 'page' : null,
          onclick: () => go(v),
        }, label, v === 'computers' && attention > 0 ? h('span', { class: 'count', text: attention }) : null)),
        h('div', { class: 'grow' }),
        h('div', { class: 'who', text: `Signed in as ${state.me}` }),
        h('button', { class: 'nav', text: 'Sign out', onclick: signOut })),
      main));
    if (state.editing) return renderEditor(main, state.editing);
    const render = { overview: viewOverview, computers: viewComputers, policies: viewPolicies, enroll: viewEnroll, license: viewLicense, admins: viewAdmins }[state.view];
    render(main);
  }

  async function signOut() {
    await attempt(() => api('POST', '/signout'));
    state.me = null;
    renderSignIn();
  }

  function head(title, sub, ...actions) {
    return h('div', { class: 'head' },
      h('div', {}, h('h1', { text: title }), sub ? h('p', { class: 'sub', text: sub }) : null),
      actions.length ? h('div', { class: 'actions' }, actions) : null);
  }

  /** Refreshes the open view every 30 seconds while nothing else is open. */
  function autoRefresh(main, render) {
    clearInterval(state.refreshTimer);
    state.refreshTimer = setInterval(() => {
      if (!document.querySelector('.veil') && document.visibilityState === 'visible' && main.isConnected) render(main, true);
    }, 30000);
  }

  async function loadDevices() {
    state.devices = await api('GET', '/devices');
    const ids = new Set(state.devices.map((d) => d.id));
    for (const id of [...state.selected]) if (!ids.has(id)) state.selected.delete(id);
    updateCount();
  }

  /** The number of computers needing attention, next to "Computers" in the side bar. */
  function updateCount() {
    const nav = document.querySelector('.nav[data-view=computers]');
    if (!nav) return;
    const n = state.devices.filter((d) => d.status === 'attention' || d.status === 'offline').length;
    nav.querySelector('.count')?.remove();
    if (n > 0) nav.append(h('span', { class: 'count', text: n, title: `${n} need attention` }));
  }

  async function loadPolicies() {
    state.policies = await api('GET', '/policies');
  }

  // ---------- overview ----------

  async function viewOverview(main, quiet) {
    if (!quiet) fill(main, head('Overview', 'Loading...'));
    const o = await attempt(() => api('GET', '/overview'));
    if (!o) return;
    attempt(loadDevices);   // for the count in the side bar
    const tile = (n, label, cls, onclick) => h('button', { class: 'tile ' + (cls || ''), onclick },
      h('div', { class: 'l', text: label }), h('div', { class: 'n', text: n }));
    const filterTo = (status) => () => { state.filter.status = status; go('computers'); };
    fill(main,
      licenseNote(o.license),
      head('Overview', `Every computer that reports to ${o.server}.`,
        h('button', { class: 'primary', text: 'New policy', onclick: () => editPolicy(null) }),
        h('button', { text: 'Add computers', onclick: () => go('enroll') })),
      h('div', { class: 'tiles' },
        tile(o.computers, 'Computers', '', filterTo('all')),
        tile(o.online, 'Online', 'ok', filterTo('online')),
        tile(o.attention, 'Need attention', o.attention ? 'fire' : '', filterTo('attention')),
        tile(o.offline, 'Offline or not checked in', '', filterTo('offline')),
        tile(o.policies, 'Policies', '', () => go('policies')),
        tile(o.unmanaged, 'Without a policy', o.unmanaged ? 'fire' : '', filterTo('nopolicy'))),
      h('div', { class: 'card' },
        h('h2', { text: 'Needs your attention' }),
        o.needAttention.length === 0
          ? h('p', { class: 'empty', text: o.computers === 0 ? 'No computers yet. Add some under "Add computers".' : 'All computers are fine.' })
          : h('div', { class: 'table-wrap' }, h('table', {},
            h('thead', {}, h('tr', {}, h('th', { text: 'Computer' }), h('th', { text: 'Status' }), h('th', { text: 'Why' }), h('th', { text: 'Last check-in' }))),
            h('tbody', {}, o.needAttention.map((d) => h('tr', { class: 'click', onclick: () => openComputer(d.id) },
              h('td', {}, h('b', { text: d.computer })),
              h('td', {}, statusChip(d.status)),
              h('td', { text: d.problems.join(' ') }),
              h('td', { text: ago(d.lastSeenUtc) }))))))));
    autoRefresh(main, viewOverview);
  }

  /** A warning above the overview when the license needs attention; nothing otherwise. */
  function licenseNote(l) {
    if (!l) return null;
    let text = null;
    if (l.over) text = `${l.computers} computers report to this server, but the license covers ${l.seats}. Add seats to stay covered.`;
    else if (l.state === 'expired') text = 'The organization\'s license has expired. Computers keep working; renew to stay covered.';
    else if (l.state === 'expiring') text = l.message;
    else if (l.state === 'none' && l.computers > 3) text = `${l.computers} computers and no license. Free use covers businesses with up to 3 computers.`;
    if (!text) return null;
    return h('div', { class: 'bulk warn' }, h('span', { text }), h('span', { class: 'spacer' }),
      h('button', { class: 'small', text: 'License', onclick: () => go('license') }));
  }

  // ---------- computers ----------

  function matches(d) {
    const f = state.filter;
    const text = f.text.trim().toLowerCase();
    if (text && !(`${d.computer} ${d.address || ''} ${d.policyName || ''}`.toLowerCase().includes(text))) return false;
    if (f.status === 'online' && !(d.status === 'ok' || d.status === 'attention')) return false;
    if (f.status === 'attention' && d.status !== 'attention') return false;
    if (f.status === 'offline' && !(d.status === 'offline' || d.status === 'new')) return false;
    if (f.status === 'nopolicy' && d.policyId) return false;
    if (f.policy !== 'all' && (d.policyId || 'none') !== f.policy) return false;
    return true;
  }

  async function viewComputers(main, quiet) {
    if (!quiet) fill(main, head('Computers', 'Loading...'));
    const ok = await attempt(async () => { await Promise.all([loadDevices(), loadPolicies()]); return true; });
    if (!ok) return;
    const shown = state.devices.filter(matches);
    const rerender = () => viewComputers(main, true);

    const search = h('input', { type: 'search', placeholder: 'Search computers', value: state.filter.text, 'aria-label': 'Search computers' });
    search.addEventListener('input', () => { state.filter.text = search.value; rerender().then(() => { const s = main.querySelector('input[type=search]'); s.focus(); s.setSelectionRange(s.value.length, s.value.length); }); });
    const status = h('select', { 'aria-label': 'Status', onchange: (e) => { state.filter.status = e.target.value; rerender(); } },
      [['all', 'All statuses'], ['online', 'Online'], ['attention', 'Needs attention'], ['offline', 'Offline or new'], ['nopolicy', 'Without a policy']]
        .map(([v, t]) => h('option', { value: v, text: t, selected: state.filter.status === v ? 'selected' : null })));
    const policy = h('select', { 'aria-label': 'Policy', onchange: (e) => { state.filter.policy = e.target.value; rerender(); } },
      h('option', { value: 'all', text: 'All policies' }),
      h('option', { value: 'none', text: 'No policy', selected: state.filter.policy === 'none' ? 'selected' : null }),
      state.policies.map((p) => h('option', { value: p.policy.id, text: p.policy.name, selected: state.filter.policy === p.policy.id ? 'selected' : null })));

    const allShownSelected = shown.length > 0 && shown.every((d) => state.selected.has(d.id));
    const selectAll = h('input', { type: 'checkbox', 'aria-label': 'Select all shown', checked: allShownSelected,
      onchange: (e) => { for (const d of shown) e.target.checked ? state.selected.add(d.id) : state.selected.delete(d.id); rerender(); } });

    const selected = state.devices.filter((d) => state.selected.has(d.id));
    const bulk = selected.length === 0 ? null : h('div', { class: 'bulk' },
      h('b', { text: `${selected.length} selected` }),
      h('button', { class: 'small primary', text: 'Apply a policy...', onclick: () => assignDialog(selected.map((d) => d.id)) }),
      h('button', { class: 'small', text: 'Remove their policy', onclick: () => assign(selected.map((d) => d.id), null) }),
      h('button', { class: 'small danger', text: 'Remove from server', onclick: () => removeComputers(selected) }),
      h('span', { class: 'spacer' }),
      h('button', { class: 'small ghost', text: 'Clear selection', onclick: () => { state.selected.clear(); rerender(); } }));

    fill(main,
      head('Computers', `${state.devices.length} computer(s) report to this server. Select some to apply a policy to them, or click one for details.`,
        h('button', { text: 'Add computers', onclick: () => go('enroll') })),
      bulk,
      h('div', { class: 'card' },
        h('div', { class: 'row', style: 'margin-bottom:12px' }, search, status, policy,
          h('span', { class: 'spacer' }),
          shown.length > 0 ? h('button', { class: 'small', text: `Apply a policy to all ${shown.length} shown...`, onclick: () => assignDialog(shown.map((d) => d.id)) }) : null),
        h('div', { class: 'table-wrap' }, h('table', {},
          h('thead', {}, h('tr', {}, h('th', { class: 'check' }, selectAll), h('th', { text: 'Computer' }), h('th', { text: 'Status' }),
            h('th', { text: 'Policy' }), h('th', { text: 'Mode' }), h('th', { text: 'Rules' }), h('th', { text: 'Last check-in' }), h('th', { text: 'Address' }))),
          h('tbody', {}, shown.length === 0
            ? h('tr', {}, h('td', { colspan: 8, class: 'empty', text: state.devices.length ? 'No computer matches the filters.' : 'No computers yet. Add some under "Add computers".' }))
            : shown.map((d) => {
              const r = d.report;
              const box = h('input', { type: 'checkbox', 'aria-label': `Select ${d.computer}`, checked: state.selected.has(d.id),
                onclick: (e) => e.stopPropagation(),
                onchange: (e) => { e.target.checked ? state.selected.add(d.id) : state.selected.delete(d.id); rerender(); } });
              return h('tr', { class: 'click' + (state.selected.has(d.id) ? ' selected' : ''), onclick: () => openComputer(d.id) },
                h('td', { class: 'check' }, box),
                h('td', {}, h('b', { text: d.computer })),
                h('td', { title: d.problems.join(' ') }, statusChip(d.status)),
                h('td', {}, d.policyName ? [d.policyName, d.policyApplied ? null : h('span', { class: 'muted', text: ' (pending)' })] : h('span', { class: 'muted', text: 'none' })),
                h('td', { text: r ? (modeText[r.mode] || r.mode) + (r.panic !== 'off' ? ', PANIC' : '') : '' }),
                h('td', { text: r ? r.programRules + r.networkRules + r.serviceRules : '' }),
                h('td', { text: ago(d.lastSeenUtc) }),
                h('td', { class: 'mono', text: d.address || '' }));
            }))))));
    autoRefresh(main, viewComputers);
  }

  async function assign(ids, policyId) {
    const name = policyId ? (state.policies.find((p) => p.policy.id === policyId)?.policy.name || policyId) : null;
    if (!policyId && !(await confirmDialog('Remove the policy?', `${ids.length} computer(s) will remove the organization's rules at their next check-in. Their users' own rules stay.`, 'Remove policy', true))) return;
    const done = await attempt(() => api('POST', '/devices/assign', { deviceIds: ids, policyId }),
      policyId ? `${ids.length} computer(s) get "${name}" at their next check-in.` : `${ids.length} computer(s) have no policy now.`);
    if (done !== undefined) { state.selected.clear(); renderShell(); }
  }

  async function removeComputers(devices) {
    if (!(await confirmDialog(`Remove ${devices.length} computer(s)?`, 'They stop reporting to this server (they need a new enrollment code to come back). Their firewall keeps working with the rules they have.', 'Remove', true))) return;
    const r = await attempt(() => api('POST', '/devices/remove', { deviceIds: devices.map((d) => d.id) }), (x) => `Removed ${x.count} computer(s).`);
    if (r) { state.selected.clear(); renderShell(); }
  }

  /** Choose a policy for the given computers. */
  async function assignDialog(ids) {
    if (state.policies.length === 0) await attempt(loadPolicies);
    if (state.policies.length === 0) {
      if (await confirmDialog('No policies yet', 'Create a policy first: the organization\'s rules and what users may change.', 'New policy')) editPolicy(null);
      return;
    }
    modal((close) => {
      const choice = h('select', {}, state.policies.map((p) => h('option', { value: p.policy.id, text: `${p.policy.name} (${p.policy.rules.programs.length + p.policy.rules.network.length + p.policy.rules.services.length} rules)` })));
      return h('div', { class: 'dialog', role: 'dialog', 'aria-label': 'Apply a policy' },
        h('h2', { text: `Apply a policy to ${ids.length} computer(s)` }),
        h('p', { class: 'hint', style: 'margin:8px 0 14px', text: 'They apply it at their next check-in (within a few minutes). Each computer has one policy; this replaces the one it had.' }),
        h('label', { class: 'field' }, h('span', { text: 'Policy' }), choice),
        h('div', { class: 'buttons' },
          h('button', { class: 'ghost', text: 'Cancel', onclick: close }),
          h('button', { class: 'primary', text: 'Apply', onclick: () => { close(); assign(ids, choice.value); } })));
    });
  }

  /** The details of one computer, in a drawer. */
  async function openComputer(id) {
    await attempt(loadDevices);
    if (state.policies.length === 0) await attempt(loadPolicies);
    const d = state.devices.find((x) => x.id === id);
    if (!d) return toast('That computer is no longer on this server.', true);
    const r = d.report || {};
    let activityBox;
    const close = modal((closeDrawer) => {
      const policy = h('select', {}, h('option', { value: '', text: 'No policy' }),
        state.policies.map((p) => h('option', { value: p.policy.id, text: p.policy.name, selected: d.policyId === p.policy.id ? 'selected' : null })));
      const kind = h('select', { 'aria-label': 'What' }, [['blocked', 'Blocked'], ['allowed', 'Allowed'], ['all', 'Blocked and allowed']].map(([v, t]) => h('option', { value: v, text: t })));
      const hours = h('select', { 'aria-label': 'Period' }, [[1, 'Last hour'], [24, 'Last 24 hours'], [168, 'Last 7 days'], [720, 'Last 30 days']].map(([v, t]) => h('option', { value: v, text: t, selected: v === 24 ? 'selected' : null })));
      activityBox = h('div', {});
      return h('div', { class: 'drawer', role: 'dialog', 'aria-label': d.computer },
        h('div', { class: 'row' }, h('h1', { text: d.computer }), statusChip(d.status), h('span', { class: 'spacer' }), h('button', { class: 'ghost', text: 'Close', onclick: closeDrawer })),
        d.problems.length ? h('ul', { class: 'problems' }, d.problems.map((p) => h('li', { text: p }))) : null,
        h('dl', { class: 'facts' },
          h('dt', { text: 'Last check-in' }), h('dd', { text: `${when(d.lastSeenUtc)} (${ago(d.lastSeenUtc)})` }),
          h('dt', { text: 'Address' }), h('dd', { class: 'mono', text: d.address || '-' }),
          h('dt', { text: 'Enrolled' }), h('dd', { text: when(d.enrolledUtc) }),
          h('dt', { text: 'Mode' }), h('dd', { text: r.mode ? (modeText[r.mode] || r.mode) : '-' }),
          h('dt', { text: 'Panic' }), h('dd', { text: r.panic ? (r.panic === 'off' ? 'off' : r.panic === 'block' ? 'ON: all traffic blocked' : 'ON: everything allowed') : '-' }),
          h('dt', { text: 'Own rules' }), h('dd', { text: d.report ? `${r.programRules} program, ${r.networkRules} network, ${r.serviceRules} service` : '-' }),
          h('dt', { text: 'Changed programs' }), h('dd', { text: d.report ? String(r.changedPrograms) : '-' }),
          h('dt', { text: 'Tamper protection' }), h('dd', { text: d.report ? (r.requireAdmin ? 'on' : 'off') : '-' }),
          h('dt', { text: 'License' }), h('dd', { text: r.license || '-' }),
          h('dt', { text: 'CrioFire version' }), h('dd', { text: r.appVersion || '-' }),
          h('dt', { text: 'Windows' }), h('dd', { text: r.osVersion || '-' })),
        h('div', { class: 'card' },
          h('h2', { text: 'Policy' }),
          h('p', { class: 'sub', text: d.policyId ? (d.policyApplied ? 'Applied.' : 'Waiting for the computer to apply it at its next check-in.') : 'This computer has no policy: only its user\'s own rules apply.' }),
          h('div', { class: 'row' }, policy,
            h('button', { class: 'primary', text: 'Apply', onclick: () => { closeDrawer(); policy.value ? assign([d.id], policy.value) : assign([d.id], null); } }))),
        h('div', { class: 'card' },
          h('h2', { text: 'Activity' }),
          h('p', { class: 'sub', text: 'Computers send what they blocked and allowed only when you ask. It arrives after their next check-in (within a few minutes).' }),
          h('div', { class: 'row' }, kind, hours,
            h('button', { text: 'Ask for activity', onclick: async () => {
              const asked = await attempt(() => api('POST', `/devices/${encodeURIComponent(d.id)}/activity`, { kind: kind.value, hours: Number(hours.value), limit: 300 }), 'Asked. The computer answers after its next check-in.');
              if (asked) showActivity(d.id, activityBox, true);
            } })),
          activityBox),
        h('div', { class: 'row', style: 'margin-top:10px' }, h('span', { class: 'spacer' }),
          h('button', { class: 'danger', text: 'Remove from server', onclick: () => { closeDrawer(); removeComputers([d]); } })));
    }, false);
    showActivity(d.id, activityBox, false, close);
  }

  async function showActivity(id, box, waiting) {
    const data = await attempt(() => api('GET', `/devices/${encodeURIComponent(id)}/activity`));
    if (!data || !box.isConnected) return;
    const parts = [];
    if (data.pending) {
      parts.push(h('p', { class: 'hint', style: 'margin-top:12px', text: `Waiting for the computer to answer (asked ${ago(data.pending.requestedUtc)})...` }));
      setTimeout(() => { if (box.isConnected) showActivity(id, box, true); }, 10000);
    }
    const up = data.upload;
    if (up) {
      parts.push(h('p', { class: 'hint', style: 'margin-top:12px', text: `Sent ${when(up.createdUtc)}: ${up.page.connections} connection(s) in ${up.page.total} group(s).` }));
      parts.push(h('div', { class: 'table-wrap' }, h('table', {},
        h('thead', {}, h('tr', {}, h('th', { text: '' }), h('th', { text: 'Times' }), h('th', { text: 'Program' }), h('th', { text: 'To' }), h('th', { text: 'Why' }), h('th', { text: 'Last' }))),
        h('tbody', {}, up.page.items.length === 0
          ? h('tr', {}, h('td', { colspan: 6, class: 'empty', text: 'Nothing in that period.' }))
          : up.page.items.map((i) => h('tr', {},
            h('td', {}, h('span', { class: 'chip ' + (i.allowed ? 'ice' : 'fire'), text: i.allowed ? 'allowed' : 'blocked' })),
            h('td', { text: i.count }),
            h('td', { title: i.app || '', text: (i.app || i.service || '?').split('\\').pop() + (i.service ? ` (${i.service})` : '') }),
            h('td', { class: 'mono', text: `${i.remote || '?'}${i.port ? ':' + i.port : ''} ${i.protocol || ''}` }),
            h('td', { text: i.whyLabel || '' }),
            h('td', { text: ago(i.lastUtc) })))))));
    } else if (!data.pending && waiting === false) {
      parts.push(h('p', { class: 'hint', style: 'margin-top:12px', text: 'Nothing asked yet.' }));
    }
    fill(box, ...parts);
  }

  // ---------- policies ----------

  async function viewPolicies(main) {
    fill(main, head('Policies', 'Loading...'));
    const ok = await attempt(async () => { await Promise.all([loadPolicies(), loadDevices()]); return true; });
    if (!ok) return;
    fill(main,
      head('Policies', 'A policy is the organization\'s rules for the computers it is given to, and what their users may still change. Organization rules always win over users\' own.',
        h('button', { class: 'primary', text: 'New policy', onclick: () => editPolicy(null) })),
      state.policies.length === 0
        ? h('div', { class: 'card' }, h('p', { class: 'empty', text: 'No policies yet. Create one, or start from rules exported on a computer set up the way you want (criofire export).' }))
        : state.policies.map((v) => {
          const p = v.policy;
          const count = p.rules.programs.length + p.rules.network.length + p.rules.services.length;
          return h('div', { class: 'card policy-card' },
            h('div', {},
              h('div', { class: 'row' }, h('h2', { text: p.name }), v.isDefault ? h('span', { class: 'chip ice', text: 'for new computers' }) : null),
              h('div', { class: 'meta' },
                h('span', { class: 'chip ice', text: `${count} rule(s)` }),
                h('span', { class: 'chip ice', text: p.mode ? `mode: ${modeText[p.mode]}` : 'users choose the mode' }),
                h('span', { class: 'chip ' + (p.allowUserRules ? 'ice' : 'fire'), text: p.allowUserRules ? 'users may add rules' : 'locked: no user rules' }),
                p.requireAdmin ? h('span', { class: 'chip fire', text: 'tamper protection' }) : null,
                h('span', { class: 'chip ok', text: `${v.computers} computer(s)` })),
              h('p', { class: 'hint', style: 'margin-top:8px', text: `Version ${p.version}, changed ${when(p.updatedUtc)}.` })),
            h('div', { class: 'row', style: 'align-self:start' },
              h('button', { class: 'primary small', text: 'Apply to computers...', onclick: () => applyPolicyDialog(p) }),
              h('button', { class: 'small', text: 'Edit', onclick: () => editPolicy(p) }),
              h('button', { class: 'small', text: v.isDefault ? 'Not for new computers' : 'Use for new computers',
                onclick: async () => { if (await attempt(() => api('POST', `/policies/${v.isDefault ? 'none' : p.id}/default`), v.isDefault ? 'New computers get no policy.' : `New computers get "${p.name}".`) !== undefined) renderShell(); } }),
              h('button', { class: 'small danger', text: 'Delete', onclick: () => deletePolicy(p, v.computers) })));
        }));
  }

  async function deletePolicy(p, computers) {
    if (!(await confirmDialog(`Delete "${p.name}"?`, computers ? `${computers} computer(s) have it; they remove its rules at their next check-in.` : 'No computer has it.', 'Delete', true))) return;
    if (await attempt(() => api('DELETE', `/policies/${p.id}`), `Deleted "${p.name}".`) !== undefined) renderShell();
  }

  /** Apply a policy to all, some or one computer. */
  async function applyPolicyDialog(p) {
    await attempt(loadDevices);
    const devices = state.devices.slice().sort((a, b) => a.computer.localeCompare(b.computer));
    modal((close) => {
      const chosen = new Set(devices.filter((d) => d.policyId === p.id).map((d) => d.id));
      const list = h('div', { class: 'checklist' });
      const search = h('input', { type: 'search', placeholder: 'Search computers' });
      const count = h('span', { class: 'hint' });
      const drawList = () => {
        const text = search.value.trim().toLowerCase();
        const shown = devices.filter((d) => !text || d.computer.toLowerCase().includes(text));
        list.replaceChildren(...(shown.length ? shown.map((d) => h('label', {},
          h('input', { type: 'checkbox', checked: chosen.has(d.id), onchange: (e) => { e.target.checked ? chosen.add(d.id) : chosen.delete(d.id); drawCount(); } }),
          h('span', { text: d.computer }), h('span', { class: 'muted', text: d.policyName ? ` (now: ${d.policyName})` : ' (no policy)' }))) : [h('p', { class: 'empty', text: 'No computer matches.' })]));
      };
      const drawCount = () => { count.textContent = `${chosen.size} of ${devices.length} chosen`; };
      search.addEventListener('input', drawList);
      const all = h('button', { class: 'small', text: 'Choose all', onclick: () => { devices.forEach((d) => chosen.add(d.id)); drawList(); drawCount(); } });
      const none = h('button', { class: 'small ghost', text: 'Choose none', onclick: () => { chosen.clear(); drawList(); drawCount(); } });
      drawList();
      drawCount();
      return h('div', { class: 'dialog', role: 'dialog', 'aria-label': 'Apply to computers' },
        h('h2', { text: `Apply "${p.name}"` }),
        h('p', { class: 'hint', style: 'margin:8px 0 12px', text: 'Choose the computers that get this policy. They apply it at their next check-in. Computers you leave out keep the policy they have.' }),
        devices.length === 0 ? h('p', { class: 'empty', text: 'No computers yet.' }) : [h('div', { class: 'row' }, search, all, none, count), list],
        h('div', { class: 'buttons' },
          h('button', { class: 'ghost', text: 'Cancel', onclick: close }),
          h('button', { class: 'primary', text: 'Apply', disabled: devices.length === 0 ? true : null, onclick: async () => {
            const ids = [...chosen];
            if (ids.length === 0) return toast('Choose at least one computer.', true);
            close();
            await assign(ids, p.id);
          } })));
    });
  }

  // ---------- policy editor ----------

  const blankRules = () => ({ format: 1, programs: [], network: [], services: [], autoRules: [] });

  function editPolicy(policy) {
    const p = policy
      ? JSON.parse(JSON.stringify(policy))
      : { id: null, name: '', mode: null, allowUserRules: true, requireAdmin: false, rules: blankRules() };
    p.rules = Object.assign(blankRules(), p.rules || {});
    state.editing = p;
    state.view = 'policies';
    history.replaceState(null, '', '#policies');
    renderShell();
  }

  function renderEditor(main, p) {
    const name = h('input', { value: p.name, maxlength: 80, placeholder: 'For example: Office PCs', oninput: (e) => { p.name = e.target.value; } });
    const mode = h('select', { onchange: (e) => { p.mode = e.target.value || null; } },
      [['', 'Users choose the mode'], ['learning', 'Learning: programs without a rule may connect'], ['ask', 'Ask: new programs are blocked until someone decides'], ['allowlist', 'Allow-list: only programs with a rule may connect']]
        .map(([v, t]) => h('option', { value: v, text: t, selected: (p.mode || '') === v ? 'selected' : null })));
    const userRules = h('input', { type: 'checkbox', checked: p.allowUserRules, onchange: (e) => { p.allowUserRules = e.target.checked; } });
    const protect = h('input', { type: 'checkbox', checked: p.requireAdmin, onchange: (e) => { p.requireAdmin = e.target.checked; } });
    const auto = (key, label) => {
      const current = p.rules.autoRules.find((a) => a.name === key);
      return h('label', { class: 'field' }, h('span', { text: label }),
        h('select', { onchange: (e) => {
          p.rules.autoRules = p.rules.autoRules.filter((a) => a.name !== key);
          if (e.target.value) p.rules.autoRules.push({ name: key, enabled: e.target.value === 'on' });
        } },
        [['', 'Keep each computer\'s setting'], ['on', 'On'], ['off', 'Off']].map(([v, t]) => h('option', { value: v, text: t,
          selected: (current ? (current.enabled ? 'on' : 'off') : '') === v ? 'selected' : null }))));
    };

    const redraw = () => renderEditor(main, p);
    const select = (value, options, set) => h('select', { onchange: (e) => set(e.target.value) },
      options.map(([v, t]) => h('option', { value: v, text: t, selected: value === v ? 'selected' : null })));
    const actions = [['allow', 'Allow'], ['block', 'Block']];
    const directions = [['out', 'Outgoing'], ['in', 'Incoming'], ['both', 'Both']];
    // Which kinds of network a rule applies on (as Windows classifies them); elsewhere the mode decides.
    const networkChoices = (value) => {
      const list = [['', 'Every network'], ['domain,private', 'Home and work'], ['public', 'Public']];
      if (value && !list.some(([v]) => v === value)) list.push([value, value]);
      return list;
    };
    const networks = (r) => select(r.networks || '', networkChoices(r.networks || ''), (v) => { r.networks = v || null; });
    const remove = (list, i) => h('button', { class: 'icon ghost', title: 'Remove this rule', 'aria-label': 'Remove this rule', text: '✕', onclick: () => { list.splice(i, 1); redraw(); } });

    const programs = h('table', { class: 'edit' },
      h('thead', {}, h('tr', {}, h('th', { text: 'Program (full path, System for the Windows kernel, or pkg:<family> for a Store app)' }), h('th', { text: 'Action' }), h('th', { text: 'Direction' }), h('th', { text: 'Networks' }), h('th', {}))),
      h('tbody', {}, p.rules.programs.length === 0
        ? h('tr', {}, h('td', { colspan: 5, class: 'empty', text: 'No program rules.' }))
        : p.rules.programs.map((r, i) => h('tr', {},
          h('td', {}, h('input', { value: r.app, placeholder: 'C:\\Program Files\\App\\app.exe', oninput: (e) => { r.app = e.target.value; } })),
          h('td', {}, select(r.action, actions, (v) => { r.action = v; })),
          h('td', {}, select(r.direction, directions, (v) => { r.direction = v; })),
          h('td', {}, networks(r)),
          h('td', {}, remove(p.rules.programs, i))))));
    const network = h('table', { class: 'edit' },
      h('thead', {}, h('tr', {}, h('th', { text: 'Action' }), h('th', { text: 'Direction' }), h('th', { text: 'Protocol' }), h('th', { text: 'Ports' }), h('th', { text: 'Remote addresses' }), h('th', { text: 'Only for program (optional)' }), h('th', { text: 'Networks' }), h('th', {}))),
      h('tbody', {}, p.rules.network.length === 0
        ? h('tr', {}, h('td', { colspan: 8, class: 'empty', text: 'No port or address rules.' }))
        : p.rules.network.map((r, i) => h('tr', {},
          h('td', {}, select(r.action, actions, (v) => { r.action = v; })),
          h('td', {}, select(r.direction, directions, (v) => { r.direction = v; })),
          h('td', {}, select(r.protocol, [['any', 'Any'], ['tcp', 'TCP'], ['udp', 'UDP']], (v) => { r.protocol = v; })),
          h('td', {}, h('input', { value: r.ports, placeholder: '445 or 80,443', oninput: (e) => { r.ports = e.target.value; } })),
          h('td', {}, h('input', { value: r.addresses, placeholder: '10.0.0.0/8', oninput: (e) => { r.addresses = e.target.value; } })),
          h('td', {}, h('input', { value: r.app || '', placeholder: 'any program', oninput: (e) => { r.app = e.target.value || null; } })),
          h('td', {}, networks(r)),
          h('td', {}, remove(p.rules.network, i))))));
    const services = h('table', { class: 'edit' },
      h('thead', {}, h('tr', {}, h('th', { text: 'Windows service (its short name, e.g. DiagTrack)' }), h('th', { text: 'Action' }), h('th', { text: 'Direction' }), h('th', { text: 'Networks' }), h('th', {}))),
      h('tbody', {}, p.rules.services.length === 0
        ? h('tr', {}, h('td', { colspan: 5, class: 'empty', text: 'No service rules.' }))
        : p.rules.services.map((r, i) => h('tr', {},
          h('td', {}, h('input', { value: r.service, placeholder: 'DiagTrack', oninput: (e) => { r.service = e.target.value; } })),
          h('td', {}, select(r.action, actions, (v) => { r.action = v; })),
          h('td', {}, select(r.direction, directions, (v) => { r.direction = v; })),
          h('td', {}, networks(r)),
          h('td', {}, remove(p.rules.services, i))))));

    const file = h('input', { type: 'file', accept: '.json,application/json', hidden: true, onchange: async (e) => {
      const f = e.target.files[0];
      if (!f) return;
      try {
        const data = JSON.parse(await f.text());
        if (!Array.isArray(data.programs) && !Array.isArray(data.network) && !Array.isArray(data.services)) throw new Error();
        const key = (o) => JSON.stringify(o).toLowerCase();
        let added = 0;
        for (const list of ['programs', 'network', 'services']) {
          const have = new Set(p.rules[list].map(key));
          for (const r of data[list] || []) if (!have.has(key(r))) { p.rules[list].push(r); added++; }
        }
        toast(`Added ${added} rule(s) from ${f.name}.`);
        redraw();
      } catch {
        toast('That is not a CrioFire rules file (made with "criofire export" or Export on the Rules page).', true);
      }
    } });

    const save = async (thenApply) => {
      if (!p.name.trim()) return toast('Give the policy a name.', true);
      const body = { name: p.name, mode: p.mode, allowUserRules: p.allowUserRules, requireAdmin: p.requireAdmin, rules: cleanRules(p.rules) };
      const saved = await attempt(() => (p.id ? api('PUT', `/policies/${p.id}`, body) : api('POST', '/policies', body)),
        (s) => (p.id ? `Saved "${s.name}" (version ${s.version}). Computers with it apply the change at their next check-in.` : `Created "${s.name}".`));
      if (!saved) return;
      if (thenApply) {
        await loadPolicies();
        go('policies');
        applyPolicyDialog(saved);
      } else {
        go('policies');
      }
    };

    fill(main,
      head(p.id ? `Edit "${p.name}"` : 'New policy', p.id ? `Version ${p.version}. Saving makes a new version; computers with this policy apply it at their next check-in.` : 'The organization\'s rules and what users may still change.',
        h('button', { class: 'ghost', text: 'Cancel', onclick: () => go('policies') }),
        h('button', { text: 'Save', onclick: () => save(false) }),
        h('button', { class: 'primary', text: 'Save and apply to computers...', onclick: () => save(true) })),
      h('div', { class: 'card' },
        h('div', { class: 'grid2' },
          h('label', { class: 'field' }, h('span', { text: 'Name' }), name),
          h('label', { class: 'field' }, h('span', { text: 'Mode' }), mode)),
        h('div', { class: 'grid2', style: 'margin-top:16px' },
          h('label', { class: 'switch' }, userRules, h('span', {}, 'Users may add their own rules',
            h('small', { text: 'Off: users\' own rules are removed (a backup stays on each computer) and they cannot add any. Organization rules win either way.' }))),
          h('label', { class: 'switch' }, protect, h('span', {}, 'Require tamper protection',
            h('small', { text: 'Every rule change on the computer needs administrator approval, and users cannot switch this off.' })))),
        h('div', { class: 'grid2', style: 'margin-top:16px' },
          auto('svchost', 'Automatic rule: Windows services (DNS, updates...)'),
          auto('system', 'Automatic rule: Windows kernel (file sharing...)'))),
      h('div', { class: 'card' },
        h('div', { class: 'row' },
          h('h2', { text: 'Rules' }), h('span', { class: 'spacer' }),
          file,
          h('button', { class: 'small', text: 'Add rules from a file...', onclick: () => file.click() }),
          h('button', { class: 'small ghost', text: 'Save rules as a file', onclick: () => download(`criofire-policy-${(p.name || 'rules').replace(/[^\w-]+/g, '-')}.json`, JSON.stringify(cleanRules(p.rules), null, 2)) })),
        h('p', { class: 'sub', text: 'Tip: set up one computer the way you want, run "criofire export rules.json" (or Export on its Rules page), and add that file here. Rules for programs a computer does not have are skipped there.' }),
        h('div', { class: 'section-title' }, h('h3', { text: 'Programs' }), h('button', { class: 'small', text: 'Add program rule', onclick: () => { p.rules.programs.push({ app: '', action: 'allow', direction: 'out' }); redraw(); } })),
        h('div', { class: 'table-wrap' }, programs),
        h('div', { class: 'section-title' }, h('h3', { text: 'Ports and addresses' }), h('button', { class: 'small', text: 'Add network rule', onclick: () => { p.rules.network.push({ action: 'block', direction: 'in', protocol: 'tcp', ports: '', addresses: '', app: null }); redraw(); } })),
        h('div', { class: 'table-wrap' }, network),
        h('div', { class: 'section-title' }, h('h3', { text: 'Windows services' }), h('button', { class: 'small', text: 'Add service rule', onclick: () => { p.rules.services.push({ service: '', action: 'block', direction: 'out' }); redraw(); } })),
        h('div', { class: 'table-wrap' }, services)));
  }

  /** Drops empty rows and spaces before saving. */
  function cleanRules(rules) {
    return {
      format: 1,
      programs: rules.programs.filter((r) => r.app && r.app.trim()).map((r) => ({ app: r.app.trim(), action: r.action, direction: r.direction, networks: r.networks || null })),
      network: rules.network.filter((r) => (r.ports || '').trim() || (r.addresses || '').trim() || r.protocol !== 'any')
        .map((r) => ({ action: r.action, direction: r.direction, protocol: r.protocol, ports: (r.ports || '').trim(), addresses: (r.addresses || '').trim(), app: r.app && r.app.trim() ? r.app.trim() : null, networks: r.networks || null })),
      services: rules.services.filter((r) => r.service && r.service.trim()).map((r) => ({ service: r.service.trim(), action: r.action, direction: r.direction, networks: r.networks || null })),
      autoRules: rules.autoRules,
    };
  }

  // ---------- enrollment ----------

  async function viewEnroll(main) {
    fill(main, head('Add computers', 'Loading...'));
    const tokens = await attempt(() => api('GET', '/tokens'));
    if (!tokens) return;
    const uses = h('input', { type: 'number', min: 1, max: 100000, value: 25 });
    const days = h('input', { type: 'number', min: 1, max: 365, value: 7 });
    const note = h('input', { placeholder: 'For example: Sales laptops', maxlength: 80 });
    const result = h('div', {});
    fill(main,
      head('Add computers', 'Install CrioFire on each computer, then run one command there to connect it to this server.'),
      h('div', { class: 'card' },
        h('h2', { text: 'Create an enrollment code' }),
        h('p', { class: 'sub', text: 'One code can enroll many computers. They get the policy marked "for new computers", if there is one.' }),
        h('div', { class: 'grid2' },
          h('label', { class: 'field' }, h('span', { text: 'Computers it may enroll' }), uses),
          h('label', { class: 'field' }, h('span', { text: 'Valid for (days)' }), days),
          h('label', { class: 'field' }, h('span', { text: 'Note (optional)' }), note)),
        h('div', { class: 'row', style: 'margin-top:14px' },
          h('button', { class: 'primary', text: 'Create code', onclick: async () => {
            const made = await attempt(() => api('POST', '/tokens', { uses: Number(uses.value), days: Number(days.value), note: note.value || null }));
            if (!made) return;
            const copy = h('button', { text: 'Copy', onclick: async () => { await navigator.clipboard.writeText(made.command); toast('Copied.'); } });
            fill(result,
              h('p', { class: 'hint', style: 'margin-top:16px', text: 'Run this on each computer from an administrator prompt (the code is shown only now):' }),
              h('div', { class: 'copy' }, h('code', { text: made.command }), copy));
            refreshList();
          } })),
        result),
      h('div', { class: 'card' }, h('h2', { text: 'Codes that still work' }), h('div', { id: 'tokenList' })));
    const refreshList = async () => {
      const list = await attempt(() => api('GET', '/tokens'));
      const box = main.querySelector('#tokenList');
      if (!list || !box) return;
      fill(box, list.length === 0 ? h('p', { class: 'empty', text: 'No codes.' }) : h('div', { class: 'table-wrap' }, h('table', {},
        h('thead', {}, h('tr', {}, h('th', { text: 'Code' }), h('th', { text: 'Uses left' }), h('th', { text: 'Until' }), h('th', { text: 'Note' }), h('th', {}))),
        h('tbody', {}, list.map((t) => h('tr', {},
          h('td', { class: 'mono', text: t.id }), h('td', { text: t.usesLeft }), h('td', { text: when(t.expiresUtc) }), h('td', { text: t.note || '' }),
          h('td', {}, h('button', { class: 'small danger', text: 'Cancel code', onclick: async () => {
            if (await attempt(() => api('DELETE', `/tokens/${t.id}`), 'Cancelled.') !== undefined) refreshList();
          } }))))))));
    };
    refreshList();
  }

  // ---------- license ----------

  async function viewLicense(main) {
    fill(main, head('License', 'Loading...'));
    const l = await attempt(() => api('GET', '/license'));
    if (!l) return;
    const chipClass = { valid: 'ok', expiring: 'attention', expired: 'fire', invalid: 'fire', unavailable: 'offline', none: 'offline' }[l.state] || 'offline';
    const chipText = { valid: 'Valid', expiring: 'Expires soon', expired: 'Expired', invalid: 'Not valid', unavailable: 'Cannot be checked', none: 'No license' }[l.state] || l.state;
    const counted = l.seats > 0 && ['valid', 'expiring', 'expired'].includes(l.state);
    const pct = counted ? Math.min(100, Math.round((l.computers / l.seats) * 100)) : 0;
    const key = h('textarea', { rows: 4, placeholder: 'CRIOFIRE1....', spellcheck: 'false', 'aria-label': 'License key', class: 'mono' });
    fill(main,
      head('License', 'Your organization\'s CrioFire business license. The server gives it to every computer at its next check-in, so nobody has to enter it on each one.'),
      h('div', { class: 'card' },
        h('div', { class: 'row' }, h('h2', { text: l.licensee || 'No license yet' }), h('span', { class: 'chip ' + chipClass, text: chipText })),
        h('p', { class: 'sub', text: l.message }),
        counted ? [
          h('div', { class: 'meter' + (l.over ? ' over' : ''), role: 'meter', 'aria-valuemin': 0, 'aria-valuemax': l.seats, 'aria-valuenow': l.computers, 'aria-label': 'Seats used' },
            h('div', { style: `width:${pct}%` })),
          h('p', { class: 'hint', text: `${l.computers} of ${l.seats} seats used` + (l.over ? `: ${l.computers - l.seats} computer(s) more than the license covers. Computers keep working; add seats to stay covered.` : '.') }),
        ] : h('p', { class: 'hint', text: `${l.computers} computer(s) report to this server.` }),
        l.expiresUtc && l.state !== 'none' ? h('dl', { class: 'facts' },
          h('dt', { text: 'Edition' }), h('dd', { text: l.edition || '-' }),
          h('dt', { text: 'Valid until' }), h('dd', { text: when(l.expiresUtc) }),
          h('dt', { text: 'License id' }), h('dd', { class: 'mono', text: l.licenseId || '-' })) : null),
      h('div', { class: 'card' },
        h('h2', { text: l.state === 'none' ? 'Enter your license key' : 'Replace the license key' }),
        h('p', { class: 'sub', text: 'Paste the key from the email you received from CrioSoft (it starts with CRIOFIRE1).' }),
        key,
        h('div', { class: 'row', style: 'margin-top:12px' },
          h('button', { class: 'primary', text: 'Save key', onclick: async () => {
            if (!key.value.trim()) return toast('Paste the license key first.', true);
            if (await attempt(() => api('PUT', '/license', { key: key.value }), 'License saved. Computers get it at their next check-in.')) viewLicense(main);
          } }),
          h('span', { class: 'spacer' }),
          l.state === 'none' ? null : h('button', { class: 'danger', text: 'Remove key', onclick: async () => {
            if (!(await confirmDialog('Remove the license key?', 'The server stops giving it to computers. Computers that already have it keep it.', 'Remove', true))) return;
            if (await attempt(() => api('DELETE', '/license'), 'License key removed.')) viewLicense(main);
          } }))));
  }

  // ---------- administrators ----------

  async function viewAdmins(main) {
    fill(main, head('Administrators', 'Loading...'));
    const admins = await attempt(() => api('GET', '/admins'));
    if (!admins) return;
    const newName = h('input', { autocomplete: 'off' });
    const newPassword = h('input', { type: 'password', autocomplete: 'new-password' });
    const current = h('input', { type: 'password', autocomplete: 'current-password' });
    const next = h('input', { type: 'password', autocomplete: 'new-password' });
    fill(main,
      head('Administrators', 'People who can sign in to this console.'),
      h('div', { class: 'card' }, h('div', { class: 'table-wrap' }, h('table', {},
        h('thead', {}, h('tr', {}, h('th', { text: 'Name' }), h('th', { text: 'Added' }), h('th', { text: 'Last sign-in' }), h('th', {}))),
        h('tbody', {}, admins.map((a) => h('tr', {},
          h('td', {}, h('b', { text: a.name }), a.name.toLowerCase() === (state.me || '').toLowerCase() ? h('span', { class: 'muted', text: ' (you)' }) : null),
          h('td', { text: when(a.createdUtc) }), h('td', { text: when(a.lastSignInUtc) }),
          h('td', {}, a.name.toLowerCase() === (state.me || '').toLowerCase() ? null : h('button', { class: 'small danger', text: 'Remove', onclick: async () => {
            if (!(await confirmDialog(`Remove ${a.name}?`, 'They can no longer sign in.', 'Remove', true))) return;
            if (await attempt(() => api('DELETE', `/admins/${encodeURIComponent(a.name)}`), `Removed ${a.name}.`) !== undefined) renderShell();
          } })))))))),
      h('div', { class: 'grid2' },
        h('div', { class: 'card' }, h('h2', { text: 'Add an administrator' }),
          h('div', { style: 'display:grid;gap:12px;margin-top:12px' },
            h('label', { class: 'field' }, h('span', { text: 'Name' }), newName),
            h('label', { class: 'field' }, h('span', { text: 'Password (at least 10 characters)' }), newPassword),
            h('div', {}, h('button', { class: 'primary', text: 'Add', onclick: async () => {
              if (await attempt(() => api('POST', '/admins', { name: newName.value, password: newPassword.value }), `Added ${newName.value}.`) !== undefined) renderShell();
            } })))),
        h('div', { class: 'card' }, h('h2', { text: 'Change your password' }),
          h('div', { style: 'display:grid;gap:12px;margin-top:12px' },
            h('label', { class: 'field' }, h('span', { text: 'Current password' }), current),
            h('label', { class: 'field' }, h('span', { text: 'New password' }), next),
            h('div', {}, h('button', { class: 'primary', text: 'Change', onclick: async () => {
              if (await attempt(() => api('POST', '/password', { current: current.value, new: next.value }), 'Password changed.') !== undefined) { current.value = ''; next.value = ''; }
            } }))))));
  }

  start();
})();
