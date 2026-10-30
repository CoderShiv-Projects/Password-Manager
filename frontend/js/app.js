'use strict';
/* Personal Password Management and Account Credential Organization System - frontend.
   Plain JavaScript + Fetch API. All data comes from the C++ backend; nothing is
   stored in the browser, and untrusted text is only ever inserted with textContent. */

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

// ---------- tiny DOM helpers ----------
function h(tag, props = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'text') el.textContent = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return el;
}
function icon(name) {
  const NS = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(NS, 'svg');
  svg.setAttribute('class', 'icon');
  svg.setAttribute('aria-hidden', 'true');
  const use = document.createElementNS(NS, 'use');
  use.setAttribute('href', '#i-' + name);
  svg.append(use);
  return svg;
}

// ---------- state ----------
const state = {
  view: 'dashboard',     // 'dashboard' | 'accounts'
  accounts: [],
  stats: null,
  categories: [],
  category: '',
  query: '',
  sort: 'name',
  loading: false,
  locked: true,
  lockMode: 'unlock',    // 'unlock' | 'init'
  revealed: new Map(),   // id -> plaintext password (shown briefly)
  revealTimers: new Map(),
  editingId: null,
  deleteTarget: null,
  generatorForForm: false,
  pollTimer: null,
};
const REVEAL_MS = 20000;

// ---------- API wrapper ----------
class ApiError extends Error {
  constructor(status, code, message, field) { super(message); this.status = status; this.code = code; this.field = field; }
}
async function api(path, { method = 'GET', body } = {}) {
  const opts = { method, headers: { 'X-Requested-With': 'ppm' }, credentials: 'same-origin' };
  if (body !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
  let res;
  try { res = await fetch(path, opts); }
  catch { throw new ApiError(0, 'network', 'Cannot reach the local server. Check that password_manager is still running.'); }
  let data = null;
  try { data = await res.json(); } catch { /* empty or non-JSON body */ }
  if (!res.ok) {
    const e = (data && data.error) || {};
    const err = new ApiError(res.status, e.code || 'error', e.message || `Request failed (HTTP ${res.status}).`, e.field);
    if (res.status === 401 && e.code === 'locked') showLock('The vault was locked. Enter your master password to continue.');
    throw err;
  }
  return data;
}

// ---------- toasts ----------
function toast(message, { kind = '', actionLabel, onAction, duration = 4000 } = {}) {
  const el = h('div', { class: 'toast ' + kind, role: 'status' }, h('span', { text: message }));
  const remove = () => el.remove();
  if (actionLabel) el.append(h('button', { type: 'button', text: actionLabel, onclick: () => { remove(); onAction && onAction(); } }));
  $('#toasts').append(el);
  setTimeout(remove, duration);
}
const errorToast = (err) => toast(err.message || 'Something went wrong.', { kind: 'error', duration: 6000 });

// ---------- formatting ----------
const fmtDate = (iso) => new Date(iso).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });

// ---------- lock screen ----------
function showLock(message) {
  state.locked = true;
  state.accounts = []; state.stats = null;
  clearReveals();
  $$('dialog[open]').forEach((d) => d.close());
  $('#app').hidden = true;
  const screen = $('#lockScreen');
  screen.hidden = false;
  screen.classList.remove('opening');
  clearInterval(state.pollTimer);
  initLockScreen(message);
}

async function initLockScreen(message) {
  const lead = $('#lockLead'), submit = $('#lockSubmit');
  submit.disabled = true;
  let status;
  try { status = await api('/api/vault/status'); }
  catch (e) { lead.textContent = e.message; return; }
  if (status.unlocked) { enterApp(false); return; }
  state.lockMode = status.initialized ? 'unlock' : 'init';
  const init = state.lockMode === 'init';
  $('#confirmRow').hidden = !init;
  $('#masterPassword').autocomplete = init ? 'new-password' : 'current-password';
  lead.textContent = message || (init
    ? 'Create a master password to encrypt your vault. There is no recovery if you forget it.'
    : 'Enter your master password to unlock the vault.');
  submit.textContent = init ? 'Create vault' : 'Unlock vault';
  submit.disabled = false;
  if (!init && status.retryAfterSeconds > 0) showLockError(`Too many failed attempts. Try again in ${status.retryAfterSeconds} seconds.`);
  else showLockError('');
  $('#masterPassword').focus();
}

function showLockError(msg) {
  const el = $('#lockError');
  el.textContent = msg;
  el.hidden = !msg;
}

async function submitLock(ev) {
  ev.preventDefault();
  const pw = $('#masterPassword').value;
  const submit = $('#lockSubmit');
  showLockError('');
  if (state.lockMode === 'init') {
    if ([...pw].length < 12) return showLockError('Use at least 12 characters for the master password.');
    if (pw !== $('#masterConfirm').value) return showLockError('The two passwords do not match.');
  } else if (!pw) {
    return showLockError('Enter your master password.');
  }
  submit.disabled = true;
  const label = submit.textContent;
  submit.textContent = state.lockMode === 'init' ? 'Creating vault…' : 'Unlocking…';
  try {
    await api(state.lockMode === 'init' ? '/api/vault/init' : '/api/vault/unlock', { method: 'POST', body: { masterPassword: pw } });
    $('#masterPassword').value = ''; $('#masterConfirm').value = '';
    await enterApp(true);
  } catch (e) {
    showLockError(e.message);
    $('#masterPassword').select();
  } finally {
    submit.disabled = false;
    submit.textContent = label;
  }
}

async function enterApp(animate) {
  const screen = $('#lockScreen');
  if (animate) { screen.classList.add('opening'); await new Promise((r) => setTimeout(r, 450)); }
  screen.hidden = true;
  $('#app').hidden = false;
  state.locked = false;
  if (!state.categories.length) {
    try { state.categories = (await api('/api/categories')).categories; } catch (e) { errorToast(e); }
    fillCategorySelect();
  }
  await loadAccounts();
  clearInterval(state.pollTimer);
  state.pollTimer = setInterval(pollStatus, 15000);
}

async function pollStatus() {
  if (state.locked) return;
  try {
    const s = await api('/api/vault/status');
    if (!s.unlocked) showLock('The vault locked itself after a period of inactivity.');
  } catch { /* transient; next poll will retry */ }
}

async function lockVault() {
  try { await api('/api/vault/lock', { method: 'POST' }); showLock('Vault locked.'); }
  catch (e) { if (e.code !== 'locked') errorToast(e); }
}

// ---------- loading & rendering ----------
async function loadAccounts() {
  state.loading = true;
  render();
  const params = new URLSearchParams();
  if (state.view === 'accounts') {
    if (state.query) params.set('q', state.query);
    if (state.category) params.set('category', state.category);
  }
  try {
    const data = await api('/api/accounts' + (params.toString() ? '?' + params : ''));
    state.accounts = data.accounts;
    state.stats = data.stats;
  } catch (e) {
    if (e.code !== 'locked') errorToast(e);
  } finally {
    state.loading = false;
    render();
  }
}

function sortedAccounts() {
  const list = [...state.accounts];
  if (state.sort === 'recent') list.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
  else list.sort((a, b) => a.website.localeCompare(b.website, undefined, { sensitivity: 'base' }) || a.username.localeCompare(b.username));
  return list;
}

function render() {
  renderSidebar();
  const stats = state.stats;
  $('#undoButton').disabled = !(stats && stats.undoDepth > 0);
  $('#undoCount').textContent = stats && stats.undoDepth > 0 ? stats.undoDepth : '';
  $('#saveWarning').hidden = !(stats && stats.unsavedChanges);
  $('#sortSelect').parentElement.hidden = state.view !== 'accounts';
  if (state.view === 'dashboard') renderDashboard(); else renderAccounts();
}

function renderSidebar() {
  $$('[data-nav]').forEach((b) => b.classList.toggle('active', b.dataset.nav === state.view && !(state.view === 'accounts' && state.category)));
  $('#navTotal').textContent = state.stats ? state.stats.total : '';
  const nav = $('#categoryNav');
  nav.replaceChildren(...state.categories.map((c) => {
    const n = state.stats ? (state.stats.byCategory.find((x) => x.category === c) || {}).count || 0 : 0;
    const btn = h('button', { class: 'nav-item' + (state.view === 'accounts' && state.category === c ? ' active' : ''), type: 'button', 'data-category': c },
      h('span', { class: 'dot cat-' + c }), c, h('span', { class: 'count', text: n }));
    return btn;
  }));
}

function skeleton() { return h('div', { class: 'rows' }, h('div', { class: 'skeleton' }), h('div', { class: 'skeleton' }), h('div', { class: 'skeleton' })); }

function emptyState(title, text, withAdd) {
  return h('div', { class: 'empty' }, h('h2', { text: title }), h('p', { text }),
    withAdd ? h('button', { class: 'btn primary', type: 'button', 'data-action': 'add' }, icon('plus'), 'Add account') : null);
}

function accountRow(a) {
  const pw = state.revealed.get(a.id);
  const flags = [];
  if (a.weakPassword) flags.push(h('span', { class: 'flag', text: 'Weak password' }));
  if (a.reusedPassword) flags.push(h('span', { class: 'flag', text: 'Reused password' }));
  const iconBtn = (name, label, action) => h('button', { class: 'icon-btn', type: 'button', 'data-action': action, 'aria-label': label, title: label }, icon(name));
  return h('li', { class: 'row', 'data-id': a.id },
    h('div', { class: 'row-main' },
      h('div', { class: 'site', text: a.website, title: a.website }),
      h('div', { class: 'user' }, a.username, flags)),
    h('span', { class: 'chip cat-' + a.category, text: a.category }),
    pw ? h('div', { class: 'secret shown' }, pw)
       : h('div', { class: 'secret', 'aria-label': 'Password hidden' }, '••••••••••'),
    h('div', { class: 'row-actions' },
      iconBtn(pw ? 'eye-off' : 'eye', pw ? 'Hide password' : 'Show password', 'toggle'),
      iconBtn('copy', 'Copy password', 'copy'),
      iconBtn('edit', 'Edit account', 'edit'),
      iconBtn('trash', 'Delete account', 'delete')));
}

function renderAccounts() {
  const view = $('#view');
  const title = state.category ? state.category : 'All accounts';
  const head = h('div', { class: 'view-title' }, h('h1', { text: title }),
    h('span', { class: 'muted', text: state.loading ? 'Loading…' : `${state.accounts.length} ${state.accounts.length === 1 ? 'account' : 'accounts'}` }));
  let body;
  if (state.loading && !state.accounts.length) body = skeleton();
  else if (!state.accounts.length) {
    const total = state.stats ? state.stats.total : 0;
    body = (state.query || state.category) && total > 0
      ? emptyState('No accounts match', 'Try a different search or choose another category.', false)
      : emptyState('Your vault is empty', 'Add your first account to start organizing your credentials.', true);
  } else body = h('ul', { class: 'rows' }, sortedAccounts().map(accountRow));
  view.replaceChildren(head, body);
}

function renderDashboard() {
  const view = $('#view');
  const s = state.stats;
  const head = h('div', { class: 'view-title' }, h('h1', { text: 'Dashboard' }));
  if (!s) { view.replaceChildren(head, skeleton()); return; }
  if (s.total === 0) { view.replaceChildren(head, emptyState('Your vault is empty', 'Add your first account to start organizing your credentials.', true)); return; }

  const strip = h('div', { class: 'stat-strip' },
    h('div', { class: 'stat' }, h('b', { text: s.total }), h('span', { text: s.total === 1 ? 'saved account' : 'saved accounts' })),
    h('div', { class: 'stat' + (s.weakPasswords ? ' warn' : '') }, h('b', { text: s.weakPasswords }), h('span', { text: 'weak passwords' })),
    h('div', { class: 'stat' + (s.reusedPasswords ? ' warn' : '') }, h('b', { text: s.reusedPasswords }), h('span', { text: 'accounts sharing a password' })));

  const used = s.byCategory.filter((c) => c.count > 0);
  const dist = h('div', { class: 'dist', role: 'img', 'aria-label': 'Accounts per category' },
    used.map((c) => { const seg = h('span', { class: 'seg cat-' + c.category, title: `${c.category}: ${c.count}` }); seg.style.flexGrow = c.count; return seg; }));
  const legend = h('div', { class: 'legend' }, used.map((c) => h('span', {}, h('i', { class: 'dot cat-' + c.category }), c.category, h('b', { text: c.count }))));
  const distPanel = h('section', { class: 'panel' }, h('h2', { text: 'Accounts by category' }), dist, legend);

  const attention = state.accounts.filter((a) => a.weakPassword || a.reusedPassword);
  const recent = [...state.accounts].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt)).slice(0, 5);
  const panels = [strip, distPanel];
  if (attention.length) panels.push(h('section', {}, h('div', { class: 'view-title' }, h('h2', { text: 'Needs attention' })), h('ul', { class: 'rows' }, attention.slice(0, 5).map(accountRow))));
  panels.push(h('section', { style: null }, h('div', { class: 'view-title' }, h('h2', { text: 'Recently updated' }), h('span', { class: 'muted', text: fmtDate(recent[0].updatedAt) })), h('ul', { class: 'rows' }, recent.map(accountRow))));
  view.replaceChildren(head, ...panels);
}

function setView(view, category = '') {
  state.view = view; state.category = category;
  if (view === 'dashboard') { state.query = ''; $('#searchInput').value = ''; }
  loadAccounts();
}

// ---------- reveal / copy ----------
function clearReveals() {
  state.revealTimers.forEach((t) => clearTimeout(t));
  state.revealTimers.clear(); state.revealed.clear();
}
function hideReveal(id) {
  clearTimeout(state.revealTimers.get(id));
  state.revealTimers.delete(id); state.revealed.delete(id);
}
async function fetchPassword(id) { return (await api('/api/accounts/' + encodeURIComponent(id))).account.password; }

async function toggleReveal(id) {
  if (state.revealed.has(id)) { hideReveal(id); render(); return; }
  try {
    state.revealed.set(id, await fetchPassword(id));
    state.revealTimers.set(id, setTimeout(() => { hideReveal(id); render(); }, REVEAL_MS));
    render();
  } catch (e) { if (e.code !== 'locked') errorToast(e); }
}

async function copyText(text) {
  try { await navigator.clipboard.writeText(text); return true; }
  catch {
    const ta = h('textarea', { 'aria-hidden': 'true' });
    ta.value = text; document.body.append(ta); ta.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch { ok = false; }
    ta.remove();
    return ok;
  }
}
async function copyPassword(id) {
  try {
    const ok = await copyText(await fetchPassword(id));
    toast(ok ? 'Password copied to the clipboard.' : 'Copy failed. Use Show password and copy it manually.', { kind: ok ? 'ok' : 'error' });
  } catch (e) { if (e.code !== 'locked') errorToast(e); }
}

// ---------- add / edit dialog ----------
function fillCategorySelect() {
  $('#fCategory').replaceChildren(...state.categories.map((c) => h('option', { value: c, text: c })));
}
function clearFormErrors() { $$('[data-error-for]').forEach((p) => { p.hidden = true; p.textContent = ''; }); }
function showFormError(field, msg) {
  const el = $(`[data-error-for="${field}"]`) || $('[data-error-for="form"]');
  el.textContent = msg; el.hidden = false;
}
function setPasswordVisible(visible) {
  $('#fPassword').type = visible ? 'text' : 'password';
  $('#fToggle').setAttribute('aria-label', visible ? 'Hide password' : 'Show password');
  $('#fToggle').replaceChildren(icon(visible ? 'eye-off' : 'eye'));
}

function openAccountDialog(account) {
  state.editingId = account ? account.id : null;
  clearFormErrors();
  $('#accountForm').reset();
  setPasswordVisible(false);
  $('#accountDialogTitle').textContent = account ? 'Edit account' : 'Add account';
  $('#accountSubmit').textContent = account ? 'Save changes' : 'Add account';
  $('#fPassword').placeholder = account ? 'Leave blank to keep the current password' : '';
  if (account) {
    $('#fWebsite').value = account.website;
    $('#fUsername').value = account.username;
    $('#fCategory').value = account.category;
  }
  $('#accountDialog').showModal();
  $('#fWebsite').focus();
}

async function submitAccount(ev) {
  ev.preventDefault();
  clearFormErrors();
  const editing = state.editingId;
  const body = { website: $('#fWebsite').value, username: $('#fUsername').value, category: $('#fCategory').value };
  const pw = $('#fPassword').value;
  if (!editing || pw) body.password = pw;
  if (!body.website.trim()) return showFormError('website', 'Enter a website or app name.');
  if (!body.username.trim()) return showFormError('username', 'Enter a username or email.');
  if (!editing && !pw) return showFormError('password', 'Enter a password or use Generate.');

  const btn = $('#accountSubmit');
  btn.disabled = true;
  try {
    await api(editing ? '/api/accounts/' + encodeURIComponent(editing) : '/api/accounts', { method: editing ? 'PUT' : 'POST', body });
    if (editing) hideReveal(editing);
    $('#accountDialog').close();
    toast(editing ? 'Account updated.' : 'Account added.', { kind: 'ok' });
    await loadAccounts();
  } catch (e) {
    if (e.code === 'locked') return;
    if (e.status === 400 && e.field) showFormError(e.field, e.message);
    else { showFormError('form', e.message); if (e.code === 'storage_error') loadAccounts(); }
  } finally { btn.disabled = false; }
}

async function startEdit(id) {
  const acc = state.accounts.find((a) => a.id === id);
  if (acc) openAccountDialog(acc);
}

// ---------- delete / undo ----------
function askDelete(id) {
  const acc = state.accounts.find((a) => a.id === id);
  if (!acc) return;
  state.deleteTarget = acc;
  $('#confirmText').textContent = `${acc.website} (${acc.username}) will be removed from your vault.`;
  $('#confirmDialog').showModal();
}
async function confirmDelete() {
  const acc = state.deleteTarget;
  if (!acc) return;
  const btn = $('#confirmDelete');
  btn.disabled = true;
  try {
    await api('/api/accounts/' + encodeURIComponent(acc.id), { method: 'DELETE' });
    hideReveal(acc.id);
    $('#confirmDialog').close();
    toast(`Deleted ${acc.website}.`, { actionLabel: 'Undo', onAction: undoDelete, duration: 10000 });
    await loadAccounts();
  } catch (e) {
    $('#confirmDialog').close();
    if (e.code !== 'locked') { errorToast(e); loadAccounts(); }
  } finally { btn.disabled = false; state.deleteTarget = null; }
}
async function undoDelete() {
  try {
    const data = await api('/api/undo-delete', { method: 'POST' });
    toast(`Restored ${data.restored.website}.`, { kind: 'ok' });
    await loadAccounts();
  } catch (e) {
    if (e.code === 'nothing_to_undo') { toast('There is nothing to undo.'); loadAccounts(); }
    else if (e.code !== 'locked') errorToast(e);
  }
}

// ---------- password generator ----------
const POOLS = { lower: 26, upper: 26, numbers: 10, symbols: 25 };
let genTimer = null;

function genOptions() {
  return {
    length: Number($('#genLength').value),
    lowercase: $('#genLower').checked, uppercase: $('#genUpper').checked,
    numbers: $('#genNumbers').checked, symbols: $('#genSymbols').checked,
  };
}
function updateStrength(o) {
  const pool = (o.lowercase ? POOLS.lower : 0) + (o.uppercase ? POOLS.upper : 0) + (o.numbers ? POOLS.numbers : 0) + (o.symbols ? POOLS.symbols : 0);
  const bits = pool ? Math.round(o.length * Math.log2(pool)) : 0;
  const level = bits < 50 ? ['Weak', 20, '#ea7b84'] : bits < 75 ? ['Fair', 45, '#f0975a'] : bits < 110 ? ['Strong', 75, '#d9a94a'] : ['Excellent', 100, '#67c9a0'];
  const meter = $('#genMeter');
  meter.style.width = level[1] + '%'; meter.style.background = level[2];
  $('#genStrength').textContent = `${level[0]} (about ${bits} bits of entropy)`;
}
async function generatePassword() {
  const o = genOptions();
  $('#genLengthValue').textContent = o.length;
  const err = $('#genError');
  if (!o.lowercase && !o.uppercase && !o.numbers && !o.symbols) {
    err.textContent = 'Select at least one character type.'; err.hidden = false;
    $('#genOutput').textContent = ''; return;
  }
  err.hidden = true;
  updateStrength(o);
  try { $('#genOutput').textContent = (await api('/api/generate-password', { method: 'POST', body: o })).password; }
  catch (e) { err.textContent = e.message; err.hidden = false; }
}
function scheduleGenerate() { clearTimeout(genTimer); genTimer = setTimeout(generatePassword, 120); }
function openGenerator(forForm) {
  state.generatorForForm = forForm;
  $('#genUse').hidden = !forForm;
  $('#generatorDialog').showModal();
  generatePassword();
}

// ---------- wiring ----------
function bindEvents() {
  $('#lockForm').addEventListener('submit', submitLock);
  $('#lockButton').addEventListener('click', lockVault);
  $('#addButton').addEventListener('click', () => openAccountDialog(null));
  $('#undoButton').addEventListener('click', undoDelete);
  $('#openGenerator').addEventListener('click', () => openGenerator(false));
  $('#accountForm').addEventListener('submit', submitAccount);
  $('#fToggle').addEventListener('click', () => setPasswordVisible($('#fPassword').type === 'password'));
  $('#fGenerate').addEventListener('click', () => openGenerator(true));
  $('#confirmDelete').addEventListener('click', confirmDelete);

  $$('dialog [data-close]').forEach((b) => b.addEventListener('click', () => b.closest('dialog').close()));
  $$('dialog').forEach((d) => d.addEventListener('click', (ev) => { if (ev.target === d) d.close(); }));

  $('#genLength').addEventListener('input', scheduleGenerate);
  ['#genLower', '#genUpper', '#genNumbers', '#genSymbols'].forEach((s) => $(s).addEventListener('change', generatePassword));
  $('#genRegenerate').addEventListener('click', generatePassword);
  $('#genCopy').addEventListener('click', async () => {
    const pw = $('#genOutput').textContent;
    if (!pw) return;
    toast((await copyText(pw)) ? 'Password copied to the clipboard.' : 'Copy failed.', { kind: 'ok' });
  });
  $('#genUse').addEventListener('click', () => {
    const pw = $('#genOutput').textContent;
    if (!pw) return;
    $('#fPassword').value = pw; setPasswordVisible(true);
    $('#generatorDialog').close();
    $('#fPassword').focus();
  });

  $$('[data-nav]').forEach((b) => b.addEventListener('click', () => setView(b.dataset.nav)));
  $('#categoryNav').addEventListener('click', (ev) => {
    const b = ev.target.closest('[data-category]');
    if (b) setView('accounts', b.dataset.category);
  });

  let searchTimer = null;
  $('#searchInput').addEventListener('input', (ev) => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      state.query = ev.target.value.trim();
      if (state.view !== 'accounts') state.view = 'accounts';
      loadAccounts();
    }, 220);
  });
  $('#sortSelect').addEventListener('change', (ev) => { state.sort = ev.target.value; render(); });

  $('#view').addEventListener('click', (ev) => {
    const btn = ev.target.closest('[data-action]');
    if (!btn) return;
    const row = btn.closest('[data-id]');
    const id = row && row.dataset.id;
    switch (btn.dataset.action) {
      case 'add': openAccountDialog(null); break;
      case 'toggle': toggleReveal(id); break;
      case 'copy': copyPassword(id); break;
      case 'edit': startEdit(id); break;
      case 'delete': askDelete(id); break;
    }
  });

  document.addEventListener('keydown', (ev) => {
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName);
    if (ev.key === '/' && !typing && !state.locked && !$('dialog[open]')) { ev.preventDefault(); $('#searchInput').focus(); }
  });
  document.addEventListener('visibilitychange', () => { if (!document.hidden) pollStatus(); });
}

bindEvents();
initLockScreen();
