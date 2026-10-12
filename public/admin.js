import { api, message, seconds } from './common.js';

const get_element = (id) => document.getElementById(id);
const notice = get_element('notice');
let page = 1;
let pages = 1;
let current = null;
let pending = null;

function cell(text) {
  const value = document.createElement('td');
  value.textContent = text;
  return value;
}

function stat(label, value) {
  const box = document.createElement('div');
  box.className = 'stat';
  const name = document.createElement('span');
  name.className = 'muted';
  name.textContent = label;
  const strong = document.createElement('strong');
  strong.textContent = value;
  box.append(name, strong);
  return box;
}

async function load() {
  try {
    const form = new FormData(get_element('search'));
    const query = new URLSearchParams({
      page: String(page),
      page_size: '20',
      q: form.get('q'),
      status: form.get('status'),
    });
    const data = await api(`/api/admin/users?${query}`);
    pages = data.pagination.pages || 1;
    get_element('users').replaceChildren();
    const table = document.createElement('table');
    const head = document.createElement('thead');
    const head_row = document.createElement('tr');
    for (const title of ['Email', 'Status', 'Time', '']) {
      const th = document.createElement('th');
      th.textContent = title;
      head_row.append(th);
    }
    head.append(head_row);
    table.append(head);
    const body = document.createElement('tbody');
    for (const user of data.users) {
      const row = document.createElement('tr');
      row.append(
        cell(user.email),
        cell(user.status),
        cell(seconds(user.remaining_seconds)),
      );
      const action = cell('');
      const button = document.createElement('button');
      button.textContent = 'View';
      button.addEventListener('click', () => details(user.admin_ref));
      action.append(button);
      row.append(action);
      body.append(row);
    }
    table.append(body);
    get_element('users').append(table);
    get_element('previous').disabled = page <= 1;
    get_element('next').disabled = page >= pages;
  } catch (error) {
    message(notice, error.message);
  }
}

async function details(ref) {
  try {
    const data = await api(`/api/admin/users/${encodeURIComponent(ref)}`);
    current = data.user;
    get_element('detail').hidden = false;
    get_element('detail-email').textContent = current.email;
    get_element('detail-stats').replaceChildren(
      stat('Status', current.status),
      stat('Subscription', seconds(current.remaining_seconds)),
      stat('Licenses', String(current.linked_license_count)),
    );
    get_element('detail-devices').textContent = data.devices.length
      ? data.devices
        .map((device) => `${device.name} — ${device.revoked_at ? 'revoked' : 'active'}`)
        .join('\n')
      : 'No devices.';
    get_element('history').textContent = data.audit_history.length
      ? data.audit_history
        .map((entry) => `${new Date(entry.created_at * 1000).toLocaleString()} — ${entry.action}: ${entry.reason}`)
        .join('\n')
      : 'No audit events.';
  } catch (error) {
    message(notice, error.message);
  }
}

function open_dialog(action) {
  if (!current) {
    return;
  }
  pending = action;
  get_element('confirm-title').textContent = {
    'subscription': 'Adjust subscription time',
    'hwid-reset': 'Reset HWID',
    'status': 'Change account status',
  }[action];
  get_element('value-field').hidden = action !== 'subscription';
  get_element('status-field').hidden = action !== 'status';
  get_element('value').required = action === 'subscription';
  get_element('value').value = '';
  get_element('reason').value = '';
  get_element('confirm').showModal();
}

document.querySelectorAll('[data-action]').forEach((button) => {
  button.addEventListener('click', () => open_dialog(button.dataset.action));
});

get_element('confirm-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!current || !pending) {
    return;
  }
  const reason = get_element('reason').value;
  const title = get_element('confirm-title').textContent.toLowerCase();
  if (!confirm(`Confirm ${title} for ${current.email}?`)) {
    return;
  }
  const body = { reason };
  if (pending === 'subscription') {
    body.seconds = Number(get_element('value').value);
  }
  if (pending === 'status') {
    body.status = get_element('new-status').value;
  }
  try {
    await api(`/api/admin/users/${encodeURIComponent(current.admin_ref)}/${pending}`, {
      method: 'POST',
      body: JSON.stringify(body),
    });
    get_element('confirm').close();
    message(notice, 'Operation completed and audited.', true);
    await details(current.admin_ref);
    await load();
  } catch (error) {
    message(notice, error.message);
  }
});

get_element('search').addEventListener('submit', (event) => {
  event.preventDefault();
  page = 1;
  load();
});

get_element('previous').addEventListener('click', () => {
  page = Math.max(1, page - 1);
  load();
});

get_element('next').addEventListener('click', () => {
  page = Math.min(pages, page + 1);
  load();
});

load();
