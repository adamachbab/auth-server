import { api, message, seconds } from './common.js';

const get_element = (id) => document.getElementById(id);
const notice = get_element('notice');

function form_body(form) {
  return Object.fromEntries(new FormData(form));
}

function show(account) {
  get_element('guest').hidden = true;
  get_element('member').hidden = false;
  get_element('email').textContent = account.email;
  get_element('time').textContent = seconds(account.remaining_seconds);
  load_devices();
}

async function session() {
  try {
    show((await api('/api/account')).account);
  } catch {
    get_element('guest').hidden = false;
    get_element('member').hidden = true;
  }
}

async function load_devices() {
  try {
    const { devices } = await api('/api/account/devices');
    get_element('devices').innerHTML = '';
    if (!devices.length) {
      get_element('devices').textContent = 'No linked devices.';
      return;
    }
    const table = document.createElement('table');
    table.innerHTML = '<thead><tr><th>Name</th><th>Scopes</th><th>Last used</th><th>Action</th></tr></thead>';
    const body = document.createElement('tbody');
    for (const device of devices) {
      const row = document.createElement('tr');
      const values = [
        device.name,
        device.scopes.join(', '),
        device.last_used_at
          ? new Date(device.last_used_at * 1000).toLocaleString()
          : 'Never',
      ];
      for (const value of values) {
        const cell = document.createElement('td');
        cell.textContent = value;
        row.append(cell);
      }
      const cell = document.createElement('td');
      const button = document.createElement('button');
      button.className = 'danger';
      button.textContent = device.revoked_at ? 'Revoked' : 'Revoke';
      button.disabled = Boolean(device.revoked_at);
      button.addEventListener('click', async () => {
        if (confirm(`Revoke ${device.name}?`)) {
          await api('/api/account/devices/revoke', {
            method: 'POST',
            body: JSON.stringify({ device_id: device.device_id }),
          });
          load_devices();
        }
      });
      cell.append(button);
      row.append(cell);
      body.append(row);
    }
    table.append(body);
    get_element('devices').append(table);
  } catch (error) {
    message(notice, error.message);
  }
}

get_element('login').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  try {
    const result = await api('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify(form_body(form)),
    });
    show(result.account);
    message(notice, 'Signed in.', true);
    form.reset();
  } catch (error) {
    message(notice, error.message);
  }
});

get_element('register').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  try {
    const result = await api('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify(form_body(form)),
    });
    message(notice, result.message, true);
    form.reset();
  } catch (error) {
    message(notice, error.message);
  }
});

get_element('redeem').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  try {
    const result = await api('/api/account/licenses/redeem', {
      method: 'POST',
      body: JSON.stringify(form_body(form)),
    });
    show(result.account);
    message(notice, 'License linked.', true);
    form.reset();
  } catch (error) {
    message(notice, error.message);
  }
});

get_element('password').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  try {
    const result = await api('/api/account/password', {
      method: 'POST',
      body: JSON.stringify(form_body(form)),
    });
    message(notice, result.message, true);
    form.reset();
    session();
  } catch (error) {
    message(notice, error.message);
  }
});

get_element('logout').addEventListener('click', async () => {
  try {
    await api('/api/auth/logout', { method: 'POST', body: '{}' });
  } finally {
    location.reload();
  }
});

get_element('refresh').addEventListener('click', load_devices);

session();
