const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { create_store } = require('../src/lib/data-store');
const {
  command_definitions,
  handle_command,
  handle_reseller_modal,
  update_deferred_response
} = require('../src/discord/bot');
const { quote_order } = require('../src/reseller-service');

const user_id = '111111111111111111';
const admin_id = '222222222222222222';
const other_id = '333333333333333333';

process.env.AUTH_DISCORD_ADMIN_USER_IDS = admin_id;

function option(name, value) {
  return { name, value };
}

function interaction(name, options = [], admin = false, member_id = user_id) {
  return {
    data: { name, options },
    member: {
      permissions: admin ? '8' : '0',
      roles: [],
      user: {
        id: member_id,
        username: `user-${member_id.slice(-4)}`,
        global_name: 'Test User',
        avatar: null
      }
    }
  };
}

function reseller_modal_interaction(action, product = null, quantity = '', member_id = user_id) {
  const result = interaction('unused', [], false, member_id);
  result.type = 5;
  result.data = {
    custom_id: 'reseller:manager:v1',
    components: [
      {
        type: 18,
        component: { type: 3, custom_id: 'reseller_action', values: [action] }
      },
      {
        type: 18,
        component: { type: 3, custom_id: 'reseller_product', values: product ? [product] : [] }
      },
      {
        type: 18,
        component: { type: 4, custom_id: 'reseller_quantity', value: quantity }
      }
    ]
  };
  return result;
}

function content(result) {
  return result.data.content;
}

function balance_options(action, amount, reason) {
  return [
    option('user', user_id),
    option('action', action),
    option('amount', amount),
    option('reason', reason)
  ];
}

const expected_prices = [
  [1, 25, [674, 1124, 2624, 4499]],
  [5, 30, [629, 1049, 2449, 4199]],
  [10, 35, [584, 974, 2274, 3899]],
  [25, 40, [539, 899, 2099, 3599]],
  [50, 45, [494, 824, 1924, 3299]],
  [100, 50, [450, 750, 1750, 3000]]
];
const products = ['one_day', 'three_days', 'one_week', 'one_month'];

test('schema version 4 databases migrate reseller collections without losing licenses', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'auth-reseller-migration-'));

  try {
    const filename = path.join(directory, 'database.json');
    fs.writeFileSync(filename, JSON.stringify({
      schema_version: 4,
      keys: { 'EXISTING-KEY': { duration_seconds: 86400 } },
      service_state: { keys_paused: false, keys_paused_at: null }
    }));

    const database = create_store(filename).initialize();
    assert.equal(database.schema_version, 5);
    assert.ok(database.keys['EXISTING-KEY']);
    assert.deepEqual(database.resellers, {});
    assert.deepEqual(database.reseller_ledger, []);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('reseller quantity tiers use the configured cent-exact price table', () => {
  for (const [quantity, discount, prices] of expected_prices) {
    products.forEach((product, index) => {
      const quote = quote_order(product, quantity);
      assert.equal(quote.discount_percent, discount);
      assert.equal(quote.unit_price_cents, prices[index]);
      assert.equal(quote.total_cents, prices[index] * quantity);
    });
  }

  assert.equal(quote_order('one_day', 4).unit_price_cents, 674);
  assert.equal(quote_order('one_day', 9).unit_price_cents, 629);
  assert.equal(quote_order('one_day', 24).unit_price_cents, 584);
  assert.equal(quote_order('one_day', 49).unit_price_cents, 539);
  assert.equal(quote_order('one_day', 99).unit_price_cents, 494);
  assert.throws(() => quote_order('one_day', 0), /between 1 and/);
  assert.throws(() => quote_order('invalid', 1), /valid key duration/);
});

test('admins create reseller accounts and atomically add, set, or remove balances', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'auth-reseller-admin-'));

  try {
    const store = create_store(path.join(directory, 'database.json'));
    store.initialize();
    const services = { store };
    const create_options = [option('user', user_id), option('starting_balance', 100)];

    const denied = handle_command(interaction('add_reseller', create_options), services);
    assert.match(content(denied), /Administrator permission/);

    const created = handle_command(
      interaction('add_reseller', create_options, true, admin_id),
      services
    );
    assert.match(content(created), /\$100\.00/);
    assert.equal(store.read().resellers[user_id].balance_cents, 10000);

    const add = handle_command(
      interaction(
        'reseller_balance',
        balance_options('add', 25.55, 'Card payment received'),
        true,
        admin_id
      ),
      services
    );
    assert.match(content(add), /\$125\.55/);

    const remove = handle_command(
      interaction(
        'reseller_balance',
        balance_options('remove', 5.55, 'Balance correction'),
        true,
        admin_id
      ),
      services
    );
    assert.match(content(remove), /\$120\.00/);

    const set = handle_command(
      interaction(
        'reseller_balance',
        balance_options('set', 1000, 'Confirmed account balance'),
        true,
        admin_id
      ),
      services
    );
    assert.match(content(set), /\$1000\.00/);

    const before = store.read().resellers[user_id].balance_cents;
    const rejected = handle_command(
      interaction(
        'reseller_balance',
        balance_options('remove', 1000.01, 'Invalid overdraft'),
        true,
        admin_id
      ),
      services
    );
    assert.match(content(rejected), /outside the allowed range/);

    const database = store.read();
    assert.equal(database.resellers[user_id].balance_cents, before);
    assert.equal(database.reseller_ledger.length, 4);
    assert.ok(database.audit_events.some((entry) => entry.action === 'reseller.create'));
    assert.ok(database.audit_events.some((entry) => entry.action === 'reseller.balance.set'));
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('reseller modal reports balances and generates priced key batches as an attachment', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'auth-reseller-order-'));

  try {
    const store = create_store(path.join(directory, 'database.json'));
    store.initialize();
    const services = { store };

    handle_command(
      interaction(
        'add_reseller',
        [option('user', user_id), option('starting_balance', 5000)],
        true,
        admin_id
      ),
      services
    );

    assert.match(
      content(handle_command(interaction('reseller', [], false, other_id), services)),
      /do not have an active reseller/
    );

    const modal = handle_command(interaction('reseller'), services);
    assert.equal(modal.type, 9);
    assert.equal(modal.data.custom_id, 'reseller:manager:v1');

    const balance = await handle_reseller_modal(reseller_modal_interaction('balance'), services);
    assert.match(content(balance), /\$5000\.00/);

    const generated = await handle_reseller_modal(
      reseller_modal_interaction('generate', 'one_day', '100'),
      services
    );
    assert.ok(generated.file);
    assert.match(content(generated), /100 × 1 Day/);
    assert.match(content(generated), /\$4\.50 each/);
    assert.match(content(generated), /\$450\.00 total/);

    const file_lines = generated.file.buffer.toString('utf8').split('\n');
    const keys = file_lines.filter((line) => /^AUTH-[A-Z2-9-]+$/.test(line));
    assert.equal(keys.length, 100);
    assert.equal(new Set(keys).size, 100);

    const database = store.read();
    assert.equal(Object.keys(database.keys).length, 100);
    assert.equal(database.resellers[user_id].balance_cents, 455000);
    assert.equal(database.resellers[user_id].total_spent_cents, 45000);
    assert.equal(database.resellers[user_id].total_keys_generated, 100);
    assert.ok(keys.every((key) => database.keys[key].duration_seconds === 86400));
    assert.ok(keys.every((key) => database.keys[key].reseller_discord_id === user_id));
    assert.ok(database.reseller_ledger.some((entry) => {
      return entry.type === 'key_order' && entry.quantity === 100;
    }));
    assert.ok(database.audit_events.some((entry) => entry.action === 'reseller.keys.generate'));

    handle_command(
      interaction(
        'reseller_balance',
        balance_options('set', 0, 'Testing insufficient funds'),
        true,
        admin_id
      ),
      services
    );

    const key_count = Object.keys(store.read().keys).length;
    const rejected = await handle_reseller_modal(
      reseller_modal_interaction('generate', 'one_month', '1'),
      services
    );
    assert.match(content(rejected), /Insufficient reseller balance/);
    assert.equal(Object.keys(store.read().keys).length, key_count);
    assert.equal(rejected.file, undefined);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('Discord command registration includes reseller entry points', () => {
  const commands = new Map(command_definitions().map((command) => [command.name, command]));

  for (const name of ['add_reseller', 'reseller_balance', 'reseller']) {
    assert.ok(commands.has(name), name);
  }

  const action_choices = commands.get('reseller_balance').options
    .find((entry) => entry.name === 'action')
    .choices.map((entry) => entry.value);
  assert.deepEqual(action_choices, ['add', 'set', 'remove']);
});

test('deferred reseller responses upload generated keys as an ephemeral attachment', async () => {
  let captured;
  const fetch_impl = async (url, request) => {
    captured = { url, request };
    return { ok: true, status: 200 };
  };
  const payload = {
    type: 4,
    data: { content: 'Keys attached', flags: 64, allowed_mentions: { parse: [] } },
    file: { filename: 'keys.txt', buffer: Buffer.from('KEY-1\nKEY-2', 'utf8') }
  };

  await update_deferred_response(
    { application_id: '123456789012345678', token: 'interaction-token' },
    payload,
    fetch_impl
  );

  assert.equal(
    captured.url,
    'https://discord.com/api/v10/webhooks/123456789012345678/interaction-token/messages/@original'
  );
  assert.equal(captured.request.method, 'PATCH');
  assert.ok(captured.request.body instanceof FormData);

  const body = JSON.parse(captured.request.body.get('payload_json'));
  assert.deepEqual(body.attachments, [{ id: 0, filename: 'keys.txt' }]);
  assert.equal(await captured.request.body.get('files[0]').text(), 'KEY-1\nKEY-2');
});
