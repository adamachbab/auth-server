const crypto = require('crypto');

const max_order_quantity = 1000;
const max_balance_cents = 100_000_000;

const products = Object.freeze({
  one_day: Object.freeze({ label: '1 Day', duration_seconds: 86400 }),
  three_days: Object.freeze({ label: '3 Day', duration_seconds: 3 * 86400 }),
  one_week: Object.freeze({ label: '1 Week', duration_seconds: 7 * 86400 }),
  one_month: Object.freeze({ label: '1 Month', duration_seconds: 30 * 86400 })
});

function tier(minimum, label, discount_percent, prices) {
  return Object.freeze({
    minimum,
    label,
    discount_percent,
    prices: Object.freeze(prices)
  });
}

const tiers = Object.freeze([
  tier(100, '100+', 50, { one_day: 450, three_days: 750, one_week: 1750, one_month: 3000 }),
  tier(50, '50–99', 45, { one_day: 494, three_days: 824, one_week: 1924, one_month: 3299 }),
  tier(25, '25–49', 40, { one_day: 539, three_days: 899, one_week: 2099, one_month: 3599 }),
  tier(10, '10–24', 35, { one_day: 584, three_days: 974, one_week: 2274, one_month: 3899 }),
  tier(5, '5–9', 30, { one_day: 629, three_days: 1049, one_week: 2449, one_month: 4199 }),
  tier(1, '1–4', 25, { one_day: 674, three_days: 1124, one_week: 2624, one_month: 4499 })
]);

class reseller_error extends Error {}

function now_unix() {
  return Math.floor(Date.now() / 1000);
}

function valid_discord_id(value) {
  return /^\d{17,20}$/.test(String(value || ''));
}

function format_money(cents) {
  return `$${(cents / 100).toFixed(2)}`;
}

function valid_cents(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= max_balance_cents;
}

function cents_from_amount(value) {
  const amount = Number(value);

  if (!Number.isFinite(amount) || amount < 0) {
    return null;
  }

  const cents = Math.round(amount * 100);

  if (
    !Number.isSafeInteger(cents) ||
    cents > max_balance_cents ||
    Math.abs(amount * 100 - cents) > 1e-7
  ) {
    return null;
  }

  return cents;
}

function ensure_collections(db) {
  if (!db.resellers || typeof db.resellers !== 'object' || Array.isArray(db.resellers)) {
    db.resellers = {};
  }

  if (!Array.isArray(db.reseller_ledger)) {
    db.reseller_ledger = [];
  }
}

function reseller_account(db, discord_id) {
  ensure_collections(db);

  const account = db.resellers[String(discord_id || '')];

  if (
    !account ||
    account.status !== 'active' ||
    !Number.isSafeInteger(account.balance_cents) ||
    account.balance_cents < 0
  ) {
    return null;
  }

  return account;
}

function add_reseller(db, discord_id, starting_balance_cents, actor_id, current = now_unix()) {
  ensure_collections(db);

  if (!valid_discord_id(discord_id)) {
    throw new reseller_error('A valid Discord user is required.');
  }

  if (!valid_cents(starting_balance_cents)) {
    throw new reseller_error('The starting balance is invalid.');
  }

  const existing = db.resellers[discord_id];

  if (existing?.status === 'active') {
    throw new reseller_error('That Discord user is already a reseller.');
  }

  const before = Number.isSafeInteger(existing?.balance_cents) ? existing.balance_cents : 0;
  const after = before + starting_balance_cents;

  if (after > max_balance_cents) {
    throw new reseller_error('The resulting reseller balance is outside the allowed range.');
  }

  const account = {
    discord_id,
    status: 'active',
    balance_cents: after,
    total_spent_cents: Number.isSafeInteger(existing?.total_spent_cents)
      ? existing.total_spent_cents
      : 0,
    total_keys_generated: Number.isSafeInteger(existing?.total_keys_generated)
      ? existing.total_keys_generated
      : 0,
    created_at: Number.isSafeInteger(existing?.created_at) ? existing.created_at : current,
    created_by: existing?.created_by || actor_id,
    updated_at: current
  };

  db.resellers[discord_id] = account;
  db.reseller_ledger.push({
    id: crypto.randomUUID(),
    reseller_discord_id: discord_id,
    type: existing ? 'account_reactivated' : 'account_created',
    delta_cents: starting_balance_cents,
    balance_before_cents: before,
    balance_after_cents: after,
    actor_discord_id: actor_id,
    reason: existing ? 'Reseller account reactivated' : 'Reseller account created',
    created_at: current
  });

  return account;
}

function adjust_reseller_balance(
  db,
  discord_id,
  action,
  amount_cents,
  actor_id,
  reason,
  current = now_unix()
) {
  const account = reseller_account(db, discord_id);

  if (!account) {
    throw new reseller_error('That Discord user does not have an active reseller account.');
  }

  if (!['add', 'set', 'remove'].includes(action)) {
    throw new reseller_error('Choose add, set, or remove.');
  }

  if (!valid_cents(amount_cents)) {
    throw new reseller_error('The balance amount is invalid.');
  }

  if (action !== 'set' && amount_cents === 0) {
    throw new reseller_error('The balance adjustment must be greater than zero.');
  }

  const before = account.balance_cents;
  let after = amount_cents;

  if (action === 'add') {
    after = before + amount_cents;
  } else if (action === 'remove') {
    after = before - amount_cents;
  }

  if (!valid_cents(after)) {
    throw new reseller_error('The resulting reseller balance is outside the allowed range.');
  }

  account.balance_cents = after;
  account.updated_at = current;
  db.reseller_ledger.push({
    id: crypto.randomUUID(),
    reseller_discord_id: discord_id,
    type: `balance_${action}`,
    delta_cents: after - before,
    balance_before_cents: before,
    balance_after_cents: after,
    actor_discord_id: actor_id,
    reason,
    created_at: current
  });

  return { account, before, after };
}

function quote_order(product_id, quantity) {
  const product = products[product_id];

  if (!product) {
    throw new reseller_error('Choose a valid key duration.');
  }

  if (!Number.isSafeInteger(quantity) || quantity < 1 || quantity > max_order_quantity) {
    throw new reseller_error(`Quantity must be between 1 and ${max_order_quantity}.`);
  }

  const selected_tier = tiers.find((candidate) => quantity >= candidate.minimum);
  const unit_price_cents = selected_tier.prices[product_id];

  return {
    product_id,
    product_label: product.label,
    duration_seconds: product.duration_seconds,
    quantity,
    tier_label: selected_tier.label,
    discount_percent: selected_tier.discount_percent,
    unit_price_cents,
    total_cents: unit_price_cents * quantity
  };
}

function generate_reseller_order(
  db,
  discord_id,
  product_id,
  quantity,
  generate_key,
  current = now_unix()
) {
  const account = reseller_account(db, discord_id);

  if (!account) {
    throw new reseller_error('You do not have an active reseller account.');
  }

  const quote = quote_order(product_id, quantity);

  if (account.balance_cents < quote.total_cents) {
    throw new reseller_error(
      `Insufficient reseller balance. Required ${format_money(quote.total_cents)}; ` +
        `available ${format_money(account.balance_cents)}.`
    );
  }

  const order_id = crypto.randomUUID();
  const keys = [];

  for (let index = 0; index < quantity; index++) {
    let key;

    do {
      key = generate_key();
    } while (db.keys[key]);

    db.keys[key] = {
      duration_seconds: quote.duration_seconds,
      start_unix: null,
      expiry_unix: null,
      hwid: null,
      client_public_key: null,
      created_at: current,
      pause_reasons: [],
      pause_started_at: null,
      reseller_discord_id: discord_id,
      reseller_order_id: order_id,
      reseller_unit_price_cents: quote.unit_price_cents
    };
    keys.push(key);
  }

  const before = account.balance_cents;

  account.balance_cents -= quote.total_cents;
  account.total_spent_cents += quote.total_cents;
  account.total_keys_generated += quantity;
  account.updated_at = current;

  db.reseller_ledger.push({
    id: crypto.randomUUID(),
    reseller_discord_id: discord_id,
    type: 'key_order',
    order_id,
    delta_cents: -quote.total_cents,
    balance_before_cents: before,
    balance_after_cents: account.balance_cents,
    product_id,
    duration_seconds: quote.duration_seconds,
    quantity,
    unit_price_cents: quote.unit_price_cents,
    total_cents: quote.total_cents,
    tier: quote.tier_label,
    discount_percent: quote.discount_percent,
    actor_discord_id: discord_id,
    reason: 'Reseller key order',
    created_at: current
  });

  return { account, keys, order_id, quote };
}

module.exports = {
  max_balance_cents,
  max_order_quantity,
  products,
  reseller_error,
  tiers,
  add_reseller,
  adjust_reseller_balance,
  cents_from_amount,
  format_money,
  generate_reseller_order,
  quote_order,
  reseller_account
};
