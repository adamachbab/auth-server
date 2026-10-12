const crypto = require('crypto');
const express = require('express');
const {
  is_license_paused,
  pause_all,
  pause_license,
  remaining_seconds,
  resume_all,
  resume_license
} = require('../lib/license-state');
const {
  max_order_quantity,
  products,
  reseller_error,
  add_reseller,
  adjust_reseller_balance,
  cents_from_amount,
  format_money,
  generate_reseller_order,
  reseller_account
} = require('../reseller-service');

const pairing_code_length = 12;
const pairing_code_seconds = 15 * 60;
const reset_request_seconds = 7 * 24 * 60 * 60;
const code_alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const ephemeral = 1 << 6;
const ed25519_spki_prefix = Buffer.from('302a300506032b6570032100', 'hex');
const reseller_modal_id = 'reseller:manager:v1';
const discord_id_pattern = /^\d{17,20}$/;

let presence_client = null;

function now_unix() {
  return Math.floor(Date.now() / 1000);
}

function hash(domain, value) {
  return crypto
    .createHash('sha256')
    .update(domain)
    .update('\0')
    .update(value)
    .digest('base64url');
}

function license_digest(key) {
  return hash('auth-discord-license:v1', key);
}

function normalize_code(code) {
  return String(code || '').trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
}

function pairing_digest(code) {
  return hash('auth-discord-pairing:v1', normalize_code(code));
}

function random_characters(length) {
  let value = '';

  for (let index = 0; index < length; index++) {
    value += code_alphabet[crypto.randomInt(code_alphabet.length)];
  }

  return value;
}

function random_code() {
  const value = random_characters(pairing_code_length);

  return `${value.slice(0, 4)}-${value.slice(4, 8)}-${value.slice(8)}`;
}

function random_license_key() {
  const value = random_characters(20);

  return `AUTH-${value.slice(0, 5)}-${value.slice(5, 10)}-${value.slice(10, 15)}-${value.slice(15)}`;
}

function public_request_id() {
  return crypto.randomBytes(6).toString('hex').toUpperCase();
}

function mask_key(key) {
  return key.length <= 8
    ? `${key.slice(0, 2)}…${key.slice(-2)}`
    : `${key.slice(0, 4)}…${key.slice(-4)}`;
}

function format_duration(seconds) {
  if (seconds <= 0) {
    return 'expired';
  }

  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);

  return [
    days && `${days}d`,
    hours && `${hours}h`,
    (!days && minutes) && `${minutes}m`
  ].filter(Boolean).join(' ') || '<1m';
}

function audit(db, actor_id, target, action, reason, previous_value, new_value) {
  if (!Array.isArray(db.audit_events)) {
    db.audit_events = [];
  }

  db.audit_events.push({
    id: crypto.randomUUID(),
    actor_user_id: `discord:${actor_id}`,
    actor_role: 'discord_bot',
    target,
    action,
    reason,
    previous_value,
    new_value,
    created_at: now_unix(),
    request_id: crypto.randomUUID(),
    metadata: { source: 'discord' }
  });
}

function linked_licenses(db, discord_id) {
  return Object.entries(db.keys || {}).filter(([, license]) => license.discord_id === discord_id);
}

function find_license_key(db, digest) {
  return Object.keys(db.keys || {}).find((key) => license_digest(key) === digest) || null;
}

function issue_pairing_code(db, key, current = now_unix()) {
  if (!db.discord_pairing_codes || typeof db.discord_pairing_codes !== 'object') {
    db.discord_pairing_codes = {};
  }

  const digest = license_digest(key);

  for (const [id, record] of Object.entries(db.discord_pairing_codes)) {
    if (
      record.expires_at < current ||
      record.consumed_at ||
      record.license_digest === digest
    ) {
      delete db.discord_pairing_codes[id];
    }
  }

  const license = db.keys?.[key];

  if (
    !license ||
    license.discord_id ||
    !Number.isSafeInteger(license.expiry_unix) ||
    license.expiry_unix <= current
  ) {
    return null;
  }

  let code;
  let code_digest;

  do {
    code = random_code();
    code_digest = pairing_digest(code);
  } while (
    Object.values(db.discord_pairing_codes).some((record) => record.code_digest === code_digest)
  );

  const id = crypto.randomUUID();
  const expires_at = Math.min(license.expiry_unix, current + pairing_code_seconds);

  db.discord_pairing_codes[id] = {
    id,
    code_digest,
    license_digest: digest,
    created_at: current,
    expires_at,
    consumed_at: null,
    discord_id: null
  };

  return { code, expires_in: expires_at - current };
}

function option(interaction, name) {
  return interaction.data?.options?.find((entry) => entry.name === name)?.value;
}

function actor(interaction) {
  return interaction.member?.user || interaction.user || {};
}

function response(content) {
  return {
    type: 4,
    data: {
      content: String(content).slice(0, 1900),
      flags: ephemeral,
      allowed_mentions: { parse: [] }
    }
  };
}

function response_with_file(content, filename, buffer) {
  return {
    ...response(content),
    file: { filename, buffer }
  };
}

function reseller_modal() {
  return {
    type: 9,
    data: {
      custom_id: reseller_modal_id,
      title: 'Reseller Account',
      components: [
        {
          type: 18,
          label: 'Action',
          component: {
            type: 3,
            custom_id: 'reseller_action',
            min_values: 1,
            max_values: 1,
            options: [
              { label: 'View balance and totals', value: 'balance' },
              { label: 'Generate license keys', value: 'generate' }
            ]
          }
        },
        {
          type: 18,
          label: 'Key duration',
          description: 'Required when generating keys',
          component: {
            type: 3,
            custom_id: 'reseller_product',
            min_values: 0,
            max_values: 1,
            options: Object.entries(products).map(([value, product]) => ({
              label: product.label,
              value
            }))
          }
        },
        {
          type: 18,
          label: 'Quantity',
          description: `Required when generating; maximum ${max_order_quantity}`,
          component: {
            type: 4,
            custom_id: 'reseller_quantity',
            style: 1,
            required: false,
            min_length: 1,
            max_length: 4,
            placeholder: '1'
          }
        }
      ]
    }
  };
}

function id_list(value) {
  return new Set(
    String(value || '')
      .split(',')
      .map((entry) => entry.trim())
      .filter(Boolean)
  );
}

function is_admin(interaction) {
  const user_id = actor(interaction).id;

  if (user_id && id_list(process.env.AUTH_DISCORD_ADMIN_USER_IDS).has(user_id)) {
    return true;
  }

  const guild_id = String(process.env.AUTH_DISCORD_GUILD_ID || '').trim();
  const roles = id_list(process.env.AUTH_DISCORD_ADMIN_ROLE_IDS);

  if (!discord_id_pattern.test(guild_id) || !roles.size || interaction.guild_id !== guild_id) {
    return false;
  }

  return (interaction.member?.roles || []).some((role) => roles.has(role));
}

function command_name(interaction) {
  const aliases = {
    'key-status': 'time_left',
    'hwid-reset-request': 'request_hwid_reset',
    'admin-user': 'admin_user',
    'admin-time': 'admin_time',
    'admin-reset-requests': 'admin_reset_requests',
    'admin-reset-review': 'admin_reset_review'
  };

  return aliases[interaction.data?.name] || interaction.data?.name;
}

function status_lines(db, discord_id) {
  return linked_licenses(db, discord_id).map(([key, license]) => {
    const remaining = format_duration(remaining_seconds(license));
    const state = is_license_paused(db, license) ? 'paused' : 'active';
    const binding = license.hwid ? 'bound' : 'not bound';

    return `${mask_key(key)} — ${remaining} remaining — ${state} — HWID ${binding}`;
  });
}

function pair_account(db, code, user) {
  const normalized = normalize_code(code);
  const invalid = { error: 'Pairing code is invalid or expired.' };

  if (!new RegExp(`^[A-Z2-9]{${pairing_code_length}}$`).test(normalized)) {
    return invalid;
  }

  const record = Object.values(db.discord_pairing_codes || {}).find(
    (entry) => entry.code_digest === pairing_digest(normalized)
  );

  if (!record || record.consumed_at || record.expires_at < now_unix()) {
    return invalid;
  }

  const key = find_license_key(db, record.license_digest);

  if (!key) {
    return invalid;
  }

  const license = db.keys[key];

  if (license.discord_id && license.discord_id !== user.id) {
    return { error: 'License is already linked to another Discord account.' };
  }

  license.discord_id = user.id;
  record.consumed_at = now_unix();
  record.discord_id = user.id;

  audit(
    db,
    user.id,
    `license:${record.license_digest}`,
    'discord.pair',
    'User completed one-time pairing',
    null,
    { discord_id: user.id }
  );

  return { key };
}

function command_definitions() {
  const string = 3;
  const integer = 4;
  const user = 6;
  const number = 10;
  const key_option = {
    type: string,
    name: 'key',
    description: 'License key',
    required: true,
    min_length: 8,
    max_length: 256
  };
  const user_option = {
    type: user,
    name: 'user',
    description: 'Discord user',
    required: true
  };
  const pair_code = {
    type: string,
    name: 'code',
    description: 'Pairing code shown by the client',
    required: true,
    min_length: 12,
    max_length: 14
  };
  const audit_reason = {
    type: string,
    name: 'reason',
    description: 'Audit reason',
    required: true,
    min_length: 3,
    max_length: 300
  };

  return [
    {
      name: 'generate',
      description: 'Generate a new license key',
      options: [
        {
          type: integer,
          name: 'length',
          description: 'Subscription length',
          required: true,
          min_value: 1,
          max_value: 87600
        },
        {
          type: string,
          name: 'unit',
          description: 'Time unit',
          required: true,
          choices: [
            { name: 'Hours', value: 'hours' },
            { name: 'Days', value: 'days' },
            { name: 'Weeks', value: 'weeks' }
          ]
        }
      ]
    },
    { name: 'list', description: 'List license keys' },
    {
      name: 'add_reseller',
      description: 'Create a reseller account',
      options: [
        user_option,
        {
          type: number,
          name: 'starting_balance',
          description: 'Starting balance in USD',
          required: false,
          min_value: 0,
          max_value: 1000000
        }
      ]
    },
    {
      name: 'reseller_balance',
      description: 'Add, set, or remove reseller balance',
      options: [
        user_option,
        {
          type: string,
          name: 'action',
          description: 'Balance operation',
          required: true,
          choices: [
            { name: 'Add', value: 'add' },
            { name: 'Set', value: 'set' },
            { name: 'Remove', value: 'remove' }
          ]
        },
        {
          type: number,
          name: 'amount',
          description: 'Amount in USD',
          required: true,
          min_value: 0,
          max_value: 1000000
        },
        { ...audit_reason }
      ]
    },
    { name: 'reseller', description: 'Open your reseller account manager' },
    {
      name: 'reset_user',
      description: 'Reset every HWID linked to a Discord user',
      options: [
        { type: user, name: 'discord_user', description: 'Discord user', required: true }
      ]
    },
    { name: 'reset_key', description: 'Reset one key’s HWID', options: [key_option] },
    { name: 'pause_keys', description: 'Freeze all subscriptions' },
    { name: 'resume_keys', description: 'Resume all globally frozen subscriptions' },
    { name: 'pause_key', description: 'Freeze one key', options: [key_option] },
    {
      name: 'resume_key',
      description: 'Resume one administrator-frozen key',
      options: [key_option]
    },
    {
      name: 'pause_user',
      description: 'Freeze every key linked to a Discord user',
      options: [user_option]
    },
    {
      name: 'resume_user',
      description: 'Resume administrator-frozen keys for a Discord user',
      options: [user_option]
    },
    {
      name: 'link',
      description: 'Link your Discord using the code shown by the client',
      options: [pair_code]
    },
    {
      name: 'pair',
      description: 'Link your Discord using the code shown by the client',
      options: [pair_code]
    },
    {
      name: 'request_hwid_reset',
      description: 'Request an administrator-approved HWID reset',
      options: [
        {
          type: string,
          name: 'reason',
          description: 'Optional reason',
          required: false,
          max_length: 300
        }
      ]
    },
    {
      name: 'time_left',
      description: 'Show your linked keys and remaining subscription time'
    },
    { name: 'pause_subscription', description: 'Freeze your subscription time' },
    {
      name: 'unpause_subscription',
      description: 'Resume your self-frozen subscription time'
    },
    {
      name: 'admin_user',
      description: 'Show a Discord user’s license status',
      options: [user_option]
    },
    {
      name: 'admin_time',
      description: 'Add or remove subscription days',
      options: [
        user_option,
        {
          type: integer,
          name: 'days',
          description: 'Positive or negative days',
          required: true,
          min_value: -3650,
          max_value: 3650
        },
        { ...audit_reason }
      ]
    },
    { name: 'admin_reset_requests', description: 'List pending HWID reset requests' },
    {
      name: 'admin_reset_review',
      description: 'Approve or deny an HWID reset request',
      options: [
        { type: string, name: 'request', description: 'Request ID', required: true },
        {
          type: string,
          name: 'decision',
          description: 'Decision',
          required: true,
          choices: [
            { name: 'Approve', value: 'approve' },
            { name: 'Deny', value: 'deny' }
          ]
        },
        { ...audit_reason }
      ]
    }
  ].map((command) => ({
    ...command,
    integration_types: [0, 1],
    contexts: [0, 1, 2]
  }));
}

function reset_binding(license) {
  if (!license.hwid && !license.client_public_key) {
    return false;
  }

  license.hwid = null;
  license.client_public_key = null;
  return true;
}

function user_message(error) {
  return error instanceof reseller_error
    ? error.message
    : 'The command could not be completed.';
}

function handle_command(interaction, { store }) {
  const user = actor(interaction);

  if (!discord_id_pattern.test(user.id || '')) {
    return response('Discord identity was unavailable.');
  }

  const command = command_name(interaction);

  if (command === 'reseller') {
    return reseller_account(store.read(), user.id)
      ? reseller_modal()
      : response('You do not have an active reseller account.');
  }

  if (command === 'pair' || command === 'link') {
    let outcome;

    store.transaction((db) => {
      outcome = pair_account(db, option(interaction, 'code'), user);
    });

    return outcome.error
      ? response(outcome.error)
      : response(`Linked license ${mask_key(outcome.key)} to your Discord account.`);
  }

  if (command === 'time_left' || command === 'admin_user') {
    if (command === 'admin_user' && !is_admin(interaction)) {
      return response('Administrator permission is required.');
    }

    const discord_id = command === 'admin_user' ? String(option(interaction, 'user')) : user.id;
    const lines = status_lines(store.read(), discord_id);

    return response(lines.length ? lines.join('\n') : 'No license is linked to that Discord account.');
  }

  if (command === 'request_hwid_reset') {
    const reason = String(
      option(interaction, 'reason') || 'User requested an HWID reset through Discord'
    ).trim();

    if (reason.length > 300) {
      return response('The reason must be 300 characters or fewer.');
    }

    let request_id = null;

    store.transaction((db) => {
      if (!linked_licenses(db, user.id).length) {
        return;
      }

      if (!db.hwid_reset_requests || typeof db.hwid_reset_requests !== 'object') {
        db.hwid_reset_requests = {};
      }

      const existing = Object.values(db.hwid_reset_requests).find((entry) =>
        entry.discord_id === user.id &&
        entry.status === 'pending' &&
        entry.expires_at > now_unix()
      );

      if (existing) {
        request_id = existing.id;
        return;
      }

      do {
        request_id = public_request_id();
      } while (db.hwid_reset_requests[request_id]);

      db.hwid_reset_requests[request_id] = {
        id: request_id,
        discord_id: user.id,
        reason,
        status: 'pending',
        created_at: now_unix(),
        expires_at: now_unix() + reset_request_seconds,
        reviewed_at: null,
        reviewed_by: null,
        review_reason: null
      };

      audit(
        db,
        user.id,
        `discord:${user.id}`,
        'hwid_reset.request',
        reason,
        null,
        { request_id }
      );
    });

    return request_id
      ? response(`HWID reset request submitted. Request ID: ${request_id}`)
      : response('Link a license before requesting an HWID reset.');
  }

  if (command === 'pause_subscription' || command === 'unpause_subscription') {
    const pausing = command === 'pause_subscription';
    let linked = 0;
    let changed = 0;

    store.transaction((db) => {
      const licenses = linked_licenses(db, user.id);

      linked = licenses.length;

      for (const [, license] of licenses) {
        const applied = pausing
          ? pause_license(license, 'user-self')
          : resume_license(license, 'user-self');

        if (applied) {
          changed += 1;
        }
      }

      if (changed) {
        audit(
          db,
          user.id,
          `discord:${user.id}`,
          `subscription.${pausing ? 'pause' : 'resume'}`,
          'User self-service command',
          null,
          { licenses: changed }
        );
      }
    });

    if (!linked) {
      return response('Link a license before managing your subscription.');
    }

    if (!changed) {
      return response(
        pausing
          ? 'Your subscription is already paused.'
          : 'Your subscription was not self-paused. An administrator or global pause may still apply.'
      );
    }

    return response(
      pausing
        ? `Paused ${changed} subscription(s). Time will not decrease.`
        : `Resumed ${changed} subscription(s).`
    );
  }

  if (!is_admin(interaction)) {
    return response('Administrator permission is required.');
  }

  if (command === 'list') {
    const database = store.read();
    const licenses = Object.entries(database.keys || {});
    const lines = licenses.slice(0, 40).map(([key, license]) => {
      const remaining = format_duration(remaining_seconds(license));
      const state = is_license_paused(database, license) ? 'paused' : 'active';

      return `${mask_key(key)} — ${remaining} — ${state}`;
    });

    if (licenses.length > 40) {
      lines.push(`…and ${licenses.length - 40} more.`);
    }

    return response(
      lines.length
        ? `**License keys (${licenses.length})**\n${lines.join('\n')}`
        : 'No license keys exist.'
    );
  }

  if (command === 'add_reseller') {
    const discord_id = String(option(interaction, 'user') || '');
    const starting_balance_cents = cents_from_amount(option(interaction, 'starting_balance') ?? 0);

    if (starting_balance_cents === null) {
      return response(
        'Starting balance must be a USD amount with no more than two decimal places.'
      );
    }

    try {
      let account;

      store.transaction((db) => {
        account = add_reseller(db, discord_id, starting_balance_cents, user.id);
        audit(
          db,
          user.id,
          `reseller:${discord_id}`,
          'reseller.create',
          'Discord administrator command',
          null,
          { balance_cents: account.balance_cents }
        );
      });

      return response(
        `Created reseller account for <@${discord_id}> with ` +
        `${format_money(account.balance_cents)} balance.`
      );
    } catch (error) {
      return response(user_message(error));
    }
  }

  if (command === 'reseller_balance') {
    const discord_id = String(option(interaction, 'user') || '');
    const action = String(option(interaction, 'action') || '');
    const amount_cents = cents_from_amount(option(interaction, 'amount'));
    const reason = String(option(interaction, 'reason') || '').trim();

    if (amount_cents === null || reason.length < 3 || reason.length > 300) {
      return response(
        'Amount must be valid USD with at most two decimal places, and an audit reason is required.'
      );
    }

    try {
      let result;

      store.transaction((db) => {
        result = adjust_reseller_balance(db, discord_id, action, amount_cents, user.id, reason);
        audit(
          db,
          user.id,
          `reseller:${discord_id}`,
          `reseller.balance.${action}`,
          reason,
          { balance_cents: result.before },
          { balance_cents: result.after }
        );
      });

      let verb = 'Removed from';

      if (action === 'set') {
        verb = 'Set';
      } else if (action === 'add') {
        verb = 'Added to';
      }

      return response(
        `${verb} <@${discord_id}> reseller balance. New balance: ${format_money(result.after)}.`
      );
    } catch (error) {
      return response(user_message(error));
    }
  }

  if (command === 'generate') {
    const length = Number(option(interaction, 'length'));
    const unit = option(interaction, 'unit');
    const multiplier = { hours: 3600, days: 86400, weeks: 604800 }[unit];
    const duration = length * multiplier;

    if (
      !Number.isSafeInteger(length) ||
      length < 1 ||
      !multiplier ||
      !Number.isSafeInteger(duration) ||
      duration > 10 * 365 * 86400
    ) {
      return response('Choose a duration between one hour and ten years.');
    }

    let key;

    store.transaction((db) => {
      do {
        key = random_license_key();
      } while (db.keys[key]);

      db.keys[key] = {
        duration_seconds: duration,
        start_unix: null,
        expiry_unix: null,
        hwid: null,
        client_public_key: null,
        created_at: now_unix(),
        pause_reasons: [],
        pause_started_at: null
      };

      if (db.service_state?.keys_paused) {
        pause_license(db.keys[key], 'global');
      }

      audit(
        db,
        user.id,
        `license:${license_digest(key)}`,
        'license.create',
        `Generated for ${length} ${unit}`,
        null,
        { duration_seconds: duration }
      );
    });

    return response(`Generated ${length} ${unit}:\n\`${key}\``);
  }

  if (command === 'reset_key' || command === 'pause_key' || command === 'resume_key') {
    const key = String(option(interaction, 'key') || '').trim();
    let outcome = 'License key was not found.';

    store.transaction((db) => {
      const license = db.keys?.[key];

      if (!license) {
        return;
      }

      let changed = false;

      if (command === 'reset_key') {
        changed = reset_binding(license);
        outcome = changed
          ? `Reset device binding for ${mask_key(key)}.`
          : `${mask_key(key)} has no device binding.`;
      }

      if (command === 'pause_key') {
        changed = pause_license(license, 'key-admin');
        outcome = changed
          ? `Paused ${mask_key(key)}.`
          : `${mask_key(key)} is already administrator-paused.`;
      }

      if (command === 'resume_key') {
        changed = resume_license(license, 'key-admin');
        outcome = changed
          ? `Resumed ${mask_key(key)}.`
          : `${mask_key(key)} is not administrator-paused.`;
      }

      audit(
        db,
        user.id,
        `license:${license_digest(key)}`,
        command,
        'Discord administrator command',
        null,
        { changed }
      );
    });

    return response(outcome);
  }

  if (command === 'reset_user' || command === 'pause_user' || command === 'resume_user') {
    const option_name = command === 'reset_user' ? 'discord_user' : 'user';
    const discord_id = String(option(interaction, option_name) || '');

    if (!discord_id_pattern.test(discord_id)) {
      return response('A valid Discord user is required.');
    }

    let linked = 0;
    let changed = 0;

    store.transaction((db) => {
      const licenses = linked_licenses(db, discord_id);

      linked = licenses.length;

      for (const [, license] of licenses) {
        if (command === 'reset_user' && reset_binding(license)) {
          changed += 1;
        }

        if (command === 'pause_user' && pause_license(license, `user-admin:${discord_id}`)) {
          changed += 1;
        }

        if (command === 'resume_user' && resume_license(license, `user-admin:${discord_id}`)) {
          changed += 1;
        }
      }

      if (linked) {
        audit(
          db,
          user.id,
          `discord:${discord_id}`,
          command,
          'Discord administrator command',
          null,
          { licenses: changed }
        );
      }
    });

    return response(
      linked
        ? `${command.replaceAll('_', ' ')}: changed ${changed} of ${linked} linked license(s).`
        : 'No license is linked to that Discord account.'
    );
  }

  if (command === 'pause_keys' || command === 'resume_keys') {
    let changed = 0;

    store.transaction((db) => {
      changed = command === 'pause_keys' ? pause_all(db) : resume_all(db);
      audit(
        db,
        user.id,
        'licenses:all',
        command,
        'Discord administrator command',
        null,
        { licenses: changed }
      );
    });

    return response(
      command === 'pause_keys'
        ? `Global freeze enabled for ${changed} key(s).`
        : `Global freeze removed; resumed ${changed} key(s).`
    );
  }

  if (command === 'admin_time') {
    const discord_id = String(option(interaction, 'user'));
    const days = Number(option(interaction, 'days'));
    const reason = String(option(interaction, 'reason') || '').trim();

    if (
      !discord_id_pattern.test(discord_id) ||
      !Number.isSafeInteger(days) ||
      days === 0 ||
      Math.abs(days) > 3650 ||
      reason.length < 3 ||
      reason.length > 300
    ) {
      return response(
        'A Discord user, non-zero adjustment within 3650 days, and audit reason are required.'
      );
    }

    let changed = 0;
    let latest = 0;

    store.transaction((db) => {
      if (!Array.isArray(db.subscription_ledger)) {
        db.subscription_ledger = [];
      }

      const current = now_unix();

      for (const [, license] of linked_licenses(db, discord_id)) {
        const active = Number.isSafeInteger(license.start_unix) &&
          Number.isSafeInteger(license.expiry_unix);
        const previous = active ? license.expiry_unix : null;
        let next = null;

        if (active) {
          next = Math.max(current, license.expiry_unix + days * 86400);
          license.expiry_unix = next;
          latest = Math.max(latest, next);
        } else {
          const old_duration = Number.isSafeInteger(license.duration_seconds)
            ? license.duration_seconds
            : 2592000;

          license.duration_seconds = Math.max(60, old_duration + days * 86400);
          latest = Math.max(latest, current + license.duration_seconds);
        }

        changed += 1;

        db.subscription_ledger.push({
          id: crypto.randomUUID(),
          discord_id,
          seconds: days * 86400,
          previous,
          expiry: next,
          reason,
          actor_discord_id: user.id,
          created_at: current
        });
      }

      if (changed) {
        audit(
          db,
          user.id,
          `discord:${discord_id}`,
          'subscription.adjust',
          reason,
          null,
          { days, licenses: changed, expiry: latest }
        );
      }
    });

    return response(
      changed
        ? `Updated ${changed} license(s). New maximum expiry: <t:${latest}:F>.`
        : 'No license is linked to that Discord account.'
    );
  }

  if (command === 'admin_reset_requests') {
    const pending = Object.values(store.read().hwid_reset_requests || {})
      .filter((entry) => entry.status === 'pending' && entry.expires_at > now_unix())
      .slice(0, 20);

    return response(
      pending.length
        ? pending
          .map((entry) => `${entry.id} — <@${entry.discord_id}> — ${entry.reason}`)
          .join('\n')
        : 'There are no pending HWID reset requests.'
    );
  }

  if (command === 'admin_reset_review') {
    const request_id = String(option(interaction, 'request') || '').trim().toUpperCase();
    const decision = option(interaction, 'decision');
    const review_reason = String(option(interaction, 'reason') || '').trim();

    if (
      !['approve', 'deny'].includes(decision) ||
      review_reason.length < 3 ||
      review_reason.length > 300
    ) {
      return response('A valid decision and audit reason are required.');
    }

    let outcome = 'Reset request was not found or is no longer pending.';

    store.transaction((db) => {
      const request = db.hwid_reset_requests?.[request_id];

      if (!request || request.status !== 'pending' || request.expires_at < now_unix()) {
        return;
      }

      let reset_count = 0;

      if (decision === 'approve') {
        for (const [, license] of linked_licenses(db, request.discord_id)) {
          if (reset_binding(license)) {
            reset_count += 1;
          }
        }
      }

      request.status = decision === 'approve' ? 'approved' : 'denied';
      request.reviewed_at = now_unix();
      request.reviewed_by = user.id;
      request.review_reason = review_reason;

      audit(
        db,
        user.id,
        `discord:${request.discord_id}`,
        `hwid_reset.${request.status}`,
        review_reason,
        { request_id },
        { reset_count }
      );

      outcome = decision === 'approve'
        ? `Approved ${request_id}; reset ${reset_count} HWID binding(s).`
        : `Denied ${request_id}.`;
    });

    return response(outcome);
  }

  return response('Unknown command.');
}

function modal_component(data, custom_id) {
  const pending = [...(data?.components || [])];

  while (pending.length) {
    const component = pending.shift();

    if (component?.custom_id === custom_id) {
      return component;
    }

    if (component?.component) {
      pending.push(component.component);
    }

    if (Array.isArray(component?.components)) {
      pending.push(...component.components);
    }
  }

  return null;
}

async function handle_reseller_modal(interaction, { store }) {
  const user = actor(interaction);

  if (!discord_id_pattern.test(user.id || '')) {
    return response('Discord identity was unavailable.');
  }

  const action = modal_component(interaction.data, 'reseller_action')?.values?.[0];

  if (action === 'balance') {
    const account = reseller_account(store.read(), user.id);

    if (!account) {
      return response('You do not have an active reseller account.');
    }

    return response([
      '**Reseller account**',
      `Balance: **${format_money(account.balance_cents)}**`,
      `Lifetime spend: ${format_money(account.total_spent_cents)}`,
      `Keys generated: ${account.total_keys_generated}`
    ].join('\n'));
  }

  if (action !== 'generate') {
    return response('Choose a valid reseller action.');
  }

  const product_id = modal_component(interaction.data, 'reseller_product')?.values?.[0];
  const quantity_text = String(
    modal_component(interaction.data, 'reseller_quantity')?.value || ''
  ).trim();
  const quantity = /^[1-9]\d{0,3}$/.test(quantity_text) ? Number(quantity_text) : 0;

  try {
    let order;

    store.transaction((db) => {
      order = generate_reseller_order(db, user.id, product_id, quantity, random_license_key);

      if (db.service_state?.keys_paused) {
        for (const key of order.keys) {
          pause_license(db.keys[key], 'global');
        }
      }

      audit(
        db,
        user.id,
        `reseller-order:${order.order_id}`,
        'reseller.keys.generate',
        'Reseller self-service order',
        null,
        {
          quantity: order.quote.quantity,
          duration_seconds: order.quote.duration_seconds,
          unit_price_cents: order.quote.unit_price_cents,
          total_cents: order.quote.total_cents,
          balance_cents: order.account.balance_cents
        }
      );
    });

    const quote = order.quote;
    const key_file = Buffer.from([
      `Reseller order: ${order.order_id}`,
      `Product: ${quote.product_label}`,
      `Quantity: ${quote.quantity}`,
      `Tier: ${quote.tier_label} (${quote.discount_percent}% discount)`,
      `Unit price: ${format_money(quote.unit_price_cents)}`,
      `Total: ${format_money(quote.total_cents)}`,
      '',
      ...order.keys
    ].join('\n'), 'utf8');
    const summary = `Generated **${quote.quantity} × ${quote.product_label}** keys at ` +
      `${format_money(quote.unit_price_cents)} each (${format_money(quote.total_cents)} total). ` +
      `Remaining balance: **${format_money(order.account.balance_cents)}**. ` +
      'Your keys are attached.';

    return response_with_file(
      summary,
      `reseller-${order.order_id.slice(0, 8)}.txt`,
      key_file
    );
  } catch (error) {
    if (!(error instanceof reseller_error)) {
      console.error('[DISCORD] Reseller order failed:', error.message);
    }

    return response(user_message(error));
  }
}

async function update_deferred_response(interaction, payload, fetch_impl = fetch) {
  const app_id = String(interaction.application_id || '').trim();
  const token = String(interaction.token || '').trim();

  if (!discord_id_pattern.test(app_id) || !token) {
    throw new Error('Interaction webhook credentials were unavailable');
  }

  const url = `https://discord.com/api/v10/webhooks/${app_id}/${token}/messages/@original`;
  let request;

  if (payload.file) {
    const form = new FormData();

    form.set('payload_json', JSON.stringify({
      ...payload.data,
      attachments: [{ id: 0, filename: payload.file.filename }]
    }));
    form.set(
      'files[0]',
      new Blob([payload.file.buffer], { type: 'text/plain' }),
      payload.file.filename
    );

    request = { method: 'PATCH', body: form };
  } else {
    request = {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload.data)
    };
  }

  const result = await fetch_impl(url, request);

  if (!result.ok) {
    throw new Error(`Interaction webhook update failed with HTTP ${result.status}`);
  }
}

function verify_interaction(req) {
  const public_key_hex = String(process.env.AUTH_DISCORD_PUBLIC_KEY || '').trim();
  const signature_hex = String(req.get('x-signature-ed25519') || '');
  const timestamp = String(req.get('x-signature-timestamp') || '');

  if (
    !/^[a-f0-9]{64}$/i.test(public_key_hex) ||
    !/^[a-f0-9]{128}$/i.test(signature_hex) ||
    !/^\d+$/.test(timestamp)
  ) {
    return false;
  }

  if (Math.abs(Date.now() / 1000 - Number(timestamp)) > 300) {
    return false;
  }

  try {
    const key = crypto.createPublicKey({
      key: Buffer.concat([ed25519_spki_prefix, Buffer.from(public_key_hex, 'hex')]),
      format: 'der',
      type: 'spki'
    });

    return crypto.verify(
      null,
      Buffer.concat([Buffer.from(timestamp), req.body]),
      key,
      Buffer.from(signature_hex, 'hex')
    );
  } catch {
    return false;
  }
}

function mount_discord_bot(app, options) {
  const raw_body = express.raw({ type: 'application/json', limit: '64kb' });

  app.post('/api/discord/interactions', raw_body, (req, res) => {
    if (!verify_interaction(req)) {
      console.warn('[DISCORD] Rejected interaction: signature verification failed.');
      return res.status(401).send('invalid request signature');
    }

    let interaction;

    try {
      interaction = JSON.parse(req.body.toString('utf8'));
    } catch {
      return res.status(400).send('invalid JSON');
    }

    if (interaction.type === 1) {
      return res.json({ type: 1 });
    }

    if (interaction.type === 5 && interaction.data?.custom_id === reseller_modal_id) {
      res.json({ type: 5, data: { flags: ephemeral } });

      handle_reseller_modal(interaction, options)
        .then((payload) => update_deferred_response(interaction, payload, options.fetch_impl))
        .catch((error) => {
          console.error('[DISCORD] Reseller manager response failed:', error.message);
        });

      return;
    }

    if (interaction.type !== 2) {
      return res.json(response('Unsupported interaction.'));
    }

    const name = command_name(interaction) || 'unknown';

    try {
      return res.json(handle_command(interaction, options));
    } catch (error) {
      console.error(`[DISCORD] /${name} failed:`, error.message);
      return res.json(response('The command could not be completed.'));
    }
  });
}

async function start_discord_presence() {
  const token = String(process.env.AUTH_DISCORD_BOT_TOKEN || '').trim();

  if (!token) {
    console.log(
      '[DISCORD] Gateway presence disabled; configure DISCORD_BOT_TOKEN in .env to enable it.'
    );
    return null;
  }

  if (presence_client) {
    return presence_client;
  }

  const { ActivityType, Client } = require('discord.js');
  const client = new Client({
    intents: [],
    presence: {
      status: 'online',
      activities: [{ name: 'license management', type: ActivityType.Watching }]
    }
  });

  client.once('ready', (ready_client) => {
    console.log(`[DISCORD] Gateway online as ${ready_client.user.tag}.`);
  });

  client.on('error', (error) => {
    console.error('[DISCORD] Gateway error:', error.message);
  });

  client.on('warn', (message) => {
    console.warn('[DISCORD] Gateway warning:', message);
  });

  presence_client = client;

  try {
    await client.login(token);
    return client;
  } catch (error) {
    presence_client = null;
    client.destroy();
    throw new Error(`Gateway login failed: ${error.message}`);
  }
}

function expected_interactions_url() {
  const base = String(process.env.AUTH_PUBLIC_URL || '').trim().replace(/\/$/, '');

  return base
    ? `${base}/api/discord/interactions`
    : 'https://<AUTH_PUBLIC_URL>/api/discord/interactions';
}

function validate_discord_application_configuration(
  application,
  configured_app_id,
  configured_public_key
) {
  if (application?.id !== configured_app_id) {
    throw new Error('DISCORD_CLIENT_ID does not belong to the configured DISCORD_BOT_TOKEN.');
  }

  if (!/^[a-f0-9]{64}$/i.test(configured_public_key)) {
    throw new Error(
      'DISCORD_PUBLIC_KEY must be the 64-character Public Key from Discord General Information.'
    );
  }

  if (
    String(application.verify_key || '').toLowerCase() !== configured_public_key.toLowerCase()
  ) {
    throw new Error(
      'DISCORD_PUBLIC_KEY does not belong to the same Discord application as DISCORD_BOT_TOKEN.'
    );
  }

  let endpoint;

  try {
    endpoint = new URL(application.interactions_endpoint_url);
  } catch {
    throw new Error(
      `Set the Discord Interactions Endpoint URL to ${expected_interactions_url()}.`
    );
  }

  if (
    endpoint.protocol !== 'https:' ||
    endpoint.pathname.replace(/\/$/, '') !== '/api/discord/interactions'
  ) {
    throw new Error(
      `Discord has the wrong Interactions Endpoint URL; use ${expected_interactions_url()}.`
    );
  }
}

async function register_discord_commands() {
  const token = String(process.env.AUTH_DISCORD_BOT_TOKEN || '').trim();
  const app_id = String(process.env.AUTH_DISCORD_APP_ID || '').trim();
  const public_key = String(process.env.AUTH_DISCORD_PUBLIC_KEY || '').trim();

  if (!token || !discord_id_pattern.test(app_id)) {
    console.log(
      '[DISCORD] Bot command registration disabled; ' +
      'configure the server-side bot credentials to enable it.'
    );
    return false;
  }

  const application_result = await fetch(
    'https://discord.com/api/v10/oauth2/applications/@me',
    { headers: { Authorization: `Bot ${token}` } }
  );

  if (!application_result.ok) {
    throw new Error(`Discord credential preflight failed with HTTP ${application_result.status}`);
  }

  const application = await application_result.json();

  validate_discord_application_configuration(application, app_id, public_key);

  const result = await fetch(`https://discord.com/api/v10/applications/${app_id}/commands`, {
    method: 'PUT',
    headers: {
      Authorization: `Bot ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(command_definitions())
  });

  if (!result.ok) {
    throw new Error(`Discord command registration failed with HTTP ${result.status}`);
  }

  console.log(`[DISCORD] Registered ${command_definitions().length} global commands.`);
  return true;
}

module.exports = {
  command_definitions,
  handle_command,
  handle_reseller_modal,
  is_admin,
  issue_pairing_code,
  reseller_modal,
  mount_discord_bot,
  register_discord_commands,
  start_discord_presence,
  update_deferred_response,
  validate_discord_application_configuration,
  verify_interaction
};
