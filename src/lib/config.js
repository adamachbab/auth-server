const fs = require('fs');
const path = require('path');

const aliases = Object.freeze({
  DISCORD_BOT_TOKEN: 'AUTH_DISCORD_BOT_TOKEN',
  DISCORD_CLIENT_ID: 'AUTH_DISCORD_APP_ID',
  DISCORD_PUBLIC_KEY: 'AUTH_DISCORD_PUBLIC_KEY',
  DISCORD_GUILD_ID: 'AUTH_DISCORD_GUILD_ID',
  DISCORD_ADMIN_ROLE_IDS: 'AUTH_DISCORD_ADMIN_ROLE_IDS',
  DISCORD_ADMIN_USER_IDS: 'AUTH_DISCORD_ADMIN_USER_IDS'
});

function parse_value(raw) {
  const value = raw.trim();

  if (!value) {
    return '';
  }

  if (value.startsWith('"') && value.endsWith('"')) {
    return value
      .slice(1, -1)
      .replace(/\\n/g, '\n')
      .replace(/\\r/g, '\r')
      .replace(/\\t/g, '\t')
      .replace(/\\"/g, '"')
      .replace(/\\\\/g, '\\');
  }

  if (value.startsWith("'") && value.endsWith("'")) {
    return value.slice(1, -1);
  }

  return value.replace(/\s+#.*$/, '').trim();
}

function parse_env(text) {
  const values = {};

  for (const raw_line of String(text).split(/\r?\n/)) {
    const line = raw_line.trim();

    if (!line || line.startsWith('#')) {
      continue;
    }

    const match = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);

    if (match) {
      values[match[1]] = parse_value(match[2]);
    }
  }

  return values;
}

function load_configuration(filename = path.join(__dirname, '..', '..', '.env')) {
  if (fs.existsSync(filename)) {
    const values = parse_env(fs.readFileSync(filename, 'utf8'));

    for (const [name, value] of Object.entries(values)) {
      if (process.env[name] === undefined) {
        process.env[name] = value;
      }
    }
  }

  for (const [friendly, internal] of Object.entries(aliases)) {
    if (process.env[internal] === undefined && process.env[friendly] !== undefined) {
      process.env[internal] = process.env[friendly];
    }
  }

  return process.env;
}

module.exports = {
  aliases,
  load_configuration,
  parse_env
};
