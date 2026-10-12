const https = require('https');

const max_discord_response_bytes = 256 * 1024;

class discord_api_error extends Error {
  constructor(kind, retry_after_seconds) {
    super(kind);
    this.kind = kind;
    this.retry_after_seconds = retry_after_seconds;
  }
}

function retry_after_seconds(headers) {
  const raw = headers['retry-after'] || headers['x-ratelimit-reset-after'];
  const parsed = Number(raw);

  return Number.isFinite(parsed) && parsed > 0 ? Math.ceil(parsed) : 1;
}

function discord_get(path, config) {
  return new Promise((resolve, reject) => {
    const request = https.request({
      protocol: 'https:',
      hostname: 'discord.com',
      port: 443,
      method: 'GET',
      path,
      headers: {
        Authorization: `Bot ${config.bot_token}`,
        Accept: 'application/json',
        'User-Agent': 'auth-server-discord-member-info/2'
      }
    }, (response) => {
      const chunks = [];
      let length = 0;

      response.on('data', (chunk) => {
        length += chunk.length;

        if (length > max_discord_response_bytes) {
          request.destroy(new Error('Discord response exceeded maximum size'));
          return;
        }

        chunks.push(chunk);
      });

      response.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let body = null;

        if (text) {
          try {
            body = JSON.parse(text);
          } catch {
            return reject(new discord_api_error('malformed_response'));
          }
        }

        resolve({
          status: response.statusCode,
          headers: response.headers,
          body
        });
      });
    });

    request.setTimeout(config.api_timeout_ms, () => {
      request.destroy(new Error('Discord request timed out'));
    });

    request.on('error', (error) => {
      const kind = error.message === 'Discord request timed out' ? 'timeout' : 'network';

      reject(new discord_api_error(kind));
    });

    request.end();
  });
}

function is_snowflake(value) {
  return typeof value === 'string' && /^[0-9]{17,20}$/.test(value);
}

function is_nullable_string(value) {
  return value === null || value === undefined || typeof value === 'string';
}

function default_avatar_url(discord_id) {
  const index = (BigInt(discord_id) >> 22n) % 6n;

  return `https://cdn.discordapp.com/embed/avatars/${index}.png?size=256`;
}

function profile_picture_url(guild_id, user, member) {
  if (typeof member.avatar === 'string' && member.avatar) {
    return `https://cdn.discordapp.com/guilds/${guild_id}/users/${user.id}` +
      `/avatars/${member.avatar}.webp?size=256`;
  }

  if (typeof user.avatar === 'string' && user.avatar) {
    return `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.webp?size=256`;
  }

  return default_avatar_url(user.id);
}

function validate_role(role) {
  return role &&
    typeof role === 'object' &&
    !Array.isArray(role) &&
    is_snowflake(role.id) &&
    typeof role.name === 'string' &&
    Number.isSafeInteger(role.position) &&
    Number.isSafeInteger(role.color) &&
    typeof role.hoist === 'boolean' &&
    typeof role.managed === 'boolean' &&
    typeof role.mentionable === 'boolean';
}

function role_id_descending(left, right) {
  const left_id = BigInt(left.id);
  const right_id = BigInt(right.id);

  if (left_id === right_id) {
    return 0;
  }

  return left_id > right_id ? -1 : 1;
}

function to_public_role(role) {
  return {
    id: role.id,
    name: role.name,
    position: role.position,
    color: role.color,
    hoist: role.hoist,
    managed: role.managed,
    mentionable: role.mentionable
  };
}

class discord_member_service {
  constructor(options = {}) {
    this.fetch_discord = options.fetch_discord || discord_get;
    this.now = options.now || (() => Date.now());
    this.role_cache = null;
  }

  async get_roles(config) {
    const now = this.now();

    if (
      this.role_cache &&
      this.role_cache.guild_id === config.guild_id &&
      this.role_cache.expires_at > now
    ) {
      return this.role_cache.roles;
    }

    const response = await this.fetch_discord(`/api/v10/guilds/${config.guild_id}/roles`, config);

    if (response.status === 429) {
      throw new discord_api_error('rate_limited', retry_after_seconds(response.headers || {}));
    }

    if (
      response.status < 200 ||
      response.status >= 300 ||
      !Array.isArray(response.body) ||
      !response.body.every(validate_role)
    ) {
      throw new discord_api_error('roles_unavailable');
    }

    const roles = response.body.map(to_public_role);

    this.role_cache = {
      guild_id: config.guild_id,
      roles,
      expires_at: now + config.role_cache_ms
    };

    return roles;
  }

  async get_member_profile(config, discord_id) {
    const response = await this.fetch_discord(
      `/api/v10/guilds/${config.guild_id}/members/${discord_id}`,
      config
    );

    if (response.status === 429) {
      throw new discord_api_error('rate_limited', retry_after_seconds(response.headers || {}));
    }

    if (response.status === 404 && response.body && response.body.code === 10007) {
      return {
        member: false,
        discord_id,
        pfp_url: null,
        username: null,
        display_name: null,
        global_display_name: null,
        roles: [],
        highest_role: null,
        observed_unix: Math.floor(this.now() / 1000)
      };
    }

    if (response.status < 200 || response.status >= 300) {
      throw new discord_api_error('member_unavailable');
    }

    const member = response.body;

    if (
      !member ||
      typeof member !== 'object' ||
      Array.isArray(member) ||
      !member.user ||
      typeof member.user !== 'object' ||
      member.user.id !== discord_id ||
      typeof member.user.username !== 'string' ||
      !member.user.username ||
      !Array.isArray(member.roles) ||
      !member.roles.every(is_snowflake) ||
      !is_nullable_string(member.nick) ||
      !is_nullable_string(member.user.global_name) ||
      !is_nullable_string(member.user.avatar) ||
      !is_nullable_string(member.avatar)
    ) {
      throw new discord_api_error('malformed_member');
    }

    const guild_roles = await this.get_roles(config);
    const assigned_ids = new Set(member.roles);
    const roles = guild_roles
      .filter((role) => role.id !== config.guild_id && assigned_ids.has(role.id))
      .sort((left, right) => right.position - left.position || role_id_descending(left, right));
    const username = member.user.username;
    const global_display_name = member.user.global_name ?? username;
    const display_name = member.nick ?? global_display_name ?? username;

    return {
      member: true,
      discord_id,
      pfp_url: profile_picture_url(config.guild_id, member.user, member),
      username,
      display_name,
      global_display_name,
      roles,
      highest_role: roles[0] || null,
      observed_unix: Math.floor(this.now() / 1000)
    };
  }
}

module.exports = {
  discord_api_error,
  discord_member_service,
  default_avatar_url,
  discord_get,
  profile_picture_url,
  role_id_descending
};
