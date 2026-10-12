const express = require('express');
const {
  decrypt_request_envelope,
  encrypt_response_envelope,
  load_transport_private_key,
  parse_request_envelope
} = require('./envelope');
const {
  authenticate_discord_request,
  validate_request_shape
} = require('./request-auth');
const {
  discord_api_error,
  discord_member_service
} = require('./member-service');
const { sign_discord_attestation } = require('./response-signing');

const route_path = '/v2/discord/member-info';
const rate_window_ms = 60 * 1000;
const rate_cache_max_entries = 4096;
const nonce_cache_max_entries = 10000;
const nonce_ttl_ms = 120 * 1000;

function positive_integer(value, fallback) {
  const parsed = Number(value);

  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function discord_configuration(env = process.env) {
  return {
    bot_token: env.DISCORD_BOT_TOKEN,
    guild_id: env.DISCORD_GUILD_ID,
    api_timeout_ms: positive_integer(env.DISCORD_API_TIMEOUT_MS, 5000),
    role_cache_ms: positive_integer(env.DISCORD_ROLE_CACHE_MS, 30000),
    signing_private_key_file: env.DISCORD_SIGNING_PRIVATE_KEY_FILE,
    transport_private_key_file: env.DISCORD_TRANSPORT_PRIVATE_KEY_FILE,
    signing_key_id: env.DISCORD_SIGNING_KEY_ID,
    signing_issuer: env.DISCORD_SIGNING_ISSUER || 'auth-server-discord-member-info',
    signing_audience: env.DISCORD_SIGNING_AUDIENCE || 'windows-client'
  };
}

function configuration_is_complete(config) {
  return typeof config.bot_token === 'string' &&
    config.bot_token.length > 0 &&
    typeof config.guild_id === 'string' &&
    /^[0-9]{17,20}$/.test(config.guild_id) &&
    typeof config.signing_private_key_file === 'string' &&
    config.signing_private_key_file.length > 0 &&
    typeof config.transport_private_key_file === 'string' &&
    config.transport_private_key_file.length > 0 &&
    typeof config.signing_key_id === 'string' &&
    config.signing_key_id.length > 0;
}

function create_rate_limiter(options = {}) {
  const now = options.now || (() => Date.now());
  const max_entries = options.max_entries || rate_cache_max_entries;
  const ip_limit = options.ip_limit || 20;
  const license_limit = options.license_limit || 10;
  const ip_entries = new Map();
  const license_entries = new Map();

  function clean(entries, current) {
    for (const [key, entry] of entries) {
      if (entry.reset_at <= current) {
        entries.delete(key);
      }
    }
  }

  function take(entries, key, limit, current) {
    let entry = entries.get(key);

    if (!entry) {
      if (entries.size >= max_entries) {
        return {
          allowed: false,
          retry_after: Math.ceil(rate_window_ms / 1000)
        };
      }

      entry = {
        count: 0,
        reset_at: current + rate_window_ms
      };
      entries.set(key, entry);
    }

    if (entry.count >= limit) {
      return {
        allowed: false,
        retry_after: Math.max(1, Math.ceil((entry.reset_at - current) / 1000))
      };
    }

    entry.count += 1;
    return { allowed: true };
  }

  return {
    take(ip, license_hash) {
      const current = now();

      clean(ip_entries, current);
      clean(license_entries, current);

      const by_ip = take(ip_entries, ip, ip_limit, current);

      if (!by_ip.allowed) {
        return by_ip;
      }

      return take(license_entries, license_hash, license_limit, current);
    }
  };
}

function create_replay_cache(options = {}) {
  const now = options.now || (() => Date.now());
  const max_entries = options.max_entries || nonce_cache_max_entries;
  const entries = new Map();

  function clean(current) {
    for (const [key, expires_at] of entries) {
      if (expires_at <= current) {
        entries.delete(key);
      }
    }
  }

  return {
    consume(license_hash, nonce) {
      const current = now();

      clean(current);

      const key = `${license_hash}:${nonce}`;

      if (entries.has(key)) {
        return 'replayed';
      }

      if (entries.size >= max_entries) {
        return 'full';
      }

      entries.set(key, current + nonce_ttl_ms);
      return 'accepted';
    }
  };
}

function create_discord_member_router(options) {
  const router = express.Router();
  const now = options.now || (() => Date.now());
  const get_config = options.get_config || (() => discord_configuration());
  const discord_service = options.discord_service || new discord_member_service({ now });
  const sign_attestation = options.sign_attestation || sign_discord_attestation;
  const rate_limiter = options.rate_limiter || create_rate_limiter({ now });
  const replay_cache = options.replay_cache || create_replay_cache({ now });

  router.post('/', express.json({ limit: '8kb', strict: true }), async (req, res) => {
    const envelope = parse_request_envelope(req.body);

    if (!envelope) {
      return res.status(400).json({ success: false, error: 'Malformed request' });
    }

    const config = get_config();

    if (!configuration_is_complete(config)) {
      return res.status(503).json({ success: false, error: 'Discord service unavailable' });
    }

    let decrypted;

    try {
      decrypted = decrypt_request_envelope(
        envelope,
        load_transport_private_key(config.transport_private_key_file)
      );
    } catch {
      return res.status(503).json({ success: false, error: 'Discord service unavailable' });
    }

    if (!decrypted) {
      return res.status(401).json({ success: false, error: 'Unauthorized' });
    }

    const request = validate_request_shape(decrypted.body);

    if (!request) {
      return res.status(400).json({ success: false, error: 'Malformed request' });
    }

    const rate = rate_limiter.take(
      req.ip || req.socket.remoteAddress || 'unknown',
      request.license_hash
    );

    if (!rate.allowed) {
      res.setHeader('Retry-After', rate.retry_after);
      return res.status(429).json({ success: false, error: 'Too many requests' });
    }

    const authenticated = authenticate_discord_request(
      request,
      options.load_database(),
      Math.floor(now() / 1000)
    );

    if (!authenticated) {
      return res.status(401).json({ success: false, error: 'Unauthorized' });
    }

    const replay = replay_cache.consume(request.license_hash, request.nonce);

    if (replay === 'replayed') {
      return res.status(401).json({ success: false, error: 'Unauthorized' });
    }

    if (replay === 'full') {
      return res.status(503).json({ success: false, error: 'Discord service unavailable' });
    }

    try {
      const profile = await discord_service.get_member_profile(config, request.discord_id);
      const signing_now = Math.floor(now() / 1000);
      const attestation = await sign_attestation({
        member: profile.member,
        guild_id: config.guild_id,
        discord_id: request.discord_id,
        discord_id_hash: request.discord_id_hash,
        license_hash: request.license_hash,
        hwid_hash: request.hwid_hash,
        request_hash: authenticated.request_hash,
        nonce: request.nonce,
        username: profile.username,
        global_display_name: profile.global_display_name,
        display_name: profile.display_name,
        pfp_url: profile.pfp_url,
        roles: profile.roles,
        highest_role: profile.highest_role,
        observed_unix: profile.observed_unix
      }, config, signing_now);

      return res.json(
        encrypt_response_envelope(attestation, decrypted.shared_secret, request.nonce)
      );
    } catch (error) {
      if (error instanceof discord_api_error && error.kind === 'rate_limited') {
        res.setHeader('Retry-After', error.retry_after_seconds || 1);
        return res.status(429).json({ success: false, error: 'Discord service unavailable' });
      }

      return res.status(503).json({ success: false, error: 'Discord service unavailable' });
    }
  });

  router.use((error, req, res, next) => {
    if (
      error &&
      (error.type === 'entity.parse.failed' || error.type === 'entity.too.large')
    ) {
      return res.status(400).json({ success: false, error: 'Malformed request' });
    }

    return next(error);
  });

  return router;
}

function mount_discord_member_route(app, options) {
  app.use(route_path, create_discord_member_router(options));
}

module.exports = {
  route_path,
  configuration_is_complete,
  create_discord_member_router,
  create_rate_limiter,
  create_replay_cache,
  discord_configuration,
  mount_discord_member_route
};
