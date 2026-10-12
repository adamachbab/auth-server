# auth-server

<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=0:0f2027,50:203a43,100:2c5364&height=220&section=header&text=auth-server&fontSize=64&fontColor=ffffff&desc=Device-bound%20license%20authentication&descSize=20&descAlignY=66&animation=fadeIn" alt="auth-server" width="100%">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Node.js-20+-339933?logo=node.js&logoColor=white" alt="Node.js 20+">
  <img src="https://img.shields.io/badge/C++-20-00599C?logo=c%2B%2B&logoColor=white" alt="C++20">
  <img src="https://img.shields.io/badge/Discord-bot-5865F2?logo=discord&logoColor=white" alt="Discord bot">
  <img src="https://img.shields.io/badge/platform-Windows-0078D6?logo=windows&logoColor=white" alt="Windows">
  <img src="https://img.shields.io/badge/auth-ECDSA%20P--256-8A2BE2" alt="ECDSA P-256">
</p>

License key authentication server for native Windows applications, with device-bound proof of possession, a Discord bot for key management and reseller accounts.

## Features

- **Device-bound licenses**: on first activation the client generates a persistent P-256 key in the Windows CNG key store. Every login and validation must be signed with that key, so a leaked key and HWID cannot be reused on another machine.
- **Anti-replay**: signed requests carry a timestamp and a single-use nonce.
- **Short-lived sessions**: `authenticate` returns a 5-minute access token; `validate` requires a fresh device signature.
- **Pause control**: global, per-key, per-user and self-service subscription pauses that freeze remaining time.
- **Discord bot**: generate keys, list, pause, resume, adjust time, HWID reset requests with admin review, one-time pairing codes.
- **Resellers**: prepaid balances, tiered pricing and atomic key orders delivered as an attachment.
- **Web panel**: user accounts, device authorization flow, admin panel with audit history, CSRF protection and RBAC.
- **C++ client library**: single header, no external dependencies.

## Requirements

- Node.js 20+
- Windows with MSVC or MinGW to build the client
- An HTTPS reverse proxy in production

## Quick start

```bash
npm ci
cp .env.example .env
npm run migrate
npm start
```

For local testing, remove `NODE_ENV=production` from `.env`, set `AUTH_COOKIE_SECURE=false`, and use an absolute `DATABASE_PATH`.

Create a license:

```bash
curl -X POST http://localhost:1053/admin/create-key \
  -H "Authorization: Bearer $AUTH_ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"key":"AUTH-TEST1-TEST2-TEST3-TEST4","duration_seconds":86400,"reason":"local test"}'
```

Create the web administrator with `ADMIN_EMAIL` and `ADMIN_PASSWORD` in `.env`, then `npm run setup`.

## Configuration

| Variable | Description |
| --- | --- |
| `PORT` | HTTP port (default 1053) |
| `AUTH_NATIVE_PORT` | Native TCP port (default 2230) |
| `AUTH_PUBLIC_URL` | Public HTTPS base URL |
| `AUTH_ADMIN_SECRET` | 32+ character secret for `/admin/create-key` |
| `DATABASE_PATH` | Absolute path to the JSON datastore |
| `DISCORD_CLIENT_ID`, `DISCORD_PUBLIC_KEY`, `DISCORD_BOT_TOKEN` | Discord application credentials |
| `DISCORD_GUILD_ID`, `DISCORD_ADMIN_ROLE_IDS`, `DISCORD_ADMIN_USER_IDS` | Bot admin authorization |

## Client

```cpp
#include "client/auth_module.hpp"

auth::client_t client( "auth.example.com:2230" );
auth::session_t session = client.authenticate( key, auth::generate_hwid( ) );

if ( session.success ) {
    auth::session_t check = client.validate( session );
}
```

Build the example with `build.bat`, then run `auth_client.exe host:port`.

## Native protocol

TCP frames with a 16-byte header (`CAUT`, version 1, JSON length, binary length) followed by a JSON body.

| Operation | Fields |
| --- | --- |
| `authenticate` | `key`, `hwid`, `client_public_key`, `timestamp_unix`, `nonce`, `signature` |
| `validate` | `access_token`, `timestamp_unix`, `nonce`, `signature` |

## Discord

Set the Interactions Endpoint URL to `${AUTH_PUBLIC_URL}/api/discord/interactions`. Admin commands require a user ID in `DISCORD_ADMIN_USER_IDS` or a role from `DISCORD_ADMIN_ROLE_IDS` inside `DISCORD_GUILD_ID`. The Discord Administrator permission alone grants nothing.

## Deployment

On Linux, `./install-service.sh` installs a hardened systemd service under a dedicated system user. Put HTTP behind an HTTPS reverse proxy and the native port behind a TLS proxy.

## Project layout

```text
src/          server, native protocol, accounts, resellers, discord, lib
public/       web account, device and admin pages
client/       C++ client library and example
examples/     minimal client usage
migrations/   datastore migrations
scripts/      migrate and provision-admin
tests/        automated tests
```

## Tests

```bash
npm test
```

Run tests without a local `.env` and with no server running on port 2230.

## Security

See [SECURITY.md](SECURITY.md). Client-side checks can always be patched; the server is the authority for license validity.

## License

Released under the [MIT License](LICENSE).
