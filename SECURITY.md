# Security

## Trust model

The native client runs on a machine the customer controls. Any check performed only on the client can be patched. The server is the authority for license validity, expiry, pauses and device binding. Ship nothing of value that does not require a server round trip.

## Device binding

The client stores a persisted P-256 key in the Windows CNG user key store. The server binds the public key on first activation and requires a signature with a fresh nonce on every login and validation. A copied license key and HWID are not enough to authenticate from another machine.

## Known limits

- The native TCP channel is not encrypted. Terminate TLS in front of it (for example stunnel or an L4 TLS proxy) for production.
- The JSON datastore supports one process only. Use a transactional database for multi-instance deployments.
- Email verification is not implemented. Protect administrator logins with an identity-aware proxy and MFA.

## Secrets

- `AUTH_ADMIN_SECRET` (32+ chars) protects `POST /admin/create-key`. Send it as `Authorization: Bearer <secret>` over HTTPS.
- The Discord bot token and signing/transport private keys must never be committed or shipped in the client.

## Reporting

Report vulnerabilities privately to the repository owner instead of opening a public issue.
