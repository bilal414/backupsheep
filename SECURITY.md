# Security Policy

## Reporting a vulnerability

Please report security issues **privately**, not in public issues or pull requests.

- Use **GitHub Security Advisories** ("Report a vulnerability" on the repository's
  *Security* tab) to open a private report, **or**
- contact the maintainer privately if a contact is listed on the repository.

Include reproduction steps and impact. You'll get an acknowledgement and a fix timeline.
Please give a reasonable window to address the issue before any public disclosure.

## Supported versions

This is a young open-source project; security fixes target the latest `main`. Run a recent
build.

## Hardening checklist (operator responsibility)

Self-hosting means you own the deployment's security. Before exposing an instance:

- Set a strong, **stable** `DJANGO_SECRET_KEY` (not the placeholder).
- Keep `DJANGO_DEBUG=false`.
- Set `DJANGO_ALLOWED_HOSTS` to your real hostname(s), not `*`.
- Serve over TLS (reverse proxy) and set `DJANGO_HTTPS=true` + `APP_PROTOCOL=https://`.
- Use a strong `DB_PASSWORD`; don't expose the database/RabbitMQ ports publicly.
- Restrict who can reach the console (network/firewall/VPN) — it stores cloud-provider and
  storage credentials and SSH keys.

See the [production deployment guide](docs/guides/production.md) for the full checklist.

## Known security considerations

We document these openly so operators can make informed decisions:

- **Browser-session API CSRF.** Session-authenticated REST requests use Django REST
  Framework's standard CSRF enforcement. The console sends the CSRF cookie value in the
  `X-CSRFToken` header for unsafe methods. Token-authenticated API clients use
  `Authorization: Token ...` and do not rely on cookies, so Django's CSRF check does not
  apply to those requests. Keep both session cookies and API tokens private, run the
  console over HTTPS on a dedicated origin, and do not weaken the session authenticator
  to work around a missing CSRF header in a custom client.
- **Credential storage.** Connection credentials are encrypted at rest with a per-account
  Fernet key; email-provider credentials are encrypted with a key derived from
  `DJANGO_SECRET_KEY`. Protect the database and the secret key accordingly.
- **No built-in TLS.** The app speaks plain HTTP; TLS is the operator's reverse proxy.
