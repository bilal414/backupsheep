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
- Use a strong `DB_PASSWORD`; don't expose the database/Redis ports publicly.
- Restrict who can reach the console (network/firewall/VPN) — it stores cloud-provider and
  storage credentials and SSH keys.

See [docs/deployment.md](docs/deployment.md) for the full guide.

## Known security considerations

We document these openly so operators can make informed decisions:

- **Browser-session API CSRF.** The console's single-page UI calls the REST API
  authenticated by the session cookie, and CSRF enforcement is currently disabled for
  session-authenticated requests (a carry-over from the SaaS SPA). Modern browsers'
  default `SameSite=Lax` cookie policy blocks the cross-site `POST`/`PATCH`/`DELETE`
  requests this would otherwise expose, and there is no CORS allowance, so cross-site
  exploitation is substantially mitigated in practice. Still, for defense in depth, run
  the console over HTTPS on a dedicated origin and restrict access. Restoring full CSRF
  enforcement for cookie auth (while keeping API-token auth CSRF-free) is a planned
  hardening item.
- **Credential storage.** Connection credentials are encrypted at rest with a per-account
  Fernet key; email-provider credentials are encrypted with a key derived from
  `DJANGO_SECRET_KEY`. Protect the database and the secret key accordingly.
- **No built-in TLS.** The app speaks plain HTTP; TLS is the operator's reverse proxy.
