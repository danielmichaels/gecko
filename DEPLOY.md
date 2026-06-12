# Deploying Gecko (self-hosted)

Gecko ships as a single container image run in two modes — `serve` (HTTP API + web UI)
and `worker` (background scan/assess jobs) — backed by Postgres. `compose.yaml` wires the
whole stack; this guide gets it running. It is deliberately platform-agnostic: bring your
own reverse proxy, TLS, and orchestrator.

## What runs

| Service   | Role | Exposed |
|-----------|------|---------|
| `db`      | Postgres 16 (app data, River job queue, DNS cache, live-UI LISTEN/NOTIFY) | internal only |
| `migrate` | one-shot: applies goose schema migrations, then exits | — |
| `serve`   | HTTP API + web UI on `:9090`; applies River migrations on boot | `:9090` → your proxy |
| `worker`  | runs scan/assess jobs; needs DNS egress | — |
| `riverui` | River job dashboard (**no built-in auth**) | `127.0.0.1:8080` only |

Startup is ordered `db → migrate → serve → worker + riverui`, so schema (goose) and job
tables (River) are each applied exactly once before the apps depend on them.

## Requirements

- Docker + Docker Compose v2.
- A host that allows **outbound DNS**: UDP/53 *and* TCP/53 (zone transfers / AXFR). Gecko is
  a DNS tool — a host or network that blocks raw DNS egress will silently break scanning.
- Postgres with `LISTEN/NOTIFY` and session-mode connections. The bundled `db` service
  satisfies this. If you point at an **external** Postgres, avoid transaction-pooled endpoints
  (e.g. PgBouncer in transaction mode, some serverless poolers) — they break LISTEN/NOTIFY and
  River.

## 1. Get the image

The published image is currently **private**. Authenticate first (or set the GHCR package to
public and skip this):

```bash
echo "$GHCR_PAT" | docker login ghcr.io -u <your-github-username> --password-stdin
```

`$GHCR_PAT` is a GitHub Personal Access Token with `read:packages`. To pin a specific version
instead of `:latest`, set `GECKO_IMAGE` in `.env` (see below).

## 2. Configure

```bash
cp .env.example .env
# generate strong secrets:
openssl rand -hex 32   # → X_API_KEY
openssl rand -hex 32   # → AUTH_CSRF_SECRET
openssl rand -hex 24   # → POSTGRES_PASSWORD
```

Edit `.env` and set at minimum: `POSTGRES_PASSWORD`, `X_API_KEY`, `AUTH_CSRF_SECRET`, and
`APP_PUBLIC_URL` (the public HTTPS URL you'll serve from — used in invite/reset links).
Set `POSTGRES_SSL_MODE=require` only if your Postgres enforces TLS.

## 3. Bring up

```bash
docker compose up -d
docker compose ps           # serve should become healthy
docker compose logs -f serve worker
```

`migrate` runs and exits `0`; `serve` then `worker`/`riverui` start. Migrations (goose +
River) are applied automatically — there is no separate migration command to run.

## 4. Create the first owner

There is no seeded login. Bootstrap the first owner + tenant directly (run after the stack is
up so migrations have applied):

```bash
docker compose run --rm serve auth bootstrap --help   # see required flags
docker compose run --rm serve auth bootstrap ...       # create the owner
```

Then sign in at your public URL.

## 5. Reverse proxy + TLS

`serve` listens on plain HTTP `:9090`. Put your own TLS-terminating reverse proxy in front of
it (Caddy, nginx, Traefik, your platform's ingress — whatever you run) and route your domain
to `:9090`. Keep `AUTH_SESSION_COOKIE_SECURE=true`, which requires the session to be served
over HTTPS. Point `APP_PUBLIC_URL` at the public URL.

## 6. River dashboard (optional)

`riverui` binds to `127.0.0.1:8080` only, because it has **no authentication** — anyone who
reaches it can inspect and manage your job queue. Access it via an SSH tunnel, or expose it
*only* behind an authenticating proxy. To change the host port, set `RIVERUI_PORT` in `.env`.

## Operations

**Upgrade** — pull the new image and recreate; migrations run automatically on boot:
```bash
docker compose pull
docker compose up -d
```

**Back up Postgres** (the only stateful component):
```bash
docker compose exec db pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB" > gecko-$(date +%F).sql
```
The data lives in the `gecko_db` named volume; snapshot it as well if your host supports it.

**Logs:**
```bash
docker compose logs -f serve     # HTTP / API / UI
docker compose logs -f worker    # scans, assessments, mail (MAIL_DRIVER=log writes here)
```

## Troubleshooting

- **`serve` never becomes healthy** — check `docker compose logs serve`. Usually a bad
  `POSTGRES_*` value or the `migrate` step failing; confirm `docker compose logs migrate`
  exited cleanly.
- **Scans never find records / hang** — verify outbound UDP/53 and TCP/53 from the worker's
  host/network. Test from inside the container:
  `docker compose exec worker sh -c "getent hosts example.com"`.
- **Image pull denied** — re-run the `docker login ghcr.io` step (token needs `read:packages`),
  or make the package public.
- **Web login loops / CSRF errors** — `APP_PUBLIC_URL` must match the URL you browse, and the
  site must be served over HTTPS while `AUTH_SESSION_COOKIE_SECURE=true`.
