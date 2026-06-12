# Manual verification: multi-tenant auth & role guards

This walks through standing up the `tenants` branch locally and exercising the auth
system by hand — signup, API keys, invitations, and the privilege-escalation /
last-owner guards added in this branch.

There are two ways to verify:

- **Automated:** run `scripts/verify-auth.sh` against a running server — it drives the
  whole flow with `curl` and asserts the HTTP status of every security check.
- **Manual:** follow the `curl` walkthrough in [§5](#5-manual-curl-walkthrough).

---

## 1. Prerequisites

```bash
# from the worktree root
cd /Users/danielmichaels/code/github/personal/gecko/.worktrees/tenants

# tools used below (all already on PATH in this environment)
which docker go goose river jq
```

## 2. Environment file

`.env` is gitignored, so a fresh worktree may not have one. If it's missing, create it.
The values below match this project's local compose setup — **Postgres on host port
`5400`, database `gecko`, API on `7070`**. (If your `.env` already exists, just confirm
these ports; the rest of the doc assumes them.)

```bash
cat > .env <<'EOF'
POSTGRES_HOST=localhost
POSTGRES_DB=gecko
POSTGRES_USER=dbuser
POSTGRES_PASSWORD=dbuser
POSTGRES_PORT=5400
POSTGRES_SSL_MODE=disable

API_SERVER_PORT=7070
SIGNUP_ENABLED=true
# optional: speed up password hashing for local poking (prod default is 12)
AUTH_BCRYPT_COST=10
EOF
```

## 3. Start Postgres + run migrations

```bash
# bring up just the database (detached, waits until healthy)
docker compose -f compose.yaml up --wait -d db

# app schema (goose) — includes 00011_auth_multitenant.sql
task db:migration:up

# river job-queue schema (server setup builds a River client at startup)
task river:migration:up

# sanity: the new auth tables should exist
docker compose -f compose.yaml exec db \
  psql -U dbuser -d gecko -c '\dt' | grep -E 'api_keys|invitations|user_credentials|sessions'
```

## 4. Run the server

The auth endpoints never enqueue a job, so the worker can stay off:

```bash
task serve -- --disable-worker
# or without air:
#   go run ./cmd/gecko/main.go serve --disable-worker
```

Leave it running. In another terminal, smoke-test it:

```bash
curl -s localhost:7070/healthz ; echo
# API reference UI:  open http://localhost:7070/scalar
```

### (Optional) Bootstrap instead of signup

If `SIGNUP_ENABLED=false`, or you want to adopt an existing pre-auth tenant, mint the
first owner directly against the DB:

```bash
go run ./cmd/gecko/main.go auth bootstrap \
  --email owner@a.test --password supersecret --tenant-name "Team A"
```

---

## 5. Manual curl walkthrough

> Set a base URL once: `BASE=http://localhost:7070`. Emails must be globally unique
> (one email = one tenant on this branch), so re-runs need fresh addresses — append a
> suffix, e.g. `owner+$(date +%s)@a.test`.

### 5.1 Sign up an owner (creates a tenant + first owner, returns a key)

```bash
curl -s $BASE/api/auth/signup -H 'Content-Type: application/json' \
  -d '{"email":"owner@a.test","password":"supersecret","tenant_name":"Team A"}' | jq
# → 201  { "api_key": "gk_xxxx_…", "email":"owner@a.test", "role":"owner", "tenant_uid":"tenant_…" }

OWNER_KEY=gk_xxxx_…   # paste the api_key
curl -s $BASE/api/auth/me -H "X-API-Key: $OWNER_KEY" | jq   # → role: owner
```

### 5.2 Owner invites a manager; manager accepts

```bash
curl -s $BASE/api/invitations -H "X-API-Key: $OWNER_KEY" -H 'Content-Type: application/json' \
  -d '{"email":"mgr@a.test","role":"manager"}' | jq   # → 201, returns a one-time token

curl -s $BASE/api/invitations/accept -H 'Content-Type: application/json' \
  -d '{"token":"<TOKEN>","password":"supersecret"}' | jq   # → 201, returns the manager's api_key
MGR_KEY=gk_…
```

### 5.3 The security checks (the point of this branch)

Grab the uids first (list is tenant-scoped):

```bash
curl -s $BASE/api/users -H "X-API-Key: $OWNER_KEY" | jq -r '.users[] | "\(.role)\t\(.email)\t\(.uid)"'
# note the uids for owner@a.test, mgr@a.test
```

| # | Request (as manager unless noted) | Expected | Guard |
|---|-----------------------------------|----------|-------|
| 1 | `POST /api/invitations {role:"owner"}` | **403** | `requireCanGrant` — can't invite above your rank |
| 2 | `PUT /api/users/<MGR_UID> {role:"owner"}` (self) | **403** | `requireCanGrant` — no self-promotion |
| 3 | `PUT /api/users/<VIEWER_UID> {role:"owner"}` | **403** | `requireCanGrant` |
| 4 | `PUT /api/users/<OWNER_UID> {role:"viewer"}` | **403** | `requireCanManage` — can't touch a higher rank |
| 5 | `DELETE /api/users/<OWNER_UID>` | **403** | `requireCanManage` |
| 6 | `PUT /api/users/<VIEWER_UID> {role:"viewer"}` | **200** | control — managing a viewer is allowed |
| 7 | sole owner `PUT /api/users/<self> {role:"manager"}` | **409** | `withLastOwnerGuard` |
| 8 | sole owner `DELETE /api/users/<self>` | **409** | `withLastOwnerGuard` |

Example (check #1 — manager tries to mint an owner, must be refused):

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  $BASE/api/invitations -H "X-API-Key: $MGR_KEY" -H 'Content-Type: application/json' \
  -d '{"email":"escalate@a.test","role":"owner"}'
# → 403
```

### 5.4 Cross-tenant isolation

```bash
# sign up a second tenant, then try to touch its user with tenant A's key → 404
curl -s $BASE/api/auth/signup -H 'Content-Type: application/json' \
  -d '{"email":"owner@b.test","password":"supersecret"}' | jq -r .api_key   # B_KEY
curl -s $BASE/api/users -H "X-API-Key: $B_KEY" | jq -r '.users[0].uid'      # B_UID

curl -s -o /dev/null -w '%{http_code}\n' -X PUT \
  $BASE/api/users/<B_UID> -H "X-API-Key: $OWNER_KEY" -H 'Content-Type: application/json' \
  -d '{"email":"owner@b.test","role":"viewer"}'
# → 404  (B's user is invisible to A, not 403 — we don't leak existence)
```

---

## 6. One-shot automated check

The fastest path — boots the DB, applies migrations, starts the server, runs the
checks, and tears the server down:

```bash
task verify:auth
```

Or, if a server is already running, just drive it directly:

```bash
BASE=http://localhost:7070 ./scripts/verify-auth.sh
```

Either prints a PASS/FAIL line per scenario above and exits non-zero if any guard
misbehaves. (`task verify:auth` → `scripts/verify-auth-e2e.sh`, which builds and runs
the server binary so teardown can't orphan the port.)

## 7. Tear down

```bash
docker compose -f compose.yaml down            # keep data volume
docker compose -f compose.yaml down -v         # wipe data too
```