# Design: gecko web UI (v1) + service-layer extraction

- **Date:** 2026-06-06
- **Status:** Approved (pending spec review)
- **Author:** Daniel Michaels

## Context

gecko is a multi-tenant DNS reconnaissance / security-assessment platform. Today it
exposes a fully-documented REST API (huma v2 on chi, Scalar docs at `/scalar`),
a Cobra CLI, and River-driven background jobs over a Postgres store with an
append-only observation log. Auth (multi-tenant signup/login/invitations/users/
API keys) and the DNS resolver stack (shared resolver + cache + rate limiter) are
complete.

There is **no web frontend** — the only HTML in the repo is the Scalar docs page.
This design introduces the first tenant-facing web UI, plus the service-layer
refactor that lets the UI and the existing API share one core.

### Current handler pattern

huma handlers resolve a **principal from `context`** (`principalOrErr` → `p.TenantID`)
and then query `app.store` directly, scoping every query by `tenantID`. There is no
service layer; business logic lives in the handler + store. The reusable seam is
therefore **"principal in context → tenant-scoped store query."**

## Goals

- A tenant-facing web UI for **Auth** (login, accept-invite, logout) and **Domains**
  (list, add, detail with DNS records + change timeline).
- A complete app shell; not-yet-built sections appear as "coming soon" placeholders.
- Aesthetic: **security console** — dark, severity-color-driven, data-dense.
- Extract business logic into a shared **service layer** so the API and UI are two
  thin adapters over one core (thin handlers everywhere).

## Non-goals (v1)

- Findings, Scans, Team, Settings, Dashboard screens (placeholders only).
- Live/streaming scan status (no long-lived SSE broker yet — lands with Scans).
- Browser-based signup (signup stays API/CLI-only for v1).
- Any change to API request/response behavior — the refactor is behavior-preserving.

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Direction | Web UI (datastar) | Make existing data usable; dogfood the platform. |
| Audience | Tenant-facing product | Real users log in and manage their own domains. |
| Browser auth | Dedicated sessions (cookie) | Real expiry + server-side revocation; separates human logins from machine API keys. |
| Aesthetic | Security console (dark) | Signals "security tooling"; severity gets a natural visual language. |
| Integration | Shared service layer | Thin handlers everywhere; one core for two transports. |
| Refactor scope | Full surface, **sequenced** | Thin handlers everywhere, but UI value is not blocked behind trivial-CRUD extraction. Refactor and feature stay in separate commits for a bisectable history. |

## Architecture

### 1. Service layer (`internal/service`)

Business logic moves out of huma handlers into plain Go service types:

- `service.Auth` — Login, AcceptInvite, Logout, Me, Signup
- `service.Domains` — List, Create, Get, Delete, DeletionImpact
- `service.Records` — List, History, Timeline
- (Commit 2) `service.Users`, `service.Invitations`, `service.APIKeys`

Conventions:

- Methods take `(ctx, principal, params)` and return store/view structs plus **typed
  sentinel errors** (`ErrNotFound`, `ErrForbidden`, `ErrConflict`, …) consumed with
  `errors.Is`.
- `principal` is an **explicit argument** (lifted out of being read from `context`
  inside the handler). This is the seam that lets two transports share the core.
- huma handlers become thin adapters: parse input → call service → map result to
  `dto` / map error to `huma.Error4xx/5xx`.
- UI handlers are the second adapter: call service → render Templ / map error to an
  error fragment or redirect-to-login.

### 2. Sessions & browser auth

- New migration `00013_sessions.sql`:
  `sessions(id, uid, user_id, tenant_id, token_hash, expires_at, created_at,
  last_used_at, user_agent, ip)`. Only a **hash** of the session token is stored.
- `service.Auth.Login` verifies email/password (reuse `internal/auth` password
  logic), mints a session, returns the raw token once.
- `webAuth` chi middleware: reads an `HttpOnly`, `Secure`, `SameSite=Lax` cookie →
  resolves the session → puts the **same principal type the API uses** into
  `context`. Sliding `last_used_at` refresh; hard `expires_at`. Logout revokes the row.
- **CSRF:** cookie auth is not CSRF-immune. State-changing UI requests
  (`@post/@put/@delete`) carry a per-session CSRF token via a request header
  (datastar `headers` option), validated server-side; `SameSite=Lax` is the backstop.
  The API-key path is unchanged and remains CSRF-immune.

### 3. UI module (`internal/ui`)

- `handlers.go` — chi handlers mounted under **`/app`** on the existing router.
  `/app/login` and `/app/invite` are public; everything else is behind `webAuth`.
- `templates/*.templ` (Templ):
  - `AppShell` — top bar (tenant + user menus) + left sidebar nav.
  - `LoginPage`, `AcceptInvitePage`.
  - `DomainsPage` + `DomainRow`.
  - `DomainDetailPage` — lazy-loads `RecordsTable` + `Timeline` via
    `data-on-intersect__once`.
  - `ComingSoon` (Findings/Scans/Team/Settings/Dashboard).
  - Shared `ContentError` with retry.
- **datastar usage:** request/response SSE morphs only (add domain → append row;
  delete → remove row; detail → lazy load). **No long-lived SSE broker in v1.**
- `datastar.js` served from the existing embedded `/static/*` fileserver.

### 4. Tooling

- Add `templ` (codegen `.templ → _templ.go`), the `datastar-go` SDK, and the
  **Tailwind standalone CLI** (single binary, no Node) for the security-console
  styling; CSS output embedded into assets.
- Taskfile targets: `task generate` (templ), `task css` (tailwind), wired into the
  existing `air` live-reload loop.

## Data-flow examples

- **Login:** `GET /app/login` (Templ page) → `POST /app/login` (datastar `@post`
  form) → `service.Auth.Login` verifies → mint session, `Set-Cookie` → datastar
  redirect to `/app/domains`.
- **Domains list:** `GET /app/domains` → `webAuth` → `service.Domains.List(ctx,
  principal, …)` → render `DomainsPage`.
- **Add domain:** `POST /app/domains` (datastar `@post`) → `service.Domains.Create`
  (enqueues the existing scan job) → append new `DomainRow`, reset the form.
- **Domain detail:** `GET /app/domains/{uid}` → shell renders immediately,
  `data-on-intersect__once` fetches `RecordsTable` + `Timeline`.
- **Delete:** `@delete` → `service.Domains.Delete` → remove row.

## Testing strategy (TDD)

- The service layer is the **new home for tenant-scoping / privilege-escalation
  assertions** — port the intent of the existing `auth_escalation` and
  `*_integration` tests down to the service, over the existing testcontainers/dagger
  DB setup.
- New tests: session service + `webAuth` (cookie resolve, expiry, revocation,
  cross-tenant isolation); CSRF rejection; UI handlers (status / redirect / fragment).
- **Invariant:** the existing huma API integration tests must keep passing — the
  refactor is behavior-preserving for the API.

## Sequencing (commit plan)

1. **Commit 1 — v1 surfaces + UI (value):** extract `auth/session`, `domains`,
   `records/timeline` into `internal/service`; refactor those huma handlers to thin
   adapters; add sessions migration + `webAuth` + CSRF; build the `internal/ui`
   module (shell, auth screens, domains list/add/detail, placeholders) + tooling.
2. **Commit 2 — mechanical cleanup (structure):** extract `users`, `invitations`,
   `apikeys` into the service layer and thin their huma handlers. Pure
   behavior-preserving refactor, no UI change. Kept separate so a regression is
   instantly attributable to structure vs. behavior.

Each commit keeps `main` green.

## Out of scope / deferred

- Findings, Scans (incl. live status / SSE broker), Team, Settings, Dashboard UIs.
- Browser signup flow.
- Any API behavior change.
