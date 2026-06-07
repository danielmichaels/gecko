# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Gecko is a DNS security tool (Go module `github.com/danielmichaels/gecko`). It scans domains for DNS facts, assesses them for security issues, and records the results as an append-only change timeline. Pre-alpha.

## Commands

Tasks are defined in `Taskfile.yml` (run `task --list-all`). Common ones:

- `task test` — full suite: `go test -race -v -cover ./...`. Run a single test directly: `go test -run TestName ./internal/service/...`.
- `task serve` / `task worker` — run the HTTP server / job worker locally under `air` (live reload). `task cli -- <args>` runs the binary one-shot.
- `task compose:up` — start the local stack (Postgres via `zarf/compose/docker-compose.yml`), run Goose + River migrations, seed data, tail logs. `task compose:down` to stop.
- `task sqlc` — regenerate `internal/store` after changing `sql/queries/*.sql` or migrations. **Required** after any query/schema change.
- `task ui` — `templ generate` + Tailwind build. Run after editing `.templ` sources or `assets/css/app.css`.
- `task audit` — `betteralign` + `golines` + `golangci-lint`. Run after broad Go changes or formatting-sensitive edits.
- `task db:migration:create -- <name>` — new Goose migration in `assets/migrations`. `task db:migration:up|down|status` to manage. River migrations: `task river:migration:up|down|list`.
- `task verify:auth` — end-to-end auth/role guard check (boots DB, migrates, runs server, executes `scripts/verify-auth-e2e.sh`). Run when touching auth, roles, API keys, invitations, sessions, or protected-route middleware.
- CI is Dagger: `task ci:all`, `task ci:lint`, `task ci:test`, or `task dagger -- <args>` to run the engine locally.

## Architecture

**Request → command → service → store/jobs.** A single `gecko` binary (Kong CLI in `cmd/gecko/main.go`, subcommands in `internal/cmd`) runs as `serve` (HTTP) or `worker` (jobs). `internal/cmd/cmd.go` `NewSetup` wires config + pgx pool + sqlc store + optional River client; `WithRiver(count, addWorkers)` decides whether a process registers workers (server runs without them).

**HTTP layer** (`internal/server`): chi router + Huma (`humachi`) for the typed API, secured by `X-API-Key`. Handlers are thin — they unwrap the `auth.Principal` and delegate to the service layer, returning Huma errors directly. `internal/ui` is the separate browser-facing path: session-cookie middleware (`WebAuth`) + per-session CSRF, redirecting with 303. Templ + Tailwind UI is nascent (toolchain wired, assets embedded via `assets/embed.go`).

**Service layer** (`internal/service`): the business-logic seam. **Convention: every authenticated method takes `(ctx, p *auth.Principal, ...)` — the Principal is passed explicitly, not read from context, so the compiler enforces auth at every call site.** Identity-establishing methods (`Login`, `Signup`, `AcceptInvite`) are the only unauthenticated entry points. Sub-services hang off `*Service` (`DomainsService()`, `RecordsService()`, `AuthService()`). Sentinel errors live in `service.go` (`ErrNotFound`, `ErrForbidden`, `ErrConflict`, `ErrUnauthenticated`, `ErrInvalidInput`). Scheduling a scan goes through the `DomainScanScheduler` interface so tests inject a fake instead of a live River queue (`NewWithScheduler`).

**Persistence** (`internal/store`): sqlc-generated from `sql/queries/*.sql` against `assets/migrations`. pgx v5 pool. **Never hand-edit `internal/store/*.sql.go`, `db.go`, or `models.go`** — change the query/migration and run `task sqlc`.

**Background jobs** (`internal/jobs`): River on Postgres. Four dedicated queues — `queue_enumeration`, `queue_resolver`, `queue_scanner`, `queue_assessor` (enumeration capped independently to bound subfinder upstream pressure). `EnqueueDomainScan` (`scan_jobs.go`) is the single entry point: it creates a `scans` correlation row and enqueues every leaf job within the caller's transaction, gated by an active-status check and a recency dedup window (`Force` bypasses recency but not the status gate). `DomainJobArgs` carries the stable domain identity (tenant/domain/scan IDs + UID/name) onto every job so workers never re-look-up the domain by name. Keep job args, queue names, metadata, and worker registration (`river.go`) aligned when adding jobs.

**Scan → Assess pipeline** (see `ARCHITECTURE.md` for the full scanner/assessor catalog):
- `internal/scanner` — *scan phase*, lightweight data collection (DNS resolution, certs, DNSSEC, CNAME, zone transfer).
- `internal/assessor` — *assess phase*, interpretation and active probing (email security SPF/DKIM/DMARC, dangling CNAME, zone-transfer risk). The split is deliberate: scanning collects facts, assessing makes judgments.
- `internal/dnsclient` — shared resolver with a fleet-wide Postgres-backed rate limiter and an L1/DB cache, both feature-flagged off config (`miekg/dns`, `subfinder`). Scanners/assessors fall back to `dnsclient.New()` when no resolver is injected (unit tests).

**Observation log** (`internal/observer`): the write side of the "middle-path observation model". Live projection tables hold cheap current state; `domain_observations` is the append-only, product-facing change timeline (`created`/`updated`/`deleted` × entity type). Scanners and assessors carry a `DomainIdentity` (zero in unit tests → emission skipped) and call the recorder to stamp observations as they upsert into live tables. Preserve duplicate-observation, active/inactive, and retention semantics when changing domain/record/scan/observer code.

**Multi-tenancy is a core invariant.** Queries and handlers touching user, domain, scan, record, invitation, API-key, or session data must carry the tenant boundary explicitly. Auth roles (owner/admin/member) are enforced in `internal/server/middleware.go` and user-management handlers — changes there need focused tests.

## Conventions

- TDD by default (see `internal/.../​*_test.go` patterns). For DB behavior prefer real migrations + sqlc query tests / integration tests (testcontainers in `internal/testhelpers`) over mocking query semantics. For auth/tenancy, exercise the real chi→Huma middleware path where practical.
- Use `errors.Is`, not `err == err`. Prefer error groups + singleflight where applicable.
- Config is env-var driven via `joeshaw/envdecode` (`internal/config`, `.env` locally).
- Avoid unrelated `go.mod`/`go.sum` churn; keep dependency changes scoped and explained.
- `internal/cmd/formatters.go` handles CLI output; respect the `--format text|json` global flag.
