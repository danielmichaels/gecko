#!/usr/bin/env bash
#
# verify-auth.sh — exercise the multi-tenant auth + role guards against a running
# gecko server and assert the HTTP status of every security-relevant path.
#
#   BASE=http://localhost:7070 ./scripts/verify-auth.sh
#
# Prereqs: the server is running (see docs/manual-auth-verification.md), `curl` and
# `jq` on PATH. Emails are suffixed with an epoch so the script is re-runnable
# despite the one-email-one-tenant constraint.

set -uo pipefail

BASE="${BASE:-http://localhost:7070}"
PW="supersecret"
TS="$(date +%s)"

PASS=0
FAIL=0
HTTP_CODE=""
HTTP_BODY=""

green() { printf '\033[32m%s\033[0m' "$1"; }
red()   { printf '\033[31m%s\033[0m' "$1"; }

# req METHOD PATH APIKEY [JSON_BODY] → sets HTTP_CODE, HTTP_BODY
req() {
  local method="$1" path="$2" key="$3" body="${4:-}"
  local args=(-sS -X "$method" "$BASE$path" -w $'\n%{http_code}')
  [[ -n "$key" ]] && args+=(-H "X-API-Key: $key")
  [[ -n "$body" ]] && args+=(-H 'Content-Type: application/json' -d "$body")
  local resp
  resp="$(curl "${args[@]}")" || { HTTP_CODE="000"; HTTP_BODY="curl failed"; return; }
  HTTP_CODE="${resp##*$'\n'}"
  HTTP_BODY="${resp%$'\n'*}"
}

# check WANT_CODE DESCRIPTION — asserts the last req's status
check() {
  local want="$1" desc="$2"
  if [[ "$HTTP_CODE" == "$want" ]]; then
    printf '  %s %s (HTTP %s)\n' "$(green PASS)" "$desc" "$HTTP_CODE"
    PASS=$((PASS + 1))
  else
    printf '  %s %s — want %s got %s\n        body: %s\n' \
      "$(red FAIL)" "$desc" "$want" "$HTTP_CODE" "$HTTP_BODY"
    FAIL=$((FAIL + 1))
  fi
}

# checkeq GOT WANT DESCRIPTION — asserts a value (e.g. a JSON field)
checkeq() {
  local got="$1" want="$2" desc="$3"
  if [[ "$got" == "$want" ]]; then
    printf '  %s %s (%s)\n' "$(green PASS)" "$desc" "$got"
    PASS=$((PASS + 1))
  else
    printf '  %s %s — want %s got %s\n' "$(red FAIL)" "$desc" "$want" "$got"
    FAIL=$((FAIL + 1))
  fi
}

jqr() { echo "$HTTP_BODY" | jq -r "$1"; }

# need VALUE LABEL — abort if a value we depend on came back empty/null
need() {
  if [[ -z "$1" || "$1" == "null" ]]; then
    printf '\n%s could not obtain %s — is the server up at %s?\n        last body: %s\n' \
      "$(red ABORT)" "$2" "$BASE" "$HTTP_BODY" >&2
    exit 2
  fi
}

echo "Verifying auth against $BASE (run id $TS)"

# ── setup: tenant A with an owner, a manager, and a viewer ───────────────────────
echo
echo "Setup — tenant A (owner, manager, viewer)"

OWNER_EMAIL="owner+$TS@a.test"
MGR_EMAIL="mgr+$TS@a.test"
VIEWER_EMAIL="viewer+$TS@a.test"

req POST /api/auth/signup "" "{\"email\":\"$OWNER_EMAIL\",\"password\":\"$PW\",\"tenant_name\":\"Team A $TS\"}"
check 201 "signup creates an owner + tenant"
OWNER_KEY="$(jqr .api_key)"; need "$OWNER_KEY" "owner api key"
checkeq "$(jqr .role)" owner "signup role is owner"

# invite_accept EMAIL ROLE — invites and accepts, setting INVITED_KEY. Returns the key
# via a global (not stdout) so its check output reaches the terminal instead of being
# swallowed by command substitution.
INVITED_KEY=""
invite_accept() {
  local email="$1" role="$2" tok
  req POST /api/invitations "$OWNER_KEY" "{\"email\":\"$email\",\"role\":\"$role\"}"
  check 201 "owner invites a $role"
  tok="$(jqr .token)"; need "$tok" "$role invite token"
  req POST /api/invitations/accept "" "{\"token\":\"$tok\",\"password\":\"$PW\"}"
  check 201 "$role accepts the invite"
  INVITED_KEY="$(jqr .api_key)"; need "$INVITED_KEY" "$role api key"
}

invite_accept "$MGR_EMAIL" manager;  MGR_KEY="$INVITED_KEY"
invite_accept "$VIEWER_EMAIL" viewer; VIEWER_KEY="$INVITED_KEY"

req GET /api/users "$OWNER_KEY"
check 200 "owner lists tenant users"
OWNER_UID="$(jqr ".users[] | select(.email==\"$OWNER_EMAIL\") | .uid")"; need "$OWNER_UID" "owner uid"
MGR_UID="$(jqr ".users[] | select(.email==\"$MGR_EMAIL\") | .uid")";     need "$MGR_UID" "manager uid"
VIEWER_UID="$(jqr ".users[] | select(.email==\"$VIEWER_EMAIL\") | .uid")"; need "$VIEWER_UID" "viewer uid"

# ── grant-rank guard: an actor may not assign a role above their own ─────────────
echo
echo "Escalation — requireCanGrant (role being assigned)"

req POST /api/invitations "$MGR_KEY" "{\"email\":\"escalate+$TS@a.test\",\"role\":\"owner\"}"
check 403 "manager CANNOT invite an owner"

req PUT "/api/users/$MGR_UID" "$MGR_KEY" "{\"email\":\"$MGR_EMAIL\",\"role\":\"owner\"}"
check 403 "manager CANNOT self-promote to owner"

req PUT "/api/users/$VIEWER_UID" "$MGR_KEY" "{\"email\":\"$VIEWER_EMAIL\",\"role\":\"owner\"}"
check 403 "manager CANNOT promote a viewer to owner"

# ── manage-rank guard: an actor may not act on a user above their own rank ───────
echo
echo "Escalation — requireCanManage (target's current role)"

req PUT "/api/users/$OWNER_UID" "$MGR_KEY" "{\"email\":\"$OWNER_EMAIL\",\"role\":\"viewer\"}"
check 403 "manager CANNOT demote/rewrite an owner"

req DELETE "/api/users/$OWNER_UID" "$MGR_KEY"
check 403 "manager CANNOT delete an owner"

# control: managing a viewer (at/below the manager's rank) is allowed
req PUT "/api/users/$VIEWER_UID" "$MGR_KEY" "{\"email\":\"$VIEWER_EMAIL\",\"role\":\"viewer\",\"name\":\"Vee\"}"
check 200 "manager CAN manage a viewer (control)"

# control: a viewer is read-only for member management
req POST /api/apikeys "$VIEWER_KEY" '{"name":"nope"}'
check 403 "viewer CANNOT create an API key (control)"

# control: an owner may grant owner
req PUT "/api/users/$VIEWER_UID" "$OWNER_KEY" "{\"email\":\"$VIEWER_EMAIL\",\"role\":\"owner\"}"
check 200 "owner CAN promote to owner (control)"

# the promote above re-roled the viewer; mint a fresh viewer for the domain checks
DGUARD_VIEWER_EMAIL="dguard-viewer+$TS@a.test"
invite_accept "$DGUARD_VIEWER_EMAIL" viewer; DGUARD_VIEWER_KEY="$INVITED_KEY"

# ── domain mutation role guard: viewers are read-only for domains ────────────────
echo
echo "Domains — ownerOrManager guard on create/update/delete"

req POST /api/domains "$OWNER_KEY" "{\"domain\":\"guard-$TS.example.com\"}"
check 201 "owner CAN create a domain (control)"
DGUARD_UID="$(jqr .uid)"; need "$DGUARD_UID" "guarded domain uid"

req POST /api/domains "$DGUARD_VIEWER_KEY" "{\"domain\":\"viewer-$TS.example.com\"}"
check 403 "viewer CANNOT create a domain"

req PUT "/api/domains/$DGUARD_UID" "$DGUARD_VIEWER_KEY" '{"status":"inactive"}'
check 403 "viewer CANNOT update a domain"

req DELETE "/api/domains/$DGUARD_UID" "$DGUARD_VIEWER_KEY"
check 403 "viewer CANNOT delete a domain"

# the forbidden delete left the domain intact
req GET "/api/domains/$DGUARD_UID" "$OWNER_KEY"
check 200 "domain survives the forbidden viewer delete (control)"

req PUT "/api/domains/$DGUARD_UID" "$MGR_KEY" '{"status":"active"}'
check 200 "manager CAN update a domain (control)"

req DELETE "/api/domains/$DGUARD_UID" "$OWNER_KEY"
check 204 "owner CAN delete a domain (control)"

# ── last-owner guard: a tenant can never be orphaned ─────────────────────────────
echo
echo "Tenant integrity — withLastOwnerGuard (fresh sole-owner tenant)"

SOLO_EMAIL="solo+$TS@a.test"
req POST /api/auth/signup "" "{\"email\":\"$SOLO_EMAIL\",\"password\":\"$PW\"}"
check 201 "signup a fresh sole-owner tenant"
SOLO_KEY="$(jqr .api_key)"; need "$SOLO_KEY" "solo owner key"
req GET /api/users "$SOLO_KEY"
SOLO_UID="$(jqr '.users[0].uid')"; need "$SOLO_UID" "solo owner uid"

req PUT "/api/users/$SOLO_UID" "$SOLO_KEY" "{\"email\":\"$SOLO_EMAIL\",\"role\":\"manager\"}"
check 409 "sole owner CANNOT self-demote"

req DELETE "/api/users/$SOLO_UID" "$SOLO_KEY"
check 409 "sole owner CANNOT self-delete"

# ── cross-tenant isolation ───────────────────────────────────────────────────────
echo
echo "Cross-tenant — tenant B is invisible to tenant A"

B_EMAIL="owner+$TS@b.test"
req POST /api/auth/signup "" "{\"email\":\"$B_EMAIL\",\"password\":\"$PW\"}"
check 201 "signup tenant B"
B_KEY="$(jqr .api_key)"; need "$B_KEY" "tenant B key"
req GET /api/users "$B_KEY"
B_UID="$(jqr '.users[0].uid')"; need "$B_UID" "tenant B owner uid"

req PUT "/api/users/$B_UID" "$OWNER_KEY" "{\"email\":\"$B_EMAIL\",\"role\":\"viewer\"}"
check 404 "A cannot update B's user (404, not 403 — no existence leak)"

req DELETE "/api/users/$B_UID" "$OWNER_KEY"
check 404 "A cannot delete B's user (404)"

# ── summary ──────────────────────────────────────────────────────────────────────
echo
if [[ $FAIL -eq 0 ]]; then
  printf 'Result: %s passed, %s failed\n' "$(green "$PASS")" "$(green 0)"
else
  printf 'Result: %s passed, %s failed\n' "$(green "$PASS")" "$(red "$FAIL")"
fi
[[ $FAIL -eq 0 ]]