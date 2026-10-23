#!/usr/bin/env bash
# HUNT secret pattern scanner — read-only. Greps a directory for common
# credential patterns. Secret values are redacted in output (first 6 chars only).
#
# Usage: scripts/secret-scan.sh [directory]     (default: current directory)
# Exit codes: 0 = no matches, 1 = matches found, 2 = usage/runtime error
#
# NOTE: This is a first pass. Every hit must be manually verified — most will
# be placeholders, fixtures, or the intentionally public keys listed in
# PUBLIC_OK patterns (still printed, marked PUBLIC-OK).

set -euo pipefail

ROOT="${1:-.}"
if [ ! -d "$ROOT" ]; then
  echo "error: not a directory: $ROOT" >&2
  exit 2
fi

# Respect gitignore for bulky dirs, but DO scan hidden files (.env.local etc.)
# — secrets live there. node_modules/.git are excluded explicitly below.
GREP_CMD=(grep -REnI --binary-files=without-match)
if command -v rg >/dev/null 2>&1; then
  # NOTE: rg flags differ from grep — -I is --no-filename, -N disables line
  # numbers. Use -n for line numbers; rg skips binary files by default.
  GREP_CMD=(rg --no-config --hidden --no-ignore-vcs -n --color never -S)
fi

# Exclusions: lockfiles, this repo's own test fixtures are NOT excluded when
# run against an external target; when run against hunt-agent itself, the
# test-app contains intentionally fake secrets for drill purposes.
EXCLUDES=('node_modules' '.git/' 'dist/' 'build/' '.next/' 'coverage/' 'vendor/')

# Push excludes into rg as globs when available (faster + cleaner output).
if command -v rg >/dev/null 2>&1; then
  GREP_CMD+=(--glob '!node_modules' --glob '!.git' --glob '!dist'
             --glob '!build' --glob '!.next' --glob '!coverage' --glob '!vendor')
fi

run_pat() {
  local label="$1" pattern="$2" public_ok="${3:-no}"
  local out
  out=$("${GREP_CMD[@]}" -e "$pattern" "$ROOT" 2>/dev/null \
    | grep -Ev "$(printf '%s|' "${EXCLUDES[@]}" | sed 's/|$//')" || true)
  if [ -n "$out" ]; then
    while IFS= read -r line; do
      # Redact: keep file:line:col prefix, truncate the matched secret text.
      file=$(printf '%s' "$line" | cut -d: -f1-2)
      rest=$(printf '%s' "$line" | cut -d: -f3-)
      head6=$(grep -Eo "$pattern" <<< "$rest" | head -1 | cut -c1-6 || true)
      tag="SECRET?"
      [ "$public_ok" = "yes" ] && tag="PUBLIC-OK"
      printf '[%s] %s :: %s…REDACTED\n' "$tag" "$file" "$head6"
    done <<< "$out"
  fi
}

echo "== HUNT secret scan: $ROOT =="
echo "-- High-signal credential patterns --"
run_pat stripe   'sk_(live|test)_[0-9A-Za-z_-]{16,}'
run_pat stripe   'sk_(live|test)_[0-9A-Za-z_-]{16,}'
run_pat supabase 'sb_secret_[0-9A-Za-z_-]{16,}'
run_pat supabase 'SUPABASE_SERVICE[_A-Z]*KEY|service_role_key|serviceRoleKey'
run_pat aws      'AKIA[0-9A-Z]{16}'
run_pat github   'ghp_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{22,}'
run_pat slack    'xox[baprs]-[0-9A-Za-z-]{10,}'
run_pat google   'AIza[0-9A-Za-z_-]{35}'
run_pat privkey  '-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----'
run_pat dburl    '(postgres|postgresql|mysql|mongodb(\+srv)?|redis)://[^:[:space:]]+:[^@[:space:]]+@'
run_pat jwt      'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'

echo ""
echo "-- Intentionally public keys (verify they are not secrets in disguise) --"
run_pat publishable 'sb_publishable_[0-9A-Za-z_-]{16,}' yes
run_pat publishable 'pk_live_[0-9A-Za-z]{16,}|pk_test_[0-9A-Za-z]{16,}' yes
run_pat anon       'NEXT_PUBLIC_SUPABASE_ANON_KEY|anon[_ ]key' yes

echo ""
echo "-- NEXT_PUBLIC_ names that look dangerous --"
run_pat nextpublic 'NEXT_PUBLIC_[A-Z_]*(SECRET|PRIVATE|PASSWORD|TOKEN|SERVICE_ROLE)[A-Z_]*'

echo ""
echo "Done. Verify every [SECRET?] hit manually before reporting."
echo "Placeholders, .env.example samples, and test fixtures are not findings."
