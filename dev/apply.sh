#!/usr/bin/env bash
# apply.sh — apply schema/*.sql in order against the dockerized DB.
# Usage:
#   ./apply.sh                # schema only
#   ./apply.sh --seed         # schema + seed
#   ./apply.sh --supabase     # include 97_supabase.sql (won't work without auth.users)
#   DB_URL=... ./apply.sh     # override target DB
set -euo pipefail

DB_URL="${DB_URL:-postgres://postgres:postgres@localhost:5433/litdb}"
SCHEMA_DIR="$(cd "$(dirname "$0")"/../schema && pwd)"
WITH_SEED=0
WITH_SUPABASE=0

for arg in "$@"; do
  case "$arg" in
    --seed)     WITH_SEED=1 ;;
    --supabase) WITH_SUPABASE=1 ;;
    *) echo "Unknown arg: $arg" >&2; exit 2 ;;
  esac
done

echo "Target: $DB_URL"
echo "Schema: $SCHEMA_DIR"

shopt -s nullglob
for f in "$SCHEMA_DIR"/*.sql; do
  if [[ "$(basename "$f")" == *.down.sql ]]; then
    echo "[skip] $f (down migration)"
    continue
  fi
  if [[ "$WITH_SUPABASE" -eq 0 && "$(basename "$f")" == "97_supabase.sql" ]]; then
    echo "[skip] $f (use --supabase to include)"
    continue
  fi
  echo "[apply] $f"
  psql "$DB_URL" -v ON_ERROR_STOP=1 -f "$f"
done

if [[ "$WITH_SEED" -eq 1 ]]; then
  echo "[apply] seed.sql"
  psql "$DB_URL" -v ON_ERROR_STOP=1 -f "$(dirname "$SCHEMA_DIR")/seed.sql"
fi

echo "Done."
