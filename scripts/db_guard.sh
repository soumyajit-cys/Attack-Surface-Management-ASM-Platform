#!/bin/bash
# DB safety guard: refuse to run against anything but a scratch database.
#
# Usage: source scripts/db_guard.sh   (aborts the shell on failure)
#    or: scripts/db_guard.sh && <alembic|pytest|script> ...
#
# Passes only when $DATABASE_URL names a database starting with
# "scratch_" or "e2e_". Prints the database name (never credentials).
set -u

_db_url="${DATABASE_URL:-}"
if [ -z "$_db_url" ]; then
    echo "db_guard: DATABASE_URL is not set -- refusing to run" >&2
    exit 1
fi

# Strip query string, then take the path segment after the last "/".
_db_path="${_db_url%%\?*}"
_db_name="${_db_path##*/}"
echo "db_guard: target database is '${_db_name}'"

case "$_db_name" in
    scratch_*|e2e_*)
        echo "db_guard: OK (scratch database)"
        ;;
    *)
        echo "db_guard: REFUSING -- '${_db_name}' is not a scratch_/e2e_ database" >&2
        exit 1
        ;;
esac
