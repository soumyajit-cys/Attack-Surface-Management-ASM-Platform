#!/usr/bin/env bash
# SentinelASM first-time setup (Phase 0, task 0.3).
#
# Idempotent: creates .env files only when they are missing and NEVER
# overwrites an existing .env. Safe to re-run (`make setup`).
#
# - Root .env (docker compose stack): generated JWT_SECRET (64-hex) and
#   POSTGRES_PASSWORD. The compose DATABASE_URL embeds the postgres password,
#   so both are updated together.
# - backend/.env (local `uvicorn` dev): generated JWT_SECRET (64-hex);
#   localhost DB/Redis URLs stay as documented in backend/.env.example.
#
# Requires: bash, python3. Uses GNU/BSD-portable constructs only
# (placeholder replacement is done via python3, not sed -i).

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

gen_hex() {
  # $1 = number of random bytes (hex output is 2x).
  python3 -c "import secrets,sys; print(secrets.token_hex(int(sys.argv[1])))" "$1"
}

inject_placeholders() {
  # $1 = env file path. Replaces known placeholder values in place.
  python3 - "$1" <<'EOF'
import sys

path = sys.argv[1]
with open(path) as f:
    text = f.read()

import secrets
try:
    from cryptography.fernet import Fernet
    secrets_key = Fernet.generate_key().decode()
except ImportError:
    import base64
    secrets_key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
replacements = {
    "change-me-generate-a-real-64-char-hex-secret": secrets.token_hex(32),
    "change-me-generate-with-fernet": secrets_key,
}
for placeholder, value in replacements.items():
    if placeholder in text:
        text = text.replace(placeholder, value)

with open(path, "w") as f:
    f.write(text)
EOF
}

sync_compose_db_password() {
  # Point the compose DATABASE_URL at the generated POSTGRES_PASSWORD.
  # Both live in the root .env; default example password is `sentinelpass`.
  python3 - <<'EOF'
import re

with open(".env") as f:
    text = f.read()

m = re.search(r"^POSTGRES_PASSWORD=(.+)$", text, re.M)
if not m:
    print("WARN: POSTGRES_PASSWORD not found in .env; leaving DATABASE_URL as-is")
    raise SystemExit
pw = m.group(1).strip()
text = re.sub(
    r"^DATABASE_URL=postgresql://([^:]+):[^@]+@",
    lambda mo: f"DATABASE_URL=postgresql://{mo.group(1)}:{pw}@",
    text,
    flags=re.M,
)
with open(".env", "w") as f:
    f.write(text)
EOF
}

if [ -e .env ]; then
  echo "setup: ./.env already exists -- leaving it untouched."
else
  cp .env.example .env
  chmod 600 .env
  NEW_PW="$(gen_hex 24)"
  # Replace the example postgres password with a generated one.
  python3 -c "
import sys
p = '.env'
t = open(p).read().replace('POSTGRES_PASSWORD=sentinelpass', 'POSTGRES_PASSWORD=' + sys.argv[1])
open(p, 'w').write(t)
" "$NEW_PW"
  inject_placeholders .env
  sync_compose_db_password
  echo "setup: created ./.env (JWT_SECRET + POSTGRES_PASSWORD generated)."
fi
if [ -e backend/.env ]; then
  echo "setup: ./backend/.env already exists -- leaving it untouched."
else
  cp backend/.env.example backend/.env
  chmod 600 backend/.env
  inject_placeholders backend/.env
  echo "setup: created ./backend/.env (JWT_SECRET generated)."
fi

cat <<'EOF'

Next steps:
  1. Local dev:  make migrate   # apply DB migrations
                  make dev       # API on http://localhost:8000
                  # + in other terminals: celery worker, celery beat, frontend (see README)
  2. Compose:     make up        # full stack on http://localhost (needs Docker)
  3. Tests:       make test

IMPORTANT: back up SECRETS_ENCRYPTION_KEY in a password manager now. Losing
it makes stored alert credentials unrecoverable (see README rotation notes).
EOF
