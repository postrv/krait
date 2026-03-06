#!/bin/bash
set -e

# KRAIT Quickstart Entrypoint
# Auto-generates secrets if not provided, runs migrations, seeds demo data.

gen_secret() {
  openssl rand -base64 $(($1 * 2)) | tr -d '\n/+=' | head -c "$1"
}

# Auto-generate secrets if not set
export SECRET_KEY_BASE="${SECRET_KEY_BASE:-$(gen_secret 64)}"
export SESSION_SIGNING_SALT="${SESSION_SIGNING_SALT:-$(gen_secret 32)}"
export SESSION_ENCRYPTION_SALT="${SESSION_ENCRYPTION_SALT:-$(gen_secret 32)}"
export LIVE_VIEW_SALT="${LIVE_VIEW_SALT:-$(gen_secret 32)}"
export ADMIN_SESSION_SALT="${ADMIN_SESSION_SALT:-$(gen_secret 32)}"
export KRAIT_API_TOKEN="${KRAIT_API_TOKEN:-$(gen_secret 48)}"
export KRAIT_ADMIN_TOKEN="${KRAIT_ADMIN_TOKEN:-$(gen_secret 48)}"

echo ""
echo "=== KRAIT Quickstart ==="
echo ""
echo "Admin dashboard: http://localhost:4000/admin/login"
echo "Admin token:     ${KRAIT_ADMIN_TOKEN}"
echo "API token:       ${KRAIT_API_TOKEN}"
echo ""
echo "========================"
echo ""

# Run migrations
echo "[quickstart] Running migrations..."
bin/krait eval "Krait.Release.migrate()"

# Seed demo data
echo "[quickstart] Seeding demo data..."
bin/krait eval "Krait.Release.seed()"

echo "[quickstart] Starting KRAIT server..."
exec bin/krait start
