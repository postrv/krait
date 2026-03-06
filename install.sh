#!/usr/bin/env bash
set -euo pipefail

# KRAIT Installer
# Kill-switched, Reproducible, Auditable, Intelligent Taskrunner

KRAIT_DIR="${KRAIT_DIR:-$(pwd)/krait}"
REPO_URL="${KRAIT_REPO:-https://github.com/postrv/krait.git}"

echo "=== KRAIT Installer ==="
echo ""

# Check prerequisites
check_prereq() {
    if ! command -v "$1" &>/dev/null; then
        echo "ERROR: $1 is required but not installed."
        echo "  $2"
        exit 1
    fi
}

check_prereq "elixir" "Install via https://elixir-lang.org/install.html"
check_prereq "mix" "Comes with Elixir installation"
check_prereq "cargo" "Install Rust via https://rustup.rs"
check_prereq "git" "Install git from https://git-scm.com"
check_prereq "docker" "Install Docker from https://docker.com (optional for sandbox)"

echo "All prerequisites found."
echo ""

# Clone or update
if [ -d "$KRAIT_DIR" ]; then
    echo "Updating existing KRAIT installation..."
    cd "$KRAIT_DIR"
    git pull --rebase

    # v27 M-7: Verify commit signature if GPG is available
    if [ "${KRAIT_REQUIRE_SIGNED_COMMITS:-false}" = "true" ]; then
        echo "Verifying commit signature (KRAIT_REQUIRE_SIGNED_COMMITS=true)..."
        if ! git verify-commit HEAD 2>/dev/null; then
            echo "ERROR: HEAD commit is not signed or signature is invalid!"
            echo "  Set KRAIT_REQUIRE_SIGNED_COMMITS=false to skip this check."
            exit 1
        fi
        echo "Commit signature verified."
    elif command -v gpg &>/dev/null; then
        echo "Checking commit signature (advisory)..."
        if git verify-commit HEAD 2>/dev/null; then
            echo "Commit signature verified."
        else
            echo "WARNING: HEAD commit is not signed. Set KRAIT_REQUIRE_SIGNED_COMMITS=true to enforce."
        fi
    fi
else
    echo "Cloning KRAIT..."
    git clone "$REPO_URL" "$KRAIT_DIR"
    cd "$KRAIT_DIR"
fi

echo ""
echo "Installing dependencies..."
# v27 M-7: Use --check-locked to verify deps match lockfile
mix deps.get --check-locked || {
    echo "WARNING: deps.get --check-locked failed, falling back to deps.get"
    mix deps.get
}

echo ""
echo "Auditing dependencies..."
mix hex.audit || echo "WARNING: Some dependencies have known vulnerabilities"

echo ""
echo "Compiling NIF..."
cd native/krait_analyzer
# v27 M-7: Use --locked to ensure Cargo.lock is respected
cargo build --release --locked

# v24 F-23: Record and verify NIF binary SHA256
echo "Computing NIF binary SHA256..."
NIF_HASH=""
if command -v sha256sum &>/dev/null; then
    NIF_HASH=$(sha256sum target/release/libkrait_analyzer.* 2>/dev/null | head -1)
elif command -v shasum &>/dev/null; then
    NIF_HASH=$(shasum -a 256 target/release/libkrait_analyzer.* 2>/dev/null | head -1)
fi

if [ -n "$NIF_HASH" ]; then
    echo "NIF SHA256: $NIF_HASH"
    echo "$NIF_HASH" > target/release/libkrait_analyzer.sha256
    echo "Hash saved to target/release/libkrait_analyzer.sha256"
else
    echo "WARNING: Could not compute NIF binary checksum"
fi

# Verify against known-good hash if provided
if [ -n "${KRAIT_NIF_EXPECTED_HASH:-}" ]; then
    ACTUAL=$(echo "$NIF_HASH" | awk '{print $1}')
    if [ "$ACTUAL" = "$KRAIT_NIF_EXPECTED_HASH" ]; then
        echo "NIF hash verification PASSED"
    else
        echo "ERROR: NIF hash mismatch!"
        echo "  Expected: $KRAIT_NIF_EXPECTED_HASH"
        echo "  Got:      $ACTUAL"
        exit 1
    fi
fi
cd ../..

echo ""
echo "Compiling Elixir..."
mix compile

echo ""
echo "Setting up database..."
mix ecto.create 2>/dev/null || true
mix ecto.migrate

echo ""
echo "Building sandbox Docker image..."
docker build --no-cache -t krait-sandbox -f docker/Dockerfile.sandbox . 2>/dev/null || \
    echo "Docker build skipped (Docker not available or failed)"

echo ""
echo "Running tests..."
mix test

echo ""
echo "=== KRAIT installed successfully ==="
echo ""
echo "Quick start:"
echo "  cd $KRAIT_DIR"
echo "  export OPENROUTER_API_KEY=your-key"
echo "  mix phx.server"
echo ""
echo "Configuration:"
echo "  GitHub App: Set GITHUB_APP_ID, GITHUB_PRIVATE_KEY_PATH, GITHUB_INSTALLATION_ID"
echo "  Telegram:   Set TELEGRAM_BOT_TOKEN"
echo ""
