#!/usr/bin/env bash
set -euo pipefail

# KRAIT Installer
# Kill-switched, Reproducible, Auditable, Intelligent Taskrunner

KRAIT_DIR="${KRAIT_DIR:-$(pwd)/krait}"
REPO_URL="${KRAIT_REPO:-https://github.com/postrv/krait.git}"
KRAIT_REQUIRE_SIGNED_COMMITS="${KRAIT_REQUIRE_SIGNED_COMMITS:-false}"
KRAIT_REQUIRE_DOCKER="${KRAIT_REQUIRE_DOCKER:-false}"
KRAIT_RUN_TESTS="${KRAIT_RUN_TESTS:-false}"
KRAIT_ALLOW_UNLOCKED_DEPS="${KRAIT_ALLOW_UNLOCKED_DEPS:-false}"
KRAIT_ALLOW_DIRTY_UPDATE="${KRAIT_ALLOW_DIRTY_UPDATE:-false}"

echo "=== KRAIT Installer ==="
echo ""

fail() {
    echo "ERROR: $1"
    exit 1
}

warn() {
    echo "WARNING: $1"
}

# Check prerequisites
check_prereq() {
    if ! command -v "$1" &>/dev/null; then
        echo "ERROR: $1 is required but not installed."
        echo "  $2"
        exit 1
    fi
}

check_optional_prereq() {
    if ! command -v "$1" &>/dev/null; then
        if [ "$3" = "true" ]; then
            fail "$1 is required but not installed. $2"
        fi

        warn "$1 not found; $4"
        return 1
    fi

    return 0
}

verify_head_commit() {
    if [ "$KRAIT_REQUIRE_SIGNED_COMMITS" = "true" ]; then
        echo "Verifying commit signature (KRAIT_REQUIRE_SIGNED_COMMITS=true)..."
        if ! git verify-commit HEAD 2>/dev/null; then
            fail "HEAD commit is not signed or signature is invalid."
        fi
        echo "Commit signature verified."
    elif command -v gpg &>/dev/null; then
        echo "Checking commit signature (advisory)..."
        if git verify-commit HEAD 2>/dev/null; then
            echo "Commit signature verified."
        else
            warn "HEAD commit is not GPG-signed; install continues. Set KRAIT_REQUIRE_SIGNED_COMMITS=true to enforce."
        fi
    else
        warn "gpg not found; skipping advisory Git commit signature check."
    fi
}

compute_sha256() {
    if command -v sha256sum &>/dev/null; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum &>/dev/null; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        return 1
    fi
}

find_runtime_nif_binary() {
    for candidate in \
        "priv/native/krait_analyzer.so" \
        "priv/native/libkrait_analyzer.so" \
        "priv/native/libkrait_analyzer.dylib" \
        "priv/native/krait_analyzer.dll" \
        "priv/native/libkrait_analyzer.dll"
    do
        if [ -f "$candidate" ]; then
            echo "$candidate"
            return 0
        fi
    done

    return 1
}

check_prereq "elixir" "Install via https://elixir-lang.org/install.html"
check_prereq "mix" "Comes with Elixir installation"
check_prereq "cargo" "Install Rust via https://rustup.rs"
check_prereq "git" "Install git from https://git-scm.com"
check_optional_prereq \
    "docker" \
    "Install Docker from https://docker.com." \
    "$KRAIT_REQUIRE_DOCKER" \
    "sandbox image build will be skipped unless Docker is installed."

echo "All prerequisites found."
echo ""

# Clone or update
if [ -d "$KRAIT_DIR" ]; then
    echo "Updating existing KRAIT installation..."
    cd "$KRAIT_DIR"

    if [ ! -d ".git" ]; then
        fail "$KRAIT_DIR exists but is not a git checkout. Set KRAIT_DIR to a clean install path."
    fi

    if [ -n "$(git status --porcelain)" ] && [ "$KRAIT_ALLOW_DIRTY_UPDATE" != "true" ]; then
        fail "existing KRAIT checkout has local changes. Commit/stash them, or set KRAIT_ALLOW_DIRTY_UPDATE=true."
    fi

    git pull --ff-only
    verify_head_commit
else
    echo "Cloning KRAIT..."
    git clone "$REPO_URL" "$KRAIT_DIR"
    cd "$KRAIT_DIR"
    verify_head_commit
fi

echo ""
echo "Installing dependencies..."
# v27 M-7: Use --check-locked to verify deps match lockfile
if ! mix deps.get --check-locked; then
    if [ "$KRAIT_ALLOW_UNLOCKED_DEPS" = "true" ]; then
        warn "deps.get --check-locked failed; KRAIT_ALLOW_UNLOCKED_DEPS=true permits fallback to deps.get."
        mix deps.get
    else
        fail "dependency resolution changed from mix.lock. Refusing unlocked install; set KRAIT_ALLOW_UNLOCKED_DEPS=true only for local development."
    fi
fi

echo ""
echo "Auditing dependencies..."
if ! mix hex.audit; then
    if [ "${KRAIT_REQUIRE_AUDIT_CLEAN:-false}" = "true" ]; then
        fail "dependency audit failed."
    fi

    warn "Some dependencies have known vulnerabilities."
fi

echo ""
echo "Compiling NIF..."
cd native/krait_analyzer
# v27 M-7: Use --locked to ensure Cargo.lock is respected
cargo build --release --locked
cd ../..

echo ""
echo "Compiling Elixir..."
mix compile --warnings-as-errors

echo ""
echo "Recording runtime NIF SHA256..."
if NIF_BINARY=$(find_runtime_nif_binary); then
    if NIF_HASH=$(compute_sha256 "$NIF_BINARY"); then
        echo "NIF binary: $NIF_BINARY"
        echo "NIF SHA256: $NIF_HASH"
        echo "$NIF_HASH" > "${NIF_BINARY}.sha256"
        echo "Hash saved to ${NIF_BINARY}.sha256"

        if [ -n "${KRAIT_NIF_EXPECTED_HASH:-}" ]; then
            if [ "$NIF_HASH" = "$KRAIT_NIF_EXPECTED_HASH" ]; then
                echo "NIF hash verification PASSED"
            else
                echo "ERROR: NIF hash mismatch!"
                echo "  Expected: $KRAIT_NIF_EXPECTED_HASH"
                echo "  Got:      $NIF_HASH"
                exit 1
            fi
        fi
    else
        warn "Could not compute NIF binary checksum; install continues without a sidecar hash."
    fi
else
    fail "compiled runtime NIF was not found under priv/native."
fi

echo ""
echo "Setting up database..."
if mix ecto.create; then
    echo "Database created."
else
    echo "Database already exists or could not be created; running migrations to verify connectivity."
fi
mix ecto.migrate

echo ""
echo "Building sandbox Docker image..."
if command -v docker &>/dev/null; then
    if docker build --no-cache -t krait-sandbox -f docker/Dockerfile.sandbox .; then
        echo "Sandbox Docker image built."
    elif [ "$KRAIT_REQUIRE_DOCKER" = "true" ]; then
        fail "Docker sandbox image build failed."
    else
        warn "Docker sandbox image build failed; install continues, but sandbox setup validation will warn."
    fi
else
    warn "Docker not available; sandbox Docker image build skipped."
fi

echo ""
echo "Running setup validation..."
mix krait.setup_validate --log-level info --checks nif,narsil,sandbox_image,github_auth,llm,admin_auth,kill_switch

echo ""
if [ "$KRAIT_RUN_TESTS" = "true" ]; then
    echo "Running full test suite (KRAIT_RUN_TESTS=true)..."
    mix test
else
    echo "Skipping full test suite during install."
    echo "  CI runs the release gate; set KRAIT_RUN_TESTS=true to run all tests locally."
fi

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
