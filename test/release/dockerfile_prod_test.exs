defmodule Krait.Release.DockerfileProdTest do
  use ExUnit.Case, async: true

  @root Path.expand("../..", __DIR__)
  @dockerfile Path.join(@root, "docker/Dockerfile.prod")
  @sandbox_dockerfile Path.join(@root, "docker/Dockerfile.sandbox")
  @deploy_workflow Path.join(@root, ".github/workflows/deploy.yml")
  @compose_prod Path.join(@root, "docker-compose.prod.yml")

  test "production image installs narsil with checksum verification" do
    dockerfile = File.read!(@dockerfile)

    assert dockerfile =~ "ARG NARSIL_VERSION"
    refute dockerfile =~ ~s(ARG NARSIL_VERSION="1.7.0")
    assert dockerfile =~ "ARG NARSIL_SHA256"
    assert dockerfile =~ ~s(ARG NARSIL_EXPECTED_VERSION="1.7.0")
    assert dockerfile =~ "test -n \"${NARSIL_VERSION}\""
    assert dockerfile =~ "test -n \"${NARSIL_SHA256}\""
    assert dockerfile =~ "NARSIL_VERSION must be ${NARSIL_EXPECTED_VERSION}"
    assert dockerfile =~ "narsil-mcp-x86_64-unknown-linux-gnu"
    assert dockerfile =~ "sha256sum -c -"
    assert dockerfile =~ "COPY --from=builder /tmp/narsil-mcp /usr/local/bin/narsil-mcp"
    assert dockerfile =~ "ENV NARSIL_BINARY=/usr/local/bin/narsil-mcp"
  end

  test "tag deploy workflow passes narsil build args" do
    workflow = File.read!(@deploy_workflow)

    assert workflow =~ "Validate release build inputs"
    assert workflow =~ "NARSIL_VERSION: ${{ vars.NARSIL_VERSION }}"
    assert workflow =~ "NARSIL_SHA256: ${{ vars.NARSIL_SHA256 }}"
    assert workflow =~ ~s(NARSIL_EXPECTED_VERSION: "1.7.0")

    assert workflow =~
             ~s(: "${NARSIL_VERSION:?NARSIL_VERSION repository variable is required}")

    assert workflow =~ ~s(: "${NARSIL_SHA256:?NARSIL_SHA256 repository variable is required}")
    assert workflow =~ "NARSIL_VERSION must be ${NARSIL_EXPECTED_VERSION}"
    assert workflow =~ "NARSIL_VERSION=${{ vars.NARSIL_VERSION }}"
    assert workflow =~ "NARSIL_SHA256=${{ vars.NARSIL_SHA256 }}"
  end

  test "production compose exposes narsil binary path to runtime config" do
    compose = File.read!(@compose_prod)

    assert compose =~ "ELIXIR_BASE_DIGEST: ${ELIXIR_BASE_DIGEST:?ELIXIR_BASE_DIGEST is required}"
    assert compose =~ "DEBIAN_BASE_DIGEST: ${DEBIAN_BASE_DIGEST:?DEBIAN_BASE_DIGEST is required}"
    assert compose =~ "NARSIL_VERSION: ${NARSIL_VERSION:?NARSIL_VERSION is required}"
    assert compose =~ "NARSIL_SHA256: ${NARSIL_SHA256:?NARSIL_SHA256 is required}"
    assert compose =~ "NARSIL_BINARY: /usr/local/bin/narsil-mcp"
  end

  test "sandbox image defaults to the current supported narsil release" do
    dockerfile = File.read!(@sandbox_dockerfile)

    assert dockerfile =~ ~s(ARG NARSIL_VERSION="1.7.0")
    refute dockerfile =~ ~s(ARG NARSIL_VERSION="1.5.0")
  end
end
