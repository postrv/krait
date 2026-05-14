defmodule Krait.Release.InstallScriptTest do
  use ExUnit.Case, async: true

  @script File.read!("install.sh")

  test "full ExUnit suite is opt-in during installation" do
    assert @script =~ "KRAIT_RUN_TESTS"
    assert @script =~ "Skipping full test suite during install"
    assert @script =~ "KRAIT_RUN_TESTS=true"

    refute @script =~
             ~r/\n\s*mix test\s*\n\s*echo ""\n\s*echo "=== KRAIT installed successfully ==="/
  end

  test "NIF hash is recorded from the runtime binary, not a loose build wildcard" do
    assert @script =~ "find_runtime_nif_binary"
    assert @script =~ "priv/native/krait_analyzer.so"
    assert @script =~ ~s(echo "$NIF_HASH" > "${NIF_BINARY}.sha256")

    refute @script =~ "target/release/libkrait_analyzer.*"
    refute @script =~ "libkrait_analyzer.sha256"
  end

  test "installer does not silently fall back from locked dependency resolution" do
    assert @script =~ "KRAIT_ALLOW_UNLOCKED_DEPS"
    assert @script =~ "mix deps.get --check-locked"
    assert @script =~ "Refusing unlocked install"
  end

  test "installer performs advisory or enforced commit signature verification after checkout" do
    assert @script =~ "verify_head_commit"
    assert @script =~ "KRAIT_REQUIRE_SIGNED_COMMITS"
    assert @script =~ "git verify-commit HEAD"
  end
end
