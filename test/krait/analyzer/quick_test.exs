defmodule Krait.Analyzer.QuickTest do
  use ExUnit.Case, async: true

  alias Krait.Test.Fixtures

  describe "quick_validate/2 — syntax checking" do
    test "accepts valid Elixir module" do
      assert {:ok, %{complexity: _, hash: hash}} =
               Krait.Analyzer.Quick.quick_validate(Fixtures.valid_elixir_module(), "elixir")

      assert is_binary(hash)
      assert String.length(hash) == 64
    end

    test "rejects module with syntax errors" do
      assert {:syntax_error, errors} =
               Krait.Analyzer.Quick.quick_validate(Fixtures.syntax_error_module(), "elixir")

      assert length(errors) > 0
      assert hd(errors).line > 0
      assert is_binary(hd(errors).message)
    end
  end

  describe "quick_validate/2 — forbidden patterns" do
    test "rejects Code.eval_string (KRAIT-001)" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               Krait.Analyzer.Quick.quick_validate(Fixtures.malicious_code_eval(), "elixir")
    end

    test "rejects System.cmd (KRAIT-002)" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               Krait.Analyzer.Quick.quick_validate(Fixtures.malicious_shell_exec(), "elixir")
    end

    test "rejects credential path access (KRAIT-003)" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               Krait.Analyzer.Quick.quick_validate(
                 Fixtures.malicious_credential_access(),
                 "elixir"
               )
    end

    test "rejects hot code loading (KRAIT-001 — broad Code module detection)" do
      # Code module is broadly forbidden — KRAIT-001 fires before KRAIT-005
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               Krait.Analyzer.Quick.quick_validate(Fixtures.malicious_hot_code_load(), "elixir")
    end

    test "rejects non-allowlisted File module (KRAIT-ALW, immutable path targeting)" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               Krait.Analyzer.Quick.quick_validate(
                 Fixtures.malicious_self_modification(),
                 "elixir"
               )
    end

    test "rejects raw HTTP client usage (KRAIT-004)" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               Krait.Analyzer.Quick.quick_validate(Fixtures.malicious_network_exfil(), "elixir")
    end
  end

  describe "quick_validate/2 — complexity" do
    test "reports complexity score" do
      assert {:ok, %{complexity: complexity}} =
               Krait.Analyzer.Quick.quick_validate(Fixtures.valid_elixir_module(), "elixir")

      assert is_integer(complexity)
      assert complexity > 0
    end

    test "high-complexity module reports high score" do
      assert {:ok, %{complexity: complexity}} =
               Krait.Analyzer.Quick.quick_validate(Fixtures.high_complexity_module(), "elixir")

      assert complexity > 20
    end
  end

  describe "quick_validate/2 — hashing" do
    test "same code produces same hash" do
      code = Fixtures.valid_elixir_module()
      {:ok, %{hash: hash1}} = Krait.Analyzer.Quick.quick_validate(code, "elixir")
      {:ok, %{hash: hash2}} = Krait.Analyzer.Quick.quick_validate(code, "elixir")
      assert hash1 == hash2
    end

    test "different code produces different hash" do
      {:ok, %{hash: hash1}} = Krait.Analyzer.Quick.quick_validate("def a, do: 1", "elixir")
      {:ok, %{hash: hash2}} = Krait.Analyzer.Quick.quick_validate("def b, do: 2", "elixir")
      assert hash1 != hash2
    end
  end
end
