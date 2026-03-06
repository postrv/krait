defmodule Krait.Analyzer.PolicyTest do
  use ExUnit.Case, async: true

  alias Krait.Analyzer.Policy

  describe "check_immutable_manifest/1" do
    test "rejects code targeting paths in .krait-immutable" do
      code = ~s[File.write!("native/krait_analyzer/src/rules.rs", "")]
      assert {:rejected, "KRAIT-006", _} = Policy.check_immutable_manifest(code)
    end

    test "rejects code targeting .krait-immutable itself" do
      code = ~s[File.write!(".krait-immutable", "")]
      assert {:rejected, "KRAIT-006", _} = Policy.check_immutable_manifest(code)
    end

    test "rejects code targeting config directory" do
      code = ~s[File.write!("config/config.exs", "")]
      assert {:rejected, "KRAIT-006", _} = Policy.check_immutable_manifest(code)
    end

    test "allows code targeting normal paths" do
      code = ~s[File.write!("lib/krait/skills/bitcoin.ex", code)]
      assert :ok = Policy.check_immutable_manifest(code)
    end
  end

  describe "check_complexity_budget/2" do
    test "passes when delta is within budget" do
      assert :ok = Policy.check_complexity_budget(50, max_delta: 100)
    end

    test "rejects when delta exceeds budget" do
      assert {:rejected, :complexity_exceeded, _} =
               Policy.check_complexity_budget(150, max_delta: 100)
    end

    test "uses default max_delta from config" do
      assert :ok = Policy.check_complexity_budget(50)
    end
  end

  describe "check_dependency_changes/1" do
    test "flags new dependencies for review" do
      diff = %{added: ["req ~> 0.5"], removed: [], changed: []}

      assert {:review_required, :new_dependencies, _} =
               Policy.check_dependency_changes(diff)
    end

    test "passes when no dependency changes" do
      diff = %{added: [], removed: [], changed: []}
      assert :ok = Policy.check_dependency_changes(diff)
    end
  end

  describe "check_target_path/1" do
    test "rejects paths in immutable manifest" do
      assert {:rejected, :immutable_path} =
               Policy.check_target_path("native/krait_analyzer/src/rules.rs")
    end

    test "rejects path traversal attempts" do
      assert {:rejected, :immutable_path} =
               Policy.check_target_path("lib/../native/krait_analyzer/src/hack.rs")
    end

    test "allows normal skill paths" do
      assert :ok = Policy.check_target_path("lib/krait/skills/community/bitcoin.ex")
    end

    test "allows normal test paths" do
      assert :ok = Policy.check_target_path("test/krait/skills/community/bitcoin_test.exs")
    end
  end

  describe "KRAIT rules via Quick Analyzer" do
    test "KRAIT-001: rejects code eval" do
      code = Krait.Test.Fixtures.malicious_code_eval()

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               Krait.Analyzer.Quick.quick_validate(code, "elixir")
    end

    test "KRAIT-002: rejects shell exec" do
      code = Krait.Test.Fixtures.malicious_shell_exec()

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               Krait.Analyzer.Quick.quick_validate(code, "elixir")
    end

    test "KRAIT-003: rejects credential access" do
      code = Krait.Test.Fixtures.malicious_credential_access()

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               Krait.Analyzer.Quick.quick_validate(code, "elixir")
    end

    test "KRAIT-004: rejects raw HTTP clients" do
      code = Krait.Test.Fixtures.malicious_network_exfil()

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               Krait.Analyzer.Quick.quick_validate(code, "elixir")
    end

    test "KRAIT-005: rejects hot code loading (KRAIT-001 — broad Code module detection)" do
      code = Krait.Test.Fixtures.malicious_hot_code_load()

      # Code module is broadly forbidden — KRAIT-001 fires before KRAIT-005
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               Krait.Analyzer.Quick.quick_validate(code, "elixir")
    end

    test "KRAIT-ALW: rejects non-allowlisted File module (immutable path targeting)" do
      code = Krait.Test.Fixtures.malicious_self_modification()

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               Krait.Analyzer.Quick.quick_validate(code, "elixir")
    end

    test "KRAIT-ALW: rejects non-allowlisted Krait.Evolution (internals tampering)" do
      code = ~S'''
      defmodule Krait.Skills.Tamper do
        def hack do
          Krait.Evolution.evolve(%{skill_name: "backdoor"})
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               Krait.Analyzer.Quick.quick_validate(code, "elixir")
    end

    test "valid code passes all KRAIT rules" do
      code = Krait.Test.Fixtures.valid_elixir_module()

      assert {:ok, %{complexity: _, hash: _}} =
               Krait.Analyzer.Quick.quick_validate(code, "elixir")
    end
  end

  describe "load_immutable_manifest/0" do
    test "returns a list of path prefixes" do
      paths = Policy.load_immutable_manifest()
      assert is_list(paths)
      assert "native/" in paths
      assert "config/" in paths
      assert "mix.exs" in paths
    end
  end
end
