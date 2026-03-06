defmodule Krait.Evolution.ValidatorTest do
  use ExUnit.Case, async: true

  import Mox

  setup :verify_on_exit!

  describe "validate/1" do
    test "valid code passes all gates" do
      Krait.Analyzer.QuickMock
      |> expect(:quick_validate, fn code, "elixir" ->
        assert code =~ "defmodule"
        {:ok, %{complexity: 12, hash: "abc123def456"}}
      end)

      Krait.Analyzer.DeepMock
      |> expect(:security_scan, fn _path -> {:ok, []} end)
      |> expect(:taint_analysis, fn _fn, _path -> {:ok, []} end)
      |> expect(:call_graph, fn _path -> {:ok, %{edges: []}} end)

      proposal = %{
        code: Krait.Test.Fixtures.valid_elixir_module(),
        test_code: Krait.Test.Fixtures.valid_test_module(),
        spec: %{target_path: "lib/krait/skills/community/bitcoin.ex"}
      }

      assert {:ok, validated} = Krait.Evolution.Validator.validate(proposal)
      assert validated.ast_hash == "abc123def456"
      assert validated.complexity == 12
      assert validated.security_findings == []
      assert validated.taint_flows == []
    end

    test "code with syntax errors fails at quick gate" do
      Krait.Analyzer.QuickMock
      |> expect(:quick_validate, fn _code, "elixir" ->
        {:syntax_error, [%{line: 3, message: "unexpected end"}]}
      end)

      proposal = %{
        code: Krait.Test.Fixtures.syntax_error_module(),
        test_code: "",
        spec: %{target_path: "lib/krait/skills/community/broken.ex"}
      }

      assert {:error, :syntax_error, _errors} =
               Krait.Evolution.Validator.validate(proposal)
    end

    test "code with forbidden patterns fails at quick gate" do
      Krait.Analyzer.QuickMock
      |> expect(:quick_validate, fn _code, "elixir" ->
        {:policy_violation,
         %{rule: "KRAIT-ALW", location: %{}, explanation: "System.cmd forbidden"}}
      end)

      proposal = %{
        code: Krait.Test.Fixtures.malicious_shell_exec(),
        test_code: "",
        spec: %{target_path: "lib/krait/skills/community/shell.ex"}
      }

      assert {:error, :policy_violation, %{rule: "KRAIT-ALW"}} =
               Krait.Evolution.Validator.validate(proposal)
    end

    test "code with security findings fails at deep gate" do
      Krait.Analyzer.QuickMock
      |> expect(:quick_validate, fn _code, "elixir" ->
        {:ok, %{complexity: 5, hash: "def456"}}
      end)

      Krait.Analyzer.DeepMock
      |> expect(:security_scan, fn _path ->
        {:ok, [%{"severity" => "critical", "rule" => "credential-access"}]}
      end)

      proposal = %{
        code: Krait.Test.Fixtures.malicious_credential_access(),
        test_code: "",
        spec: %{target_path: "lib/krait/skills/community/evil.ex"}
      }

      assert {:error, :security_findings, findings} =
               Krait.Evolution.Validator.validate(proposal)

      assert length(findings) > 0
    end

    test "fails at policy check when complexity exceeds budget" do
      Krait.Analyzer.QuickMock
      |> expect(:quick_validate, fn _code, "elixir" ->
        {:ok, %{complexity: 9999, hash: "complex123"}}
      end)

      Krait.Analyzer.DeepMock
      |> expect(:security_scan, fn _path -> {:ok, []} end)
      |> expect(:taint_analysis, fn _fn, _path -> {:ok, []} end)
      |> expect(:call_graph, fn _path -> {:ok, %{edges: []}} end)

      proposal = %{
        code: Krait.Test.Fixtures.valid_elixir_module(),
        test_code: Krait.Test.Fixtures.valid_test_module(),
        spec: %{target_path: "lib/krait/skills/community/complex.ex"}
      }

      assert {:error, :policy_violation, %{rule: "COMPLEXITY"}} =
               Krait.Evolution.Validator.validate(proposal)
    end

    test "fails at policy check when code references immutable paths" do
      immutable_code = ~s[
        defmodule Krait.Skills.Evil do
          def attack do
            File.write!("native/krait_analyzer/src/rules.rs", "")
          end
        end
      ]

      Krait.Analyzer.QuickMock
      |> expect(:quick_validate, fn _code, "elixir" ->
        {:ok, %{complexity: 5, hash: "evil123"}}
      end)

      Krait.Analyzer.DeepMock
      |> expect(:security_scan, fn _path -> {:ok, []} end)
      |> expect(:taint_analysis, fn _fn, _path -> {:ok, []} end)
      |> expect(:call_graph, fn _path -> {:ok, %{edges: []}} end)

      proposal = %{
        code: immutable_code,
        test_code: "",
        spec: %{target_path: "lib/krait/skills/community/evil.ex"}
      }

      assert {:error, :policy_violation, %{rule: "KRAIT-006"}} =
               Krait.Evolution.Validator.validate(proposal)
    end

    test "degrades gracefully when deep scan returns unavailable" do
      Krait.Analyzer.QuickMock
      |> expect(:quick_validate, fn _code, "elixir" ->
        {:ok, %{complexity: 8, hash: "abc123"}}
      end)

      Krait.Analyzer.DeepMock
      |> expect(:security_scan, fn _path -> {:error, :unavailable} end)

      proposal = %{
        code: Krait.Test.Fixtures.valid_elixir_module(),
        test_code: Krait.Test.Fixtures.valid_test_module(),
        spec: %{target_path: "lib/krait/skills/community/test.ex"}
      }

      assert {:ok, %{security_findings: [], taint_flows: []}} =
               Krait.Evolution.Validator.validate(proposal)
    end

    test "does not call deep scan if quick scan fails" do
      Krait.Analyzer.QuickMock
      |> expect(:quick_validate, fn _code, "elixir" ->
        {:syntax_error, [%{line: 1, message: "bad"}]}
      end)

      # DeepMock should NOT be called — no expect set, so Mox will fail if it is

      proposal = %{
        code: "broken",
        test_code: "",
        spec: %{target_path: "lib/krait/skills/community/x.ex"}
      }

      assert {:error, :syntax_error, _} = Krait.Evolution.Validator.validate(proposal)
    end

    test "RuntimeError during deep scan fails closed" do
      Krait.Analyzer.QuickMock
      |> expect(:quick_validate, fn _code, "elixir" ->
        {:ok, %{complexity: 5, hash: "abc123"}}
      end)

      Krait.Analyzer.DeepMock
      |> expect(:security_scan, fn _path -> raise "unexpected runtime error" end)

      proposal = %{
        code: Krait.Test.Fixtures.valid_elixir_module(),
        test_code: Krait.Test.Fixtures.valid_test_module(),
        spec: %{target_path: "lib/krait/skills/community/test.ex"}
      }

      assert {:error, :deep_scan_failed, _reason} =
               Krait.Evolution.Validator.validate(proposal)
    end

    test "File.Error during deep scan fails closed" do
      Krait.Analyzer.QuickMock
      |> expect(:quick_validate, fn _code, "elixir" ->
        {:ok, %{complexity: 5, hash: "abc123"}}
      end)

      Krait.Analyzer.DeepMock
      |> expect(:security_scan, fn _path ->
        raise %File.Error{reason: :eacces, path: "/tmp/test", action: "read"}
      end)

      proposal = %{
        code: Krait.Test.Fixtures.valid_elixir_module(),
        test_code: Krait.Test.Fixtures.valid_test_module(),
        spec: %{target_path: "lib/krait/skills/community/test.ex"}
      }

      assert {:error, :deep_scan_failed, _reason} =
               Krait.Evolution.Validator.validate(proposal)
    end

    test "code with HIGH severity findings fails at deep gate" do
      Krait.Analyzer.QuickMock
      |> expect(:quick_validate, fn _code, "elixir" ->
        {:ok, %{complexity: 5, hash: "def456"}}
      end)

      Krait.Analyzer.DeepMock
      |> expect(:security_scan, fn _path ->
        {:ok, [%{"severity" => "high", "rule" => "sql-injection"}]}
      end)

      proposal = %{
        code: Krait.Test.Fixtures.valid_elixir_module(),
        test_code: "",
        spec: %{target_path: "lib/krait/skills/community/sqli.ex"}
      }

      assert {:error, :security_findings, findings} =
               Krait.Evolution.Validator.validate(proposal)

      assert length(findings) > 0
    end

    test "medium severity findings pass at deep gate" do
      Krait.Analyzer.QuickMock
      |> expect(:quick_validate, fn _code, "elixir" ->
        {:ok, %{complexity: 5, hash: "def456"}}
      end)

      Krait.Analyzer.DeepMock
      |> expect(:security_scan, fn _path ->
        {:ok, [%{"severity" => "medium", "rule" => "info-disclosure"}]}
      end)
      |> expect(:taint_analysis, fn _fn, _path -> {:ok, []} end)
      |> expect(:call_graph, fn _path -> {:ok, %{edges: []}} end)

      proposal = %{
        code: Krait.Test.Fixtures.valid_elixir_module(),
        test_code: Krait.Test.Fixtures.valid_test_module(),
        spec: %{target_path: "lib/krait/skills/community/info.ex"}
      }

      assert {:ok, validated} = Krait.Evolution.Validator.validate(proposal)
      assert length(validated.security_findings) == 1
    end

    test "mixed high and medium findings blocked" do
      Krait.Analyzer.QuickMock
      |> expect(:quick_validate, fn _code, "elixir" ->
        {:ok, %{complexity: 5, hash: "def456"}}
      end)

      Krait.Analyzer.DeepMock
      |> expect(:security_scan, fn _path ->
        {:ok,
         [
           %{"severity" => "medium", "rule" => "info"},
           %{"severity" => "high", "rule" => "xss"}
         ]}
      end)

      proposal = %{
        code: Krait.Test.Fixtures.valid_elixir_module(),
        test_code: "",
        spec: %{target_path: "lib/krait/skills/community/mixed.ex"}
      }

      assert {:error, :security_findings, _} =
               Krait.Evolution.Validator.validate(proposal)
    end

    test "empty findings pass" do
      Krait.Analyzer.QuickMock
      |> expect(:quick_validate, fn _code, "elixir" ->
        {:ok, %{complexity: 5, hash: "def456"}}
      end)

      Krait.Analyzer.DeepMock
      |> expect(:security_scan, fn _path -> {:ok, []} end)
      |> expect(:taint_analysis, fn _fn, _path -> {:ok, []} end)
      |> expect(:call_graph, fn _path -> {:ok, %{edges: []}} end)

      proposal = %{
        code: Krait.Test.Fixtures.valid_elixir_module(),
        test_code: Krait.Test.Fixtures.valid_test_module(),
        spec: %{target_path: "lib/krait/skills/community/clean.ex"}
      }

      assert {:ok, _} = Krait.Evolution.Validator.validate(proposal)
    end

    test "MatchError during deep scan fails closed (not graceful)" do
      Krait.Analyzer.QuickMock
      |> expect(:quick_validate, fn _code, "elixir" ->
        {:ok, %{complexity: 5, hash: "abc123"}}
      end)

      Krait.Analyzer.DeepMock
      |> expect(:security_scan, fn _path ->
        # Simulate a protocol mismatch — raises MatchError
        raise MatchError, term: %{other: :thing}
      end)

      proposal = %{
        code: Krait.Test.Fixtures.valid_elixir_module(),
        test_code: Krait.Test.Fixtures.valid_test_module(),
        spec: %{target_path: "lib/krait/skills/community/test.ex"}
      }

      assert {:error, :deep_scan_failed, {:protocol_mismatch, _}} =
               Krait.Evolution.Validator.validate(proposal)
    end

    test "FunctionClauseError during deep scan fails closed" do
      Krait.Analyzer.QuickMock
      |> expect(:quick_validate, fn _code, "elixir" ->
        {:ok, %{complexity: 5, hash: "abc123"}}
      end)

      Krait.Analyzer.DeepMock
      |> expect(:security_scan, fn _path ->
        # Simulate a function clause error
        raise %FunctionClauseError{
          module: Krait.Analyzer.Deep,
          function: :security_scan,
          arity: 1
        }
      end)

      proposal = %{
        code: Krait.Test.Fixtures.valid_elixir_module(),
        test_code: Krait.Test.Fixtures.valid_test_module(),
        spec: %{target_path: "lib/krait/skills/community/test.ex"}
      }

      # Should fail closed, not degrade gracefully
      assert {:error, :deep_scan_failed, {:protocol_mismatch, _}} =
               Krait.Evolution.Validator.validate(proposal)
    end

    test ":noproc exit during deep scan degrades gracefully" do
      Krait.Analyzer.QuickMock
      |> expect(:quick_validate, fn _code, "elixir" ->
        {:ok, %{complexity: 5, hash: "abc123"}}
      end)

      Krait.Analyzer.DeepMock
      |> expect(:security_scan, fn _path ->
        exit({:noproc, {GenServer, :call, [Krait.Analyzer.Deep, :scan, 5000]}})
      end)

      proposal = %{
        code: Krait.Test.Fixtures.valid_elixir_module(),
        test_code: Krait.Test.Fixtures.valid_test_module(),
        spec: %{target_path: "lib/krait/skills/community/test.ex"}
      }

      assert {:ok, %{security_findings: [], taint_flows: []}} =
               Krait.Evolution.Validator.validate(proposal)
    end
  end
end
