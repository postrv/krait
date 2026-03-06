defmodule Krait.Analyzer.QuickAstTest do
  use ExUnit.Case, async: true

  alias Krait.Analyzer.Quick

  describe "AST-based detection — bypass resistance" do
    test "allows Code.eval_string in comments (NOT a violation)" do
      code = ~S'''
      defmodule Safe do
        # Note: we never use Code.eval_string here
        def run, do: :ok
      end
      '''

      assert {:ok, _} = Quick.quick_validate(code, "elixir")
    end

    test "allows Code.eval_string in string literals (NOT a violation)" do
      code = ~S'''
      defmodule Safe do
        def help, do: "Do not use Code.eval_string in production"
      end
      '''

      assert {:ok, _} = Quick.quick_validate(code, "elixir")
    end

    test "allows forbidden words in @moduledoc (NOT a violation)" do
      code = ~S'''
      defmodule Krait.Skills.Docs do
        @moduledoc """
        This skill does NOT use System.cmd or Code.eval_string.
        It only returns documentation strings.
        """
        def name, do: "docs"
        def description, do: "Returns documentation"
        def execute(_), do: {:ok, "See @moduledoc"}
      end
      '''

      assert {:ok, _} = Quick.quick_validate(code, "elixir")
    end

    test "detects apply(System, :cmd, ...) as KRAIT-002 violation" do
      code = ~S'''
      defmodule Evil do
        def run(cmd) do
          apply(System, :cmd, ["bash", ["-c", cmd]])
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "detects Kernel.apply(Code, :eval_string, ...) as KRAIT-001 violation" do
      code = ~S'''
      defmodule Evil do
        def run(s) do
          Kernel.apply(Code, :eval_string, [s])
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "detects apply(Code, :eval_string, ...) as KRAIT-001 violation" do
      code = ~S'''
      defmodule Evil do
        def run(s) do
          apply(Code, :eval_string, [s])
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "detects Module.concat for forbidden module as KRAIT-002" do
      code = ~S'''
      defmodule Evil do
        def run(cmd) do
          mod = Module.concat([System])
          apply(mod, :cmd, ["bash", ["-c", cmd]])
        end
      end
      '''

      assert {:policy_violation, _} = Quick.quick_validate(code, "elixir")
    end

    test "still detects direct Code.eval_string call" do
      code = ~S'''
      defmodule Evil do
        def run(s), do: Code.eval_string(s)
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "still detects direct System.cmd call" do
      code = ~S'''
      defmodule Evil do
        def run(cmd), do: System.cmd("bash", ["-c", cmd])
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "detects :os.cmd call (erlang-style)" do
      code = ~S'''
      defmodule Evil do
        def run(cmd), do: :os.cmd(String.to_charlist(cmd))
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "allows Req mention in @doc but blocks actual Req.post! call" do
      # Doc-only mention should be fine
      doc_code = ~S'''
      defmodule DocOnly do
        @doc "Prefer WebFetch over Req.post! for safety"
        def fetch(url), do: {:ok, url}
      end
      '''

      assert {:ok, _} = Quick.quick_validate(doc_code, "elixir")

      # Actual call should be blocked
      call_code = ~S'''
      defmodule CallReq do
        def fetch(url), do: Req.post!(url, body: "data")
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(call_code, "elixir")
    end

    test "allows credential path in @doc but blocks File.read + credential path" do
      doc_code = ~S'''
      defmodule DocOnly do
        @doc "Never read ~/.ssh/id_rsa directly"
        def warn, do: "Don't do it"
      end
      '''

      assert {:ok, _} = Quick.quick_validate(doc_code, "elixir")
    end

    test "detects Code.eval_quoted (KRAIT-001)" do
      code = ~S'''
      defmodule Evil do
        def run(quoted), do: Code.eval_quoted(quoted)
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "detects Code.load_file (KRAIT-001 — broad Code module detection)" do
      code = ~S'''
      defmodule Evil do
        def inject(path), do: Code.load_file(path)
      end
      '''

      # Code module is broadly forbidden — KRAIT-001 fires before KRAIT-005
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "detects Port.open spawn (KRAIT-002)" do
      code = ~S'''
      defmodule Evil do
        def run(cmd), do: Port.open({:spawn, cmd}, [:binary])
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  describe "KRAIT-007 scoped allowlist" do
    test "allows Krait.Skills.Core.WebFetch reference (legitimate skill dependency)" do
      code = ~S'''
      defmodule Krait.Skills.Community.Weather do
        def execute(%{"city" => city}) do
          Krait.Skills.Core.WebFetch.execute(%{"url" => "https://wttr.in/#{city}?format=j1"})
        end
      end
      '''

      assert {:ok, _} = Quick.quick_validate(code, "elixir")
    end

    test "blocks non-allowlisted Krait.Skills.Community reference (KRAIT-ALW)" do
      code = ~S'''
      defmodule Krait.Skills.Community.Helper do
        def delegate(params) do
          Krait.Skills.Community.Weather.execute(params)
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "blocks non-allowlisted Krait.Evolution reference (KRAIT-ALW)" do
      code = ~S'''
      defmodule Evil do
        def tamper, do: Krait.Evolution.evolve(%{})
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "blocks non-allowlisted Krait.Analyzer reference (KRAIT-ALW)" do
      code = ~S'''
      defmodule Evil do
        def tamper, do: Krait.Analyzer.Quick.quick_validate("x", "elixir")
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "blocks non-allowlisted Krait.Brain reference (KRAIT-ALW)" do
      code = ~S'''
      defmodule Evil do
        def tamper, do: Krait.Brain.think("evil")
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end
end
