defmodule Krait.Analyzer.QuickAstV20Test do
  use ExUnit.Case, async: true

  alias Krait.Analyzer.Quick

  describe "H-1: Allowlist bypass via closures/destructuring" do
    test "Bypass B: tuple destructuring {mod, _} = {:os, :cmd} -> KRAIT-ALW" do
      code = ~S'''
      defmodule Evil do
        def run do
          {mod, _} = {:os, :cmd}
          mod.cmd(~c"whoami")
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Bypass B: list destructuring [mod] = [System] -> KRAIT-ALW" do
      code = ~S'''
      defmodule Evil do
        def run do
          [mod] = [System]
          mod.cmd("whoami", [])
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Bypass C: variable-to-apply x = :os; apply(x, :cmd, args) -> KRAIT-ALW" do
      code = ~S'''
      defmodule Evil do
        def run do
          x = :os
          apply(x, :cmd, [~c"whoami"])
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Bypass C: variable-to-apply x = System; apply(x, :cmd, args) -> KRAIT-ALW" do
      code = ~S'''
      defmodule Evil do
        def run do
          x = System
          apply(x, :cmd, ["whoami", []])
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Bypass D: apply with capture variable -> KRAIT-ALW (catch-all)" do
      code = ~S'''
      defmodule Evil do
        def run(callback) do
          mod = callback.()
          apply(mod, :cmd, [~c"whoami"])
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Bypass E: for-generator with apply -> KRAIT-ALW (catch-all)" do
      code = ~S'''
      defmodule Evil do
        def run do
          for mod <- [:os] do
            apply(mod, :cmd, [~c"whoami"])
          end
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Bypass F: apply(mod, fun, args) all-variables -> KRAIT-ALW (catch-all)" do
      code = ~S'''
      defmodule Evil do
        def run(mod, fun, args) do
          apply(mod, fun, args)
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Bypass G: apply(config.mod, ...) map access -> KRAIT-ALW (catch-all)" do
      code = ~S'''
      defmodule Evil do
        def run(config) do
          apply(config.mod, :cmd, [~c"whoami"])
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "safe: apply(Enum, :map, [...]) literal module passes" do
      code = ~S'''
      defmodule Safe do
        def run do
          apply(Enum, :map, [[1, 2, 3], &(&1 * 2)])
        end
      end
      '''

      assert {:ok, _} = Quick.quick_validate(code, "elixir")
    end

    test "safe: x = Enum; x.map(...) allowlisted module passes" do
      code = ~S'''
      defmodule Safe do
        def run do
          x = Enum
          x.map([1, 2, 3], &(&1 * 2))
        end
      end
      '''

      assert {:ok, _} = Quick.quick_validate(code, "elixir")
    end

    test "safe: apply(:timer, :sleep, [100]) allowlisted Erlang passes" do
      code = ~S'''
      defmodule Safe do
        def run do
          apply(:math, :pow, [2, 10])
        end
      end
      '''

      assert {:ok, _} = Quick.quick_validate(code, "elixir")
    end

    test "Bypass B: tuple second element {_, mod} = {:ok, System} -> KRAIT-ALW" do
      code = ~S'''
      defmodule Evil do
        def run do
          {_, mod} = {:ok, System}
          mod.cmd("whoami", [])
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end
end
