defmodule Krait.Analyzer.AllowlistEscapeTest do
  @moduledoc """
  Phase 6: Adversarial allowlist escape tests.

  26+ attack vectors organized in categories A through L, plus positive tests.
  Every adversarial test MUST produce {:policy_violation, %{rule: "KRAIT-ALW"}}.
  """
  use ExUnit.Case, async: true

  alias Krait.Analyzer.Quick

  # ===========================================================================
  # A: Metaprogramming escapes
  # ===========================================================================

  describe "A: Metaprogramming escapes" do
    test "A-1: String.to_existing_atom to construct forbidden module name" do
      code = ~S'''
      defmodule Escape do
        def hack do
          mod = Enum.join(["Sys", "tem"], "") |> String.to_existing_atom()
          mod.cmd("whoami", [])
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "A-2: Module.concat to build forbidden module (not on allowlist)" do
      code = ~S'''
      defmodule Escape do
        def hack do
          mod = Module.concat([:System])
          mod.cmd("whoami", [])
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "A-3: defmacro attempt to generate forbidden code at compile time" do
      code = ~S'''
      defmodule Escape do
        defmacro evil do
          quote do
            System.cmd("whoami", [])
          end
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  # ===========================================================================
  # B: Protocol/behaviour exploitation
  # ===========================================================================

  describe "B: Protocol/behaviour exploitation" do
    test "B-1: defprotocol is banned" do
      code = ~S'''
      defprotocol Escapable do
        @doc "Escape the sandbox"
        def escape(data)
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "B-2: defimpl is banned" do
      code = ~S'''
      defimpl String.Chars, for: Atom do
        def to_string(atom), do: Atom.to_string(atom)
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  # ===========================================================================
  # C: Erlang interop via non-allowed modules
  # ===========================================================================

  describe "C: Erlang interop via non-allowed modules" do
    test "C-1: :erlang.list_to_atom not on allowlist" do
      code = ~S'''
      defmodule Escape do
        def hack do
          mod = :erlang.list_to_atom(~c"os")
          mod.cmd(~c"whoami")
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "C-2: :os.cmd direct call not on allowlist" do
      code = ~S'''
      defmodule Escape do
        def hack do
          :os.cmd(~c"whoami")
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "C-3: :erlang.binary_to_atom not on allowlist" do
      code = ~S'''
      defmodule Escape do
        def hack do
          mod = :erlang.binary_to_atom("os", :utf8)
          mod.cmd(~c"id")
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  # ===========================================================================
  # D: Capability escape via non-allowed OTP modules
  # ===========================================================================

  describe "D: Capability escape via non-allowed OTP modules" do
    test "D-1: Process module not on allowlist" do
      code = ~S'''
      defmodule Escape do
        def hack do
          Process.flag(:trap_exit, true)
          Process.send_after(self(), :tick, 1000)
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "D-2: Agent module not on allowlist" do
      code = ~S'''
      defmodule Escape do
        def hack do
          {:ok, agent} = Agent.start_link(fn -> %{} end)
          Agent.update(agent, fn state -> Map.put(state, :evil, true) end)
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  # ===========================================================================
  # E: Compile-time side effects
  # ===========================================================================

  describe "E: Compile-time side effects" do
    test "E-1: Module attribute with File.read! (File not on allowlist)" do
      code = ~S'''
      defmodule Escape do
        @secret_fn fn -> File.read!("/etc/passwd") end
        def hack, do: @secret_fn.()
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "E-2: @before_compile banned compile hook" do
      code = ~S'''
      defmodule Escape do
        @before_compile __MODULE__

        def __before_compile__(_env) do
          :evil
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "E-3: @on_load banned compile hook" do
      code = ~S'''
      defmodule Escape do
        @on_load :init

        def init do
          :ok
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  # ===========================================================================
  # F: Stream/Enum resource exhaustion via denied functions
  # ===========================================================================

  describe "F: Stream denied functions" do
    test "F-1: Stream.iterate is denied on allowed Stream module" do
      code = ~S'''
      defmodule Escape do
        def hack do
          Stream.iterate(0, &(&1 + 1))
          |> Enum.take(1_000_000)
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "F-2: Stream.resource is denied" do
      code = ~S'''
      defmodule Escape do
        def hack do
          Stream.resource(
            fn -> 0 end,
            fn n -> {[n], n + 1} end,
            fn _ -> :ok end
          )
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "F-3: Stream.unfold is denied" do
      code = ~S'''
      defmodule Escape do
        def hack do
          Stream.unfold(1, fn n -> {n, n + 1} end)
          |> Enum.take(100)
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  # ===========================================================================
  # G: Kernel.apply indirect invocation
  # ===========================================================================

  describe "G: Kernel.apply indirect invocation" do
    test "G-1: bare apply/3 is a denied Kernel function" do
      code = ~S'''
      defmodule Escape do
        def hack do
          apply(System, :cmd, ["whoami", []])
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "G-2: Kernel.apply/3 explicit call" do
      code = ~S'''
      defmodule Escape do
        def hack do
          Kernel.apply(System, :cmd, ["whoami", []])
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "G-3: apply with atom module arguments (:os)" do
      code = ~S'''
      defmodule Escape do
        def hack do
          apply(:os, :cmd, [~c"whoami"])
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  # ===========================================================================
  # H: Process dictionary abuse
  # ===========================================================================

  describe "H: Process dictionary abuse" do
    test "H-1: Process.put not on allowlist" do
      code = ~S'''
      defmodule Escape do
        def hack do
          Process.put(:secret, "exfiltrated_data")
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "H-2: Process.get not on allowlist" do
      code = ~S'''
      defmodule Escape do
        def hack do
          Process.get(:secret)
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  # ===========================================================================
  # I: Module attribute code loading
  # ===========================================================================

  describe "I: Module attribute code loading" do
    test "I-1: @on_load banned compile attribute" do
      code = ~S'''
      defmodule Escape do
        @on_load :load_nif

        def load_nif do
          :ok
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "I-2: @after_compile banned compile attribute" do
      code = ~S'''
      defmodule Escape do
        @after_compile __MODULE__

        def __after_compile__(_env, _bytecode) do
          :evil
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  # ===========================================================================
  # J: Comprehension side effects with non-allowed modules
  # ===========================================================================

  describe "J: Comprehension side effects" do
    test "J-1: for comprehension calling System.cmd" do
      code = ~S'''
      defmodule Escape do
        def hack do
          for cmd <- ["whoami", "id"] do
            System.cmd(cmd, [])
          end
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "J-2: for comprehension with File.read!" do
      code = ~S'''
      defmodule Escape do
        def hack do
          for path <- ["/etc/passwd", "/etc/shadow"] do
            File.read!(path)
          end
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  # ===========================================================================
  # K: Binary/atom construction to bypass module checks
  # ===========================================================================

  describe "K: Binary pattern matching for atom construction" do
    test "K-1: :erlang.binary_to_atom not on allowlist" do
      code = ~S'''
      defmodule Escape do
        def hack do
          mod = :erlang.binary_to_atom("os", :utf8)
          mod.cmd(~c"id")
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "K-2: String.to_atom denied on allowed String module" do
      code = ~S'''
      defmodule Escape do
        def hack do
          mod = String.to_atom("System")
          mod.cmd("whoami", [])
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  # ===========================================================================
  # L: Recursion / resource exhaustion
  # ===========================================================================

  describe "L: Recursion and resource exhaustion" do
    test "L-1: pure recursion is allowed (sandbox mitigates resource exhaustion)" do
      code = ~S'''
      defmodule DeepRecurse do
        def fib(0), do: 0
        def fib(1), do: 1
        def fib(n) when is_integer(n) and n > 1 do
          fib(n - 1) + fib(n - 2)
        end
      end
      '''

      assert {:ok, %{complexity: _, hash: _}} = Quick.quick_validate(code, "elixir")
    end

    test "L-2: recursion with allowed modules is fine (resource exhaustion mitigated by sandbox)" do
      code = ~S'''
      defmodule ListBuilder do
        def build(0, acc), do: acc
        def build(n, acc) when n > 0 do
          build(n - 1, [Enum.random(1..100) | acc])
        end
      end
      '''

      assert {:ok, %{complexity: _, hash: _}} = Quick.quick_validate(code, "elixir")
    end
  end

  # ===========================================================================
  # Additional attack vectors
  # ===========================================================================

  describe "Additional: receive and quote special forms" do
    test "receive block is banned" do
      code = ~S'''
      defmodule Escape do
        def hack do
          receive do
            {:msg, data} -> data
          after
            5000 -> :timeout
          end
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "quote block is banned" do
      code = ~S'''
      defmodule Escape do
        def hack do
          ast = quote do
            System.cmd("whoami", [])
          end
          ast
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  describe "Additional: defoverridable is banned" do
    test "defoverridable rejected" do
      code = ~S'''
      defmodule Escape do
        def execute(_), do: :ok
        defoverridable execute: 1
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  describe "Additional: variable-based dynamic dispatch" do
    test "variable bound to forbidden module then called via dot" do
      code = ~S'''
      defmodule Escape do
        def hack do
          m = System
          m.cmd("whoami", [])
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "variable bound to forbidden erlang module then called" do
      code = ~S'''
      defmodule Escape do
        def hack do
          m = :os
          m.cmd(~c"whoami")
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  describe "Additional: capture shorthand and delegation" do
    test "capture shorthand &File.read!/1 rejected" do
      code = ~S'''
      defmodule Escape do
        def hack do
          fun = &File.read!/1
          fun.("/etc/passwd")
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "defdelegate to forbidden module" do
      code = ~S'''
      defmodule Escape do
        defdelegate run(cmd, args), to: System, as: :cmd
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  describe "Additional: non-allowed networking and IO modules" do
    test "IO module not on allowlist" do
      code = ~S'''
      defmodule Escape do
        def hack do
          IO.puts("exfiltrating data to stdout")
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Task module not on allowlist" do
      code = ~S'''
      defmodule Escape do
        def hack do
          Task.async(fn -> :evil end)
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  # ===========================================================================
  # Positive tests: code that SHOULD pass
  # ===========================================================================

  describe "Positive: valid code passes the allowlist" do
    test "pure Enum/Map/String computation" do
      code = ~S'''
      defmodule PureCompute do
        def run(data) do
          data
          |> Enum.filter(fn {_k, v} -> v > 0 end)
          |> Enum.map(fn {k, v} -> {String.upcase(k), v * 2} end)
          |> Map.new()
          |> Jason.encode!()
        end
      end
      '''

      assert {:ok, %{complexity: _, hash: _}} = Quick.quick_validate(code, "elixir")
    end

    test "using allowed Krait.Skills modules" do
      code = ~S'''
      defmodule Krait.Skills.MySkill do
        @behaviour Krait.Skills.Skill
        @impl true
        def name, do: "my_skill"
        @impl true
        def description, do: "A safe skill"
        @impl true
        def execute(params) do
          result = Enum.map(params, fn {k, v} -> {k, String.downcase(v)} end)
          {:ok, Map.new(result)}
        end
      end
      '''

      assert {:ok, %{complexity: _, hash: _}} = Quick.quick_validate(code, "elixir")
    end

    test "pattern matching, guards, and safe erlang modules" do
      code = ~S'''
      defmodule SafeCode do
        def compute(x) when is_number(x) and x > 0 do
          result = :math.pow(x, 2)
          rounded = Float.round(result, 2)
          Integer.to_string(trunc(rounded))
        end

        def compute(_), do: "0"
      end
      '''

      assert {:ok, %{complexity: _, hash: _}} = Quick.quick_validate(code, "elixir")
    end
  end
end
