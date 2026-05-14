defmodule Krait.Analyzer.V17SecurityTest do
  use ExUnit.Case, async: true

  alias Krait.Analyzer.Quick
  alias Krait.Skills.Capabilities.FilesystemCap

  # ===========================================================================
  # C-1: Qualified Kernel.func() bypass
  # ===========================================================================

  describe "C-1: Kernel.func() qualified call bypass" do
    test "Kernel.spawn/1 rejected" do
      code = ~S'Kernel.spawn(fn -> :ok end)'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Kernel.spawn_link/1 rejected" do
      code = ~S'Kernel.spawn_link(fn -> :ok end)'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Kernel.send/2 rejected" do
      code = ~S'Kernel.send(pid, :msg)'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Kernel.self/0 rejected" do
      code = ~S'Kernel.self()'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Kernel.exit/1 rejected" do
      code = ~S'Kernel.exit(:normal)'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Kernel.open_port/2 rejected" do
      code = ~S'Kernel.open_port({:spawn, "cmd"}, [])'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Kernel.node/0 rejected" do
      code = ~S'Kernel.node()'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Kernel.div/2 passes (allowed)" do
      code = ~S'Kernel.div(10, 3)'
      assert {:ok, _} = Quick.quick_validate(code, "elixir")
    end

    test "Kernel.is_integer/1 passes (allowed)" do
      code = ~S'Kernel.is_integer(42)'
      assert {:ok, _} = Quick.quick_validate(code, "elixir")
    end
  end

  # ===========================================================================
  # C-2: Compile hooks (@before_compile, @after_compile, @on_load, @on_definition)
  # ===========================================================================

  describe "C-2: compile hooks rejected" do
    test "@before_compile rejected" do
      code = """
      defmodule Evil do
        @before_compile __MODULE__
        def __before_compile__(env), do: :evil
      end
      """

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "@after_compile rejected" do
      code = """
      defmodule Evil do
        @after_compile __MODULE__
        def __after_compile__(env, bytecode), do: :evil
      end
      """

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "@on_load rejected" do
      code = """
      defmodule Evil do
        @on_load :init
        def init, do: :ok
      end
      """

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "@on_definition rejected" do
      code = """
      defmodule Evil do
        @on_definition {__MODULE__, :track}
        def track(_env, _kind, _name, _args, _guards, _body), do: :ok
      end
      """

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "@doc attribute still passes" do
      code = """
      defmodule MySkill do
        @doc "A function"
        def run, do: :ok
      end
      """

      assert {:ok, _} = Quick.quick_validate(code, "elixir")
    end

    test "@behaviour attribute still passes" do
      code = """
      defmodule MySkill do
        @behaviour Krait.Skills.Skill
      end
      """

      assert {:ok, _} = Quick.quick_validate(code, "elixir")
    end
  end

  # ===========================================================================
  # C-3: receive blocks
  # ===========================================================================

  describe "C-3: receive blocks rejected" do
    test "receive do ... end rejected" do
      code = """
      defmodule Evil do
        def spy do
          receive do
            msg -> msg
          end
        end
      end
      """

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "receive with after rejected" do
      code = """
      defmodule Evil do
        def spy do
          receive do
            msg -> msg
          after
            1000 -> :timeout
          end
        end
      end
      """

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  # ===========================================================================
  # C-4: quote/unquote
  # ===========================================================================

  describe "C-4: quote/unquote rejected" do
    test "quote do: ... rejected" do
      code = ~S'quote do: String.upcase("hello")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "quote block rejected" do
      code = """
      defmodule Evil do
        def make_ast do
          quote do
            Enum.map([1, 2], & &1)
          end
        end
      end
      """

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  # ===========================================================================
  # C-5: String.to_atom/1, String.to_existing_atom/1, Stream.resource/run/repeatedly
  # ===========================================================================

  describe "C-5: denied functions on allowed modules" do
    test "String.to_atom rejected" do
      code = ~S'String.to_atom("System")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "String.to_existing_atom rejected" do
      code = ~S'String.to_existing_atom("System")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "String.upcase passes (allowed)" do
      code = ~S'String.upcase("hello")'
      assert {:ok, _} = Quick.quick_validate(code, "elixir")
    end

    test "Stream.resource rejected" do
      code = ~S'Stream.resource(fn -> init end, fn acc -> next end, fn acc -> close end)'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Stream.run rejected" do
      code = ~S'Stream.run(stream)'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Stream.repeatedly rejected" do
      code = ~S'Stream.repeatedly(fn -> :os.timestamp() end)'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Stream.map passes (allowed)" do
      code = ~S'Stream.map([1, 2, 3], & &1 * 2)'
      assert {:ok, _} = Quick.quick_validate(code, "elixir")
    end
  end

  # ===========================================================================
  # C-7: Variable-based dynamic dispatch
  # ===========================================================================

  describe "C-7: variable-based dynamic dispatch" do
    test "m = System; m.cmd() rejected" do
      code = """
      defmodule Evil do
        def run do
          m = System
          m.cmd("ls", [])
        end
      end
      """

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "m = :os; m.cmd() rejected" do
      code = """
      defmodule Evil do
        def run do
          m = :os
          m.cmd(~c"ls")
        end
      end
      """

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "m = Enum; m.map() passes (allowed module)" do
      code = """
      defmodule Safe do
        def run do
          m = Enum
          m.map([1, 2], & &1)
        end
      end
      """

      assert {:ok, _} = Quick.quick_validate(code, "elixir")
    end
  end

  # ===========================================================================
  # H-2: defdelegate paren form
  # ===========================================================================

  describe "H-2: defdelegate paren form" do
    test "defdelegate(func, to: :os) rejected" do
      code = ~S'defdelegate(my_cmd(c), to: :os)'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  # ===========================================================================
  # H-6: Kernel denied list expansion
  # ===========================================================================

  describe "H-6: expanded denied kernel functions" do
    test "binding/0 rejected" do
      code = ~S'binding()'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "dbg/1 rejected" do
      code = ~S'dbg(x)'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "tap/2 rejected" do
      code = ~S'tap(x, fn v -> IO.puts(v) end)'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Kernel.binding/0 rejected" do
      code = ~S'Kernel.binding()'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Kernel.dbg/1 rejected" do
      code = ~S'Kernel.dbg(x)'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  # ===========================================================================
  # M-3: defprotocol/defimpl denied
  # ===========================================================================

  describe "M-3: defprotocol/defimpl denied" do
    test "defprotocol rejected" do
      code = """
      defprotocol MyProtocol do
        def render(data)
      end
      """

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "defimpl rejected" do
      code = """
      defimpl MyProtocol, for: Map do
        def render(data), do: inspect(data)
      end
      """

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  # ===========================================================================
  # M-4: defoverridable denied
  # ===========================================================================

  describe "M-4: defoverridable denied" do
    test "defoverridable rejected" do
      code = """
      defmodule MyMod do
        defoverridable [run: 0]
        def run, do: :default
      end
      """

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  # ===========================================================================
  # M-6: FilesystemCap home-relative paths
  # ===========================================================================

  describe "M-6: FilesystemCap rejects ~/ paths" do
    test "read with ~/ prefix rejected" do
      assert {:error, :forbidden_path} =
               FilesystemCap.read("~/secrets.txt")
    end

    test "list with ~/ prefix rejected" do
      assert {:error, :forbidden_path} =
               FilesystemCap.list("~/.ssh")
    end

    test "read with normal path passes through" do
      # This will fail with a filesystem error, but NOT :forbidden_path
      result = FilesystemCap.read("/nonexistent/path")
      assert result != {:error, :forbidden_path}
    end
  end
end
