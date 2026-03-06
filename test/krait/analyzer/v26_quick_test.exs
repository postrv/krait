defmodule Krait.Analyzer.V26QuickTest do
  use ExUnit.Case, async: true

  alias Krait.Analyzer.Quick

  # ---------------------------------------------------------------------------
  # Phase 6: M-7 — Code Size Limit
  # ---------------------------------------------------------------------------
  describe "quick_validate code size limit (M-7)" do
    test "rejects code larger than 1MB" do
      # Generate code > 1MB
      large_code = String.duplicate("x = 1\n", 200_000)
      assert byte_size(large_code) > 1_048_576

      assert {:error, %{reason: :code_too_large}} = Quick.quick_validate(large_code, "elixir")
    end

    test "accepts code under 1MB" do
      small_code = "defmodule Foo do\n  def bar, do: :ok\nend\n"
      assert byte_size(small_code) < 1_048_576

      result = Quick.quick_validate(small_code, "elixir")
      assert {:ok, %{complexity: _, hash: _}} = result
    end

    test "error includes size and max" do
      large_code = String.duplicate("x = 1\n", 200_000)

      assert {:error, %{reason: :code_too_large, size: size, max: 1_048_576}} =
               Quick.quick_validate(large_code, "elixir")

      assert size == byte_size(large_code)
    end
  end

  # ---------------------------------------------------------------------------
  # Phase 6: M-8 — Multi-Segment Module Attribute Indirection
  # ---------------------------------------------------------------------------
  describe "multi-segment module attribute detection (M-8)" do
    test "detects @target Some.Deep.Module used as indirection" do
      # Using a multi-segment module alias that contains a forbidden module
      code = ~S"""
      defmodule Evil do
        @target Elixir.System
        def run do
          @target.cmd("ls", [])
        end
      end
      """

      assert {:policy_violation, _} = Quick.quick_validate(code, "elixir")
    end

    test "3-level attribute chain resolution (@a → @b → @c)" do
      code = ~S"""
      defmodule Evil do
        @a :os
        @b @a
        @c @b
        def run do
          @c.cmd(~c"ls")
        end
      end
      """

      assert {:policy_violation, _} = Quick.quick_validate(code, "elixir")
    end
  end
end
