defmodule Krait.Analyzer.V25SecurityTest do
  use ExUnit.Case, async: true

  alias Krait.Analyzer.Quick

  # ===========================================================================
  # L-2: Multi-step variable reassignment detection
  # ===========================================================================

  describe "L-2: variable reassignment chains" do
    test "a = :os; b = a; b.cmd() rejected" do
      code = """
      defmodule Evil do
        def run do
          a = :os
          b = a
          b.cmd(~c"ls")
        end
      end
      """

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "a = System; b = a; b.cmd() rejected" do
      code = """
      defmodule Evil do
        def run do
          a = System
          b = a
          b.cmd("ls", [])
        end
      end
      """

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "a = Enum; b = a; b.map() passes (allowed module)" do
      code = """
      defmodule Safe do
        def run do
          a = Enum
          b = a
          b.map([1, 2], & &1)
        end
      end
      """

      assert {:ok, _} = Quick.quick_validate(code, "elixir")
    end

    test "three-step chain: a = :os; b = a; c = b; c.cmd() rejected" do
      code = """
      defmodule Evil do
        def run do
          a = :os
          b = a
          c = b
          c.cmd(~c"ls")
        end
      end
      """

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  # ===========================================================================
  # L-3: Multi-segment module attribute aliases
  # ===========================================================================

  describe "L-3: module attribute alias chains" do
    test "@a :os; @b @a; apply(@b, :cmd, []) rejected" do
      code = """
      defmodule Evil do
        @a :os
        @b @a

        def run do
          apply(@b, :cmd, [[~c"ls"]])
        end
      end
      """

      assert {:policy_violation, _} = Quick.quick_validate(code, "elixir")
    end

    test "@base System; @target @base; @target.cmd() rejected" do
      code = """
      defmodule Evil do
        @base System
        @target @base

        def run do
          @target.cmd("ls", [])
        end
      end
      """

      assert {:policy_violation, _} = Quick.quick_validate(code, "elixir")
    end
  end

  # ===========================================================================
  # M-4: Exact domain match in allowlist
  # ===========================================================================

  describe "M-4: exact domain match" do
    test "subdomain of allowlisted domain is rejected" do
      # With exact match, "api.github.com" when "github.com" is in the allowlist
      # should be rejected (no subdomain inference)
      original = Application.get_env(:krait, :network_allowlist)
      Application.put_env(:krait, :network_allowlist, ["github.com"])

      on_exit(fn ->
        if original,
          do: Application.put_env(:krait, :network_allowlist, original),
          else: Application.delete_env(:krait, :network_allowlist)
      end)

      assert {:error, msg} =
               Krait.Skills.Core.WebFetch.execute(%{
                 "url" => "https://api.github.com/repos"
               })

      assert msg =~ "not in domain allowlist"
    end
  end
end
