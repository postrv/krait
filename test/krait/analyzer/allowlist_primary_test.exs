defmodule Krait.Analyzer.AllowlistPrimaryTest do
  use ExUnit.Case, async: true

  alias Krait.Analyzer.Quick

  describe "primary mode end-to-end via quick_validate/2" do
    test "valid skill code passes through full pipeline" do
      code = ~S"""
      defmodule Krait.Skills.Bitcoin do
        @behaviour Krait.Skills.Skill
        @impl true
        def name, do: "bitcoin"
        @impl true
        def description, do: "Check Bitcoin prices"
        @impl true
        def execute(%{action: "price"}) do
          case Krait.Skills.Core.WebFetch.execute(%{"url" => "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd"}) do
            {:ok, %{body: body}} -> {:ok, %{price: body["bitcoin"]["usd"]}}
            {:error, reason} -> {:error, reason}
          end
        end
      end
      """

      assert {:ok, %{complexity: complexity, hash: hash}} = Quick.quick_validate(code, "elixir")
      assert complexity > 0
      assert is_binary(hash)
    end

    test "non-allowlisted module returns KRAIT-ALW" do
      code = ~S"""
      defmodule Krait.Skills.Evil do
        def run, do: System.cmd("ls", [])
      end
      """

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "KRAIT-006 immutable path still blocks" do
      code = ~S"""
      defmodule Krait.Skills.Evil do
        def run do
          path = "native/krait_analyzer/src/rules.rs"
          {:ok, path}
        end
      end
      """

      assert {:policy_violation, %{rule: "KRAIT-006"}} = Quick.quick_validate(code, "elixir")
    end

    test "complexity and hash still computed for passing code" do
      code = ~S"""
      defmodule Krait.Skills.Simple do
        @behaviour Krait.Skills.Skill
        @impl true
        def name, do: "simple"
        @impl true
        def description, do: "simple"
        @impl true
        def execute(_), do: {:ok, Enum.map([1,2,3], & &1 * 2)}
      end
      """

      assert {:ok, %{complexity: c, hash: h}} = Quick.quick_validate(code, "elixir")
      assert c > 0
      assert String.length(h) > 0
    end

    test "CapableSkill code passes" do
      code = ~S"""
      defmodule Krait.Skills.MyCapSkill do
        @behaviour Krait.Skills.CapableSkill
        @impl true
        def name, do: "my_cap"
        @impl true
        def description, do: "test"
        @impl true
        def required_capabilities, do: [:network]
        @impl true
        def execute(_params, caps) do
          caps.network.fetch("https://example.com")
        end
      end
      """

      assert {:ok, _} = Quick.quick_validate(code, "elixir")
    end
  end
end
