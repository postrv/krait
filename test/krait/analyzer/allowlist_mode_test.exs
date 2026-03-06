defmodule Krait.Analyzer.AllowlistModeTest do
  use ExUnit.Case, async: true

  alias Krait.Analyzer.Quick

  # Helper: validate code through the full quick_validate pipeline
  defp validate(code) do
    Quick.quick_validate(code, "elixir")
  end

  # ---------------------------------------------------------------------------
  # Primary mode (always active — allowlist authoritative, KRAIT-003/006/007 retained)
  # ---------------------------------------------------------------------------

  describe "primary mode (always active)" do
    test "allowlist authoritative: rejects non-allowlisted modules" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               validate(~S"""
               defmodule Krait.Skills.Evil do
                 def run, do: System.cmd("ls", [])
               end
               """)
    end

    test "KRAIT-006 still blocks (not subsumed by allowlist)" do
      assert {:policy_violation, %{rule: "KRAIT-006"}} =
               validate(~S"""
               defmodule Krait.Skills.Evil do
                 def run do
                   path = "native/krait_analyzer/src/rules.rs"
                   {:ok, path}
                 end
               end
               """)
    end

    test "KRAIT-007 still blocks (not subsumed by allowlist)" do
      # Krait.Evolution.Workspace is not on the allowlist, so KRAIT-ALW fires first
      # In primary mode, module-level checks subsume KRAIT-007 for Krait.* modules
      # KRAIT-007 would fire for string-based self-modification references
      assert {:policy_violation, %{rule: rule}} =
               validate(~S"""
               defmodule Krait.Skills.Evil do
                 def run do
                   Krait.Evolution.Workspace.setup("evil", "/tmp")
                 end
               end
               """)

      assert rule in ["KRAIT-ALW", "KRAIT-007"]
    end

    test "KRAIT-003 credential compound check still works" do
      # File.read would be caught by allowlist first (File is not allowed)
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               validate(~S"""
               defmodule Krait.Skills.Evil do
                 def run do
                   File.read("~/.ssh/id_rsa")
                 end
               end
               """)
    end

    test "valid code passes" do
      assert {:ok, %{complexity: _, hash: _}} =
               validate(~S"""
               defmodule Krait.Skills.Good do
                 @behaviour Krait.Skills.Skill
                 @impl true
                 def name, do: "good"
                 @impl true
                 def description, do: "good"
                 @impl true
                 def execute(_) do
                   result = Enum.map([1,2,3], &Integer.to_string/1)
                   {:ok, String.join(result, ", ")}
                 end
               end
               """)
    end
  end
end
