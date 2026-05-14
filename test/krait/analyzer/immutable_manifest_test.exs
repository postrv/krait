defmodule Krait.Analyzer.ImmutableManifestTest do
  use ExUnit.Case, async: true

  @manifest_path Path.join(File.cwd!(), ".krait-immutable")

  @required_paths [
    "native/",
    ".github/",
    "lib/krait/analyzer/",
    "lib/krait/evolution/validator.ex",
    "lib/krait/evolution/deployer.ex",
    "lib/krait/sandbox/",
    "config/",
    "mix.exs",
    "lib/krait/skills/capable_skill.ex",
    "lib/krait/skills/capability_injector.ex",
    "lib/krait/skills/capabilities/",
    "lib/krait/analyzer/allowlist.ex",
    "lib/krait/brain/",
    "lib/krait/gateway/",
    "lib/krait/llm/",
    "lib/krait/skills/core/",
    "lib/krait/github/",
    "lib/krait/application.ex",
    "lib/krait/evolution/evolution.ex",
    "lib/krait/evolution/naming.ex",
    "lib/krait/security/",
    "lib/krait_web/"
  ]

  test "manifest contains all security-critical paths" do
    assert File.exists?(@manifest_path), ".krait-immutable manifest must exist"

    manifest_lines =
      @manifest_path
      |> File.read!()
      |> String.split("\n", trim: true)
      |> Enum.reject(&String.starts_with?(&1, "#"))
      |> MapSet.new()

    for required <- @required_paths do
      assert MapSet.member?(manifest_lines, required),
             "Missing immutable path: #{required}"
    end
  end
end
