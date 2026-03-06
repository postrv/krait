defmodule Krait.Integration.SelfModificationTest do
  use ExUnit.Case, async: true

  @moduletag :integration

  test "agent cannot create specs targeting any immutable path" do
    immutable_paths = Krait.Analyzer.Policy.load_immutable_manifest()

    for path <- immutable_paths do
      # For directory prefixes, append a test file
      target = if String.ends_with?(path, "/"), do: path <> "hack.ex", else: path

      assert {:error, :immutable_path} =
               Krait.Evolution.Spec.new(%{
                 skill_name: "test",
                 description: "test",
                 trigger: "test",
                 target_path: target,
                 test_path: "test/test_test.exs"
               }),
             "Path #{target} should be immutable but wasn't rejected"
    end
  end

  test "path traversal to reach immutable paths is blocked" do
    traversal_attempts = [
      "lib/../native/krait_analyzer/src/hack.rs",
      "lib/../config/config.exs",
      "lib/../.krait-immutable",
      "lib/../mix.exs",
      "test/../native/krait_analyzer/src/lib.rs",
      "lib/krait/skills/../evolution/validator.ex"
    ]

    for path <- traversal_attempts do
      assert {:error, :immutable_path} =
               Krait.Evolution.Spec.new(%{
                 skill_name: "test",
                 description: "test",
                 trigger: "test",
                 target_path: path,
                 test_path: "test/test_test.exs"
               }),
             "Traversal path #{path} should be rejected but wasn't"
    end
  end

  test "valid skill paths are accepted" do
    valid_paths = [
      "lib/krait/skills/community/bitcoin.ex",
      "lib/krait/skills/community/weather.ex",
      "lib/krait/skills/community/new_skill.ex"
    ]

    for path <- valid_paths do
      assert {:ok, _spec} =
               Krait.Evolution.Spec.new(%{
                 skill_name: "test",
                 description: "test",
                 trigger: "test",
                 target_path: path,
                 test_path: "test/krait/skills/community/test_test.exs"
               }),
             "Valid path #{path} was incorrectly rejected"
    end
  end
end
