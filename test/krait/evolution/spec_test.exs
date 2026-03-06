defmodule Krait.Evolution.SpecTest do
  use ExUnit.Case, async: true

  describe "new/1" do
    test "creates valid spec from params" do
      assert {:ok, spec} =
               Krait.Evolution.Spec.new(%{
                 skill_name: "bitcoin",
                 description: "Check Bitcoin prices",
                 trigger: "User asked about Bitcoin prices",
                 target_path: "lib/krait/skills/community/bitcoin.ex",
                 test_path: "test/krait/skills/community/bitcoin_test.exs"
               })

      assert spec.skill_name == "bitcoin"
      assert spec.branch_name =~ "krait/evolve-bitcoin-"
    end

    test "rejects spec targeting immutable paths" do
      assert {:error, :immutable_path} =
               Krait.Evolution.Spec.new(%{
                 skill_name: "evil",
                 description: "Modify the analyzer",
                 trigger: "test",
                 target_path: "native/krait_analyzer/src/rules.rs",
                 test_path: "test/evil_test.exs"
               })
    end

    test "rejects spec targeting evolution system itself" do
      assert {:error, :immutable_path} =
               Krait.Evolution.Spec.new(%{
                 skill_name: "evil",
                 description: "Modify evolution",
                 trigger: "test",
                 target_path: "lib/krait/evolution/validator.ex",
                 test_path: "test/evil_test.exs"
               })
    end

    test "rejects spec with path traversal" do
      assert {:error, :immutable_path} =
               Krait.Evolution.Spec.new(%{
                 skill_name: "evil",
                 description: "test",
                 trigger: "test",
                 target_path: "lib/../native/krait_analyzer/src/hack.rs",
                 test_path: "test/evil_test.exs"
               })
    end

    test "rejects spec targeting config" do
      assert {:error, :immutable_path} =
               Krait.Evolution.Spec.new(%{
                 skill_name: "evil",
                 description: "test",
                 trigger: "test",
                 target_path: "config/config.exs",
                 test_path: "test/evil_test.exs"
               })
    end

    test "rejects spec targeting mix.exs" do
      assert {:error, :immutable_path} =
               Krait.Evolution.Spec.new(%{
                 skill_name: "evil",
                 description: "test",
                 trigger: "test",
                 target_path: "mix.exs",
                 test_path: "test/evil_test.exs"
               })
    end
  end
end
