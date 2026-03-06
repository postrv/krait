defmodule Krait.Evolution.DeployerTest do
  use ExUnit.Case, async: false

  import Mox

  setup :set_mox_from_context
  setup :verify_on_exit!

  describe "propose_evolution/1" do
    test "full lifecycle: branch -> write -> PR" do
      validated = %Krait.Evolution.ValidatedProposal{
        code: Krait.Test.Fixtures.valid_elixir_module(),
        test_code: Krait.Test.Fixtures.valid_test_module(),
        ast_hash: "abc123def456",
        complexity: 12,
        security_findings: [],
        taint_flows: [],
        spec: %{
          skill_name: "bitcoin",
          description: "Check Bitcoin prices via CoinGecko API",
          target_path: "lib/krait/skills/community/bitcoin.ex",
          test_path: "test/krait/skills/community/bitcoin_test.exs",
          branch_name: "krait/evolve-bitcoin-1234567"
        }
      }

      Krait.GitHub.ClientMock
      |> expect(:get_default_branch_sha, fn _repo -> {:ok, "sha123"} end)
      |> expect(:create_branch, fn _repo, branch, _sha ->
        assert branch =~ "krait/evolve-bitcoin"
        {:ok, %{}}
      end)
      |> expect(:push_files, fn _repo, _branch, files ->
        assert length(files) == 2
        {:ok, %{}}
      end)
      |> expect(:create_pull_request, fn _repo, params ->
        assert params.title =~ "bitcoin"
        assert params.body =~ "abc123def456"
        assert "krait-evolution" in params.labels
        {:ok, %{"html_url" => "https://github.com/org/krait/pull/42"}}
      end)

      assert {:ok, pr_url} = Krait.Evolution.Deployer.propose_evolution(validated)
      assert pr_url =~ "pull/42"
    end

    test "returns error when get_default_branch_sha fails" do
      validated = %Krait.Evolution.ValidatedProposal{
        code: "defmodule M do end",
        test_code: "",
        ast_hash: "hash",
        complexity: 1,
        security_findings: [],
        taint_flows: [],
        spec: %{
          skill_name: "test",
          target_path: "lib/test.ex",
          test_path: "test/test_test.exs",
          branch_name: "krait/evolve-test-123"
        }
      }

      Krait.GitHub.ClientMock
      |> expect(:get_default_branch_sha, fn _repo -> {:error, :api_error} end)

      assert {:error, :api_error} = Krait.Evolution.Deployer.propose_evolution(validated)
    end

    test "returns error when create_branch fails" do
      validated = %Krait.Evolution.ValidatedProposal{
        code: "defmodule M do end",
        test_code: "",
        ast_hash: "hash",
        complexity: 1,
        security_findings: [],
        taint_flows: [],
        spec: %{
          skill_name: "test",
          target_path: "lib/test.ex",
          test_path: "test/test_test.exs",
          branch_name: "krait/evolve-test-123"
        }
      }

      Krait.GitHub.ClientMock
      |> expect(:get_default_branch_sha, fn _repo -> {:ok, "sha123"} end)
      |> expect(:create_branch, fn _repo, _branch, _sha -> {:error, :branch_exists} end)

      assert {:error, :branch_exists} = Krait.Evolution.Deployer.propose_evolution(validated)
    end

    test "renders PR body with security metadata" do
      validated = %Krait.Evolution.ValidatedProposal{
        code: Krait.Test.Fixtures.valid_elixir_module(),
        test_code: Krait.Test.Fixtures.valid_test_module(),
        ast_hash: "securehash789",
        complexity: 25,
        security_findings: [%{rule: "info-leak"}],
        taint_flows: [%{source: "input", sink: "output"}],
        spec: %{
          skill_name: "risky_skill",
          description: "A skill with some findings",
          target_path: "lib/krait/skills/community/risky.ex",
          test_path: "test/krait/skills/community/risky_test.exs",
          branch_name: "krait/evolve-risky-999"
        }
      }

      Krait.GitHub.ClientMock
      |> expect(:get_default_branch_sha, fn _repo -> {:ok, "sha123"} end)
      |> expect(:create_branch, fn _repo, _branch, _sha -> {:ok, %{}} end)
      |> expect(:push_files, fn _repo, _branch, _files -> {:ok, %{}} end)
      |> expect(:create_pull_request, fn _repo, params ->
        assert params.body =~ "securehash789"
        assert params.body =~ "25"
        assert params.body =~ "Security Findings"
        assert params.body =~ "1"
        {:ok, %{"html_url" => "https://github.com/org/krait/pull/99"}}
      end)

      assert {:ok, _pr_url} = Krait.Evolution.Deployer.propose_evolution(validated)
    end
  end
end
