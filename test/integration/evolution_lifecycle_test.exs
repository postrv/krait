defmodule Krait.Integration.EvolutionLifecycleTest do
  use ExUnit.Case, async: false

  @moduletag :integration

  import Mox

  setup :set_mox_from_context
  setup :verify_on_exit!

  @tag timeout: 120_000
  test "end-to-end: user request -> code generation -> validation -> PR" do
    # Use real Quick analyzer (Elixir fallback), mock Deep and GitHub
    # Override quick analyzer to use real implementation
    original_quick = Application.get_env(:krait, :analyzer_quick)
    Application.put_env(:krait, :analyzer_quick, Krait.Analyzer.Quick)
    on_exit(fn -> Application.put_env(:krait, :analyzer_quick, original_quick) end)

    # LLM generates valid code
    Krait.LLM.Mock
    |> expect(:complete, fn _messages, _opts ->
      {:ok,
       Jason.encode!(%{
         code: Krait.Test.Fixtures.valid_elixir_module(),
         test_code: Krait.Test.Fixtures.valid_test_module(),
         reasoning: "Using CoinGecko free API"
       })}
    end)

    # Deep scan passes
    Krait.Analyzer.DeepMock
    |> expect(:security_scan, fn _path -> {:ok, []} end)
    |> expect(:taint_analysis, fn _fn, _path -> {:ok, []} end)
    |> expect(:call_graph, fn _path -> {:ok, %{edges: []}} end)

    # GitHub operations succeed
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
      # PR body should contain analysis metadata
      assert params.body =~ "AST Hash"
      assert params.body =~ "Complexity"
      assert params.body =~ "Security Findings"
      {:ok, %{"html_url" => "https://github.com/org/krait/pull/99"}}
    end)

    assert {:ok, result} =
             Krait.Evolution.evolve(%{
               skill_name: "bitcoin",
               description: "Check Bitcoin prices",
               trigger: "User asked about Bitcoin",
               target_path: "lib/krait/skills/community/bitcoin.ex",
               test_path: "test/krait/skills/community/bitcoin_test.exs"
             })

    assert result.pr_url =~ "pull/99"
    assert result.attempts == 1
    assert result.draft == false
  end
end
