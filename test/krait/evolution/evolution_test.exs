defmodule Krait.Evolution.EvolutionTest do
  use ExUnit.Case, async: false

  import Mox

  setup :set_mox_from_context
  setup :verify_on_exit!

  setup do
    previous_max_retries = Application.fetch_env(:krait, :max_evolution_retries)
    Application.put_env(:krait, :max_evolution_retries, 3)

    # Ensure kill switch is not halted from a previous test module
    GenServer.call(Krait.KillSwitch, :reset_for_test)

    on_exit(fn ->
      case previous_max_retries do
        {:ok, value} -> Application.put_env(:krait, :max_evolution_retries, value)
        :error -> Application.delete_env(:krait, :max_evolution_retries)
      end
    end)

    :ok
  end

  describe "evolve/1" do
    test "successful evolution end-to-end" do
      # LLM generates valid code
      Krait.LLM.Mock
      |> expect(:complete, fn _messages, _opts ->
        {:ok,
         Jason.encode!(%{
           code: Krait.Test.Fixtures.valid_elixir_module(),
           test_code: Krait.Test.Fixtures.valid_test_module(),
           reasoning: "Using CoinGecko API"
         })}
      end)

      # Quick validate passes
      Krait.Analyzer.QuickMock
      |> expect(:quick_validate, fn _code, "elixir" ->
        {:ok, %{complexity: 12, hash: "abc123"}}
      end)

      # Deep scan passes
      Krait.Analyzer.DeepMock
      |> expect(:security_scan, fn _path -> {:ok, []} end)
      |> expect(:taint_analysis, fn _fn, _path -> {:ok, []} end)
      |> expect(:call_graph, fn _path -> {:ok, %{edges: []}} end)

      # GitHub operations succeed
      Krait.GitHub.ClientMock
      |> expect(:get_default_branch_sha, fn _repo -> {:ok, "sha123"} end)
      |> expect(:create_branch, fn _repo, _branch, _sha -> {:ok, %{}} end)
      |> expect(:push_files, fn _repo, _branch, _files -> {:ok, %{}} end)
      |> expect(:create_pull_request, fn _repo, _params ->
        {:ok, %{"html_url" => "https://github.com/org/krait/pull/42"}}
      end)

      assert {:ok, result} =
               Krait.Evolution.evolve(%{
                 skill_name: "bitcoin",
                 description: "Check Bitcoin prices",
                 trigger: "User asked about Bitcoin",
                 target_path: "lib/krait/skills/community/bitcoin.ex",
                 test_path: "test/krait/skills/community/bitcoin_test.exs"
               })

      assert result.pr_url =~ "pull/42"
      assert result.attempts == 1
      assert result.draft == false

      # Phase 1.5: Attestation data threaded through for Feed recording
      assert result.ast_hash == "abc123"
      assert result.complexity == 12
      assert result.security_findings == 0
      assert result.taint_flows == 0
    end

    test "retries on validation failure" do
      # LLM called twice
      Krait.LLM.Mock
      |> expect(:complete, 2, fn _messages, _opts ->
        {:ok,
         Jason.encode!(%{
           code: "defmodule M do end",
           test_code: "",
           reasoning: "test"
         })}
      end)

      # First attempt fails, second passes
      Krait.Analyzer.QuickMock
      |> expect(:quick_validate, fn _code, "elixir" ->
        {:syntax_error, [%{line: 1, message: "bad"}]}
      end)
      |> expect(:quick_validate, fn _code, "elixir" ->
        {:ok, %{complexity: 10, hash: "def456"}}
      end)

      Krait.Analyzer.DeepMock
      |> expect(:security_scan, fn _path -> {:ok, []} end)
      |> expect(:taint_analysis, fn _fn, _path -> {:ok, []} end)
      |> expect(:call_graph, fn _path -> {:ok, %{edges: []}} end)

      Krait.GitHub.ClientMock
      |> expect(:get_default_branch_sha, fn _repo -> {:ok, "sha123"} end)
      |> expect(:create_branch, fn _repo, _branch, _sha -> {:ok, %{}} end)
      |> expect(:push_files, fn _repo, _branch, _files -> {:ok, %{}} end)
      |> expect(:create_pull_request, fn _repo, _params ->
        {:ok, %{"html_url" => "https://github.com/org/krait/pull/43"}}
      end)

      assert {:ok, result} =
               Krait.Evolution.evolve(%{
                 skill_name: "test",
                 description: "test",
                 trigger: "test",
                 target_path: "lib/krait/skills/community/test_skill.ex",
                 test_path: "test/krait/skills/community/test_skill_test.exs"
               })

      assert result.attempts == 2
    end

    test "exhausts retries and returns error" do
      # LLM always returns bad code
      Krait.LLM.Mock
      |> expect(:complete, 3, fn _messages, _opts ->
        {:ok,
         Jason.encode!(%{
           code: "bad code",
           test_code: "",
           reasoning: "oops"
         })}
      end)

      # Quick validate always fails
      Krait.Analyzer.QuickMock
      |> expect(:quick_validate, 3, fn _code, "elixir" ->
        {:syntax_error, [%{line: 1, message: "parse error"}]}
      end)

      # Draft PR attempt after retries exhausted
      Krait.GitHub.ClientMock
      |> expect(:get_default_branch_sha, fn _repo -> {:error, :not_configured} end)

      assert {:error, :max_retries_exhausted, info} =
               Krait.Evolution.evolve(%{
                 skill_name: "broken",
                 description: "always fails",
                 trigger: "test",
                 target_path: "lib/krait/skills/community/broken.ex",
                 test_path: "test/krait/skills/community/broken_test.exs"
               })

      assert info.attempts == 3
      assert length(info.errors) == 3
    end

    test "opens draft PR with failure log on exhaustion" do
      # LLM always returns bad code
      Krait.LLM.Mock
      |> expect(:complete, 3, fn _messages, _opts ->
        {:ok,
         Jason.encode!(%{
           code: "bad code",
           test_code: "",
           reasoning: "oops"
         })}
      end)

      # Quick validate always fails
      Krait.Analyzer.QuickMock
      |> expect(:quick_validate, 3, fn _code, "elixir" ->
        {:syntax_error, [%{line: 1, message: "parse error"}]}
      end)

      # Draft PR attempt succeeds
      Krait.GitHub.ClientMock
      |> expect(:get_default_branch_sha, fn _repo -> {:ok, "sha123"} end)
      |> expect(:create_branch, fn _repo, _branch, _sha -> {:ok, %{}} end)
      |> expect(:create_pull_request, fn _repo, params ->
        assert params.draft == true
        assert params.body =~ "Draft Evolution"
        assert params.body =~ "Failure Log"
        assert params.body =~ "syntax_error"
        {:ok, %{"html_url" => "https://github.com/org/krait/pull/99"}}
      end)

      assert {:ok, result} =
               Krait.Evolution.evolve(%{
                 skill_name: "draft_test",
                 description: "tests draft PR",
                 trigger: "test",
                 target_path: "lib/krait/skills/community/draft_test.ex",
                 test_path: "test/krait/skills/community/draft_test_test.exs"
               })

      assert result.draft == true
      assert result.pr_url =~ "pull/99"
      assert result.attempts == 3
    end

    test "evolve/1 returns {:error, :system_halted} when kill switch is engaged" do
      Krait.KillSwitch.halt!("evolution test halt")

      assert {:error, :system_halted} =
               Krait.Evolution.evolve(%{
                 skill_name: "blocked",
                 description: "should be blocked",
                 trigger: "test",
                 target_path: "lib/krait/skills/community/blocked.ex",
                 test_path: "test/krait/skills/community/blocked_test.exs"
               })

      Krait.KillSwitch.resume!()
    end

    test "rejects immutable target paths" do
      assert {:error, :immutable_path} =
               Krait.Evolution.evolve(%{
                 skill_name: "evil",
                 description: "try to modify core",
                 trigger: "test",
                 target_path: "lib/krait/evolution/validator.ex",
                 test_path: "test/krait/evolution/validator_test.exs"
               })
    end

    test "retries on LLM failure then succeeds" do
      # First LLM call fails, second succeeds
      Krait.LLM.Mock
      |> expect(:complete, fn _messages, _opts ->
        {:error, :rate_limited}
      end)
      |> expect(:complete, fn _messages, _opts ->
        {:ok,
         Jason.encode!(%{
           code: Krait.Test.Fixtures.valid_elixir_module(),
           test_code: Krait.Test.Fixtures.valid_test_module(),
           reasoning: "retry worked"
         })}
      end)

      Krait.Analyzer.QuickMock
      |> expect(:quick_validate, fn _code, "elixir" ->
        {:ok, %{complexity: 8, hash: "retry123"}}
      end)

      Krait.Analyzer.DeepMock
      |> expect(:security_scan, fn _path -> {:ok, []} end)
      |> expect(:taint_analysis, fn _fn, _path -> {:ok, []} end)
      |> expect(:call_graph, fn _path -> {:ok, %{edges: []}} end)

      Krait.GitHub.ClientMock
      |> expect(:get_default_branch_sha, fn _repo -> {:ok, "sha123"} end)
      |> expect(:create_branch, fn _repo, _branch, _sha -> {:ok, %{}} end)
      |> expect(:push_files, fn _repo, _branch, _files -> {:ok, %{}} end)
      |> expect(:create_pull_request, fn _repo, _params ->
        {:ok, %{"html_url" => "https://github.com/org/krait/pull/44"}}
      end)

      assert {:ok, result} =
               Krait.Evolution.evolve(%{
                 skill_name: "resilient",
                 description: "handles LLM failures",
                 trigger: "test",
                 target_path: "lib/krait/skills/community/resilient.ex",
                 test_path: "test/krait/skills/community/resilient_test.exs"
               })

      assert result.attempts == 2
      assert result.draft == false
    end
  end
end
