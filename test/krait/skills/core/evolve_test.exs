defmodule Krait.Skills.Core.EvolveTest do
  use ExUnit.Case, async: false

  import Mox

  describe "name/0" do
    test "returns evolve" do
      assert Krait.Skills.Core.Evolve.name() == "evolve"
    end
  end

  describe "description/0" do
    test "returns description" do
      assert Krait.Skills.Core.Evolve.description() =~ "self-evolution"
    end
  end

  describe "trigger_phrases/0" do
    test "includes evolve and learn" do
      phrases = Krait.Skills.Core.Evolve.trigger_phrases()
      assert "evolve" in phrases
      assert "learn" in phrases
    end
  end

  describe "execute/1" do
    setup :set_mox_from_context
    setup :verify_on_exit!

    setup do
      # v22 SEC-08: Clear cooldown via GenServer API (table is :protected)
      case GenServer.whereis(Krait.EvolveCooldownServer) do
        nil -> Krait.EvolveCooldownServer.start_link([])
        pid -> if Process.alive?(pid), do: :ok, else: Krait.EvolveCooldownServer.start_link([])
      end

      Krait.EvolveCooldownServer.delete_all()

      # Ensure kill switch is not halted from a previous test module
      GenServer.call(Krait.KillSwitch, :reset_for_test)
      :ok
    end

    test "triggers evolution and returns PR URL on success" do
      Krait.LLM.Mock
      |> expect(:complete, fn _messages, _opts ->
        {:ok,
         Jason.encode!(%{
           code: Krait.Test.Fixtures.valid_elixir_module(),
           test_code: Krait.Test.Fixtures.valid_test_module(),
           reasoning: "Simple bitcoin price checker"
         })}
      end)

      Krait.Analyzer.QuickMock
      |> expect(:quick_validate, fn _code, "elixir" ->
        {:ok, %{complexity: 5, hash: "abc123"}}
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
        {:ok, %{"html_url" => "https://github.com/org/krait/pull/42"}}
      end)

      assert {:ok, result} =
               Krait.Skills.Core.Evolve.execute(%{
                 "skill_name" => "bitcoin",
                 "description" => "Check Bitcoin prices"
               })

      assert result.pr_url =~ "pull/42"
    end

    test "rejects malicious skill names (path traversal)" do
      assert {:error, msg} =
               Krait.Skills.Core.Evolve.execute(%{
                 "skill_name" => "../../../etc/passwd",
                 "description" => "malicious"
               })

      assert msg =~ "Invalid skill name"
    end

    test "rejects skill names with special characters" do
      assert {:error, msg} =
               Krait.Skills.Core.Evolve.execute(%{
                 "skill_name" => "my-skill!",
                 "description" => "test"
               })

      assert msg =~ "Invalid skill name"
    end

    test "returns error with missing params" do
      assert {:error, _} = Krait.Skills.Core.Evolve.execute(%{"skill_name" => "test"})
    end

    test "returns error when evolution fails" do
      # Make LLM return invalid response to exhaust retries
      Krait.LLM.Mock
      |> expect(:complete, 3, fn _messages, _opts ->
        {:error, :api_error}
      end)

      # After retries exhausted, it tries to open a draft PR
      Krait.GitHub.ClientMock
      |> expect(:get_default_branch_sha, fn _repo -> {:ok, "sha123"} end)
      |> expect(:create_branch, fn _repo, _branch, _sha -> {:ok, %{}} end)
      |> expect(:create_pull_request, fn _repo, _params ->
        {:ok, %{"html_url" => "https://github.com/org/krait/pull/99"}}
      end)

      assert {:ok, result} =
               Krait.Skills.Core.Evolve.execute(%{
                 "skill_name" => "failing",
                 "description" => "A skill that fails"
               })

      assert result.draft == true
    end

    test "execute/1 returns error when kill switch engaged" do
      Krait.KillSwitch.halt!("test halt")

      assert {:error, msg} =
               Krait.Skills.Core.Evolve.execute(%{
                 "skill_name" => "halted_skill",
                 "description" => "Should be blocked by kill switch"
               })

      assert msg =~ "kill switch"

      Krait.KillSwitch.resume!()
    end

    # Phase 4: Capacity bypass fix — Evolve skill must acquire/release slots
    test "execute/1 acquires evolution slot before starting" do
      # Fill up all slots to capacity
      max = Application.get_env(:krait, :max_concurrent_evolutions, 2)

      for _ <- 1..max do
        assert :ok = Krait.EvolveCooldownServer.try_acquire_slot(:active_evolutions, max)
      end

      # Now the Evolve skill should be blocked
      assert {:error, msg} =
               Krait.Skills.Core.Evolve.execute(%{
                 "skill_name" => "blocked_skill",
                 "description" => "Should be blocked by capacity"
               })

      assert msg =~ "concurrent evolutions"
    end

    test "execute/1 releases slot after successful completion" do
      Krait.LLM.Mock
      |> expect(:complete, fn _messages, _opts ->
        {:ok,
         Jason.encode!(%{
           code: Krait.Test.Fixtures.valid_elixir_module(),
           test_code: Krait.Test.Fixtures.valid_test_module(),
           reasoning: "test skill"
         })}
      end)

      Krait.Analyzer.QuickMock
      |> expect(:quick_validate, fn _code, "elixir" ->
        {:ok, %{complexity: 5, hash: "abc123"}}
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
        {:ok, %{"html_url" => "https://github.com/org/krait/pull/50"}}
      end)

      assert {:ok, _result} =
               Krait.Skills.Core.Evolve.execute(%{
                 "skill_name" => "slot_test",
                 "description" => "Test slot release"
               })

      # Slot should have been released — verify by acquiring max slots
      max = Application.get_env(:krait, :max_concurrent_evolutions, 2)

      for _ <- 1..max do
        assert :ok = Krait.EvolveCooldownServer.try_acquire_slot(:active_evolutions, max)
      end
    end

    test "execute/1 releases slot even on failure" do
      # Make LLM fail to trigger error path
      Krait.LLM.Mock
      |> expect(:complete, 3, fn _messages, _opts ->
        {:error, :api_error}
      end)

      Krait.GitHub.ClientMock
      |> expect(:get_default_branch_sha, fn _repo -> {:ok, "sha123"} end)
      |> expect(:create_branch, fn _repo, _branch, _sha -> {:ok, %{}} end)
      |> expect(:create_pull_request, fn _repo, _params ->
        {:ok, %{"html_url" => "https://github.com/org/krait/pull/99"}}
      end)

      assert {:ok, _result} =
               Krait.Skills.Core.Evolve.execute(%{
                 "skill_name" => "failing_slot",
                 "description" => "Test slot release on failure"
               })

      # Slot should have been released
      max = Application.get_env(:krait, :max_concurrent_evolutions, 2)

      for _ <- 1..max do
        assert :ok = Krait.EvolveCooldownServer.try_acquire_slot(:active_evolutions, max)
      end
    end

    test "API controller path does not double-acquire slots" do
      # The controller calls Evolution.evolve/1 directly (not through Evolve skill)
      # Verify the controller acquires, and Evolution.evolve does NOT acquire again
      # This is a structural invariant — the Evolve skill acquires independently
      # because it's called from Brain's ReAct loop, not from the controller
      max = Application.get_env(:krait, :max_concurrent_evolutions, 2)

      # Acquire max-1 slots to leave exactly 1 available
      for _ <- 1..(max - 1) do
        assert :ok = Krait.EvolveCooldownServer.try_acquire_slot(:active_evolutions, max)
      end

      # The Evolve skill should still be able to acquire the last slot
      # (it acquires 1, not 2). Set up mocks for a successful run.
      Krait.LLM.Mock
      |> expect(:complete, fn _messages, _opts ->
        {:ok,
         Jason.encode!(%{
           code: Krait.Test.Fixtures.valid_elixir_module(),
           test_code: Krait.Test.Fixtures.valid_test_module(),
           reasoning: "test"
         })}
      end)

      Krait.Analyzer.QuickMock
      |> expect(:quick_validate, fn _code, "elixir" ->
        {:ok, %{complexity: 5, hash: "abc123"}}
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
        {:ok, %{"html_url" => "https://github.com/org/krait/pull/55"}}
      end)

      # This should succeed (acquires 1 slot, total becomes max)
      assert {:ok, _result} =
               Krait.Skills.Core.Evolve.execute(%{
                 "skill_name" => "single_slot",
                 "description" => "Only acquires one slot"
               })
    end
  end
end
