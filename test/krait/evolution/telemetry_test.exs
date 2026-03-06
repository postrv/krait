defmodule Krait.Evolution.TelemetryTest do
  use ExUnit.Case, async: false

  import Mox

  setup :set_mox_from_context
  setup :verify_on_exit!

  setup do
    # Reset kill switch
    GenServer.call(Krait.KillSwitch, :reset_for_test)
    :ok
  end

  @valid_params %{
    skill_name: "telemetry_test",
    description: "test telemetry emission",
    trigger: "test",
    target_path: "lib/krait/skills/community/telemetry_test.ex",
    test_path: "test/krait/skills/community/telemetry_test_test.exs"
  }

  describe "telemetry events" do
    test "evolve/1 emits [:krait, :evolution, :start] telemetry event" do
      ref = make_ref()
      self_pid = self()
      handler_id = "test-start-#{inspect(ref)}"

      :telemetry.attach(
        handler_id,
        [:krait, :evolution, :start],
        fn event, measurements, metadata, _config ->
          send(self_pid, {:telemetry, ref, event, measurements, metadata})
        end,
        nil
      )

      # LLM fails immediately — we only care about the start event
      Krait.LLM.Mock
      |> expect(:complete, 3, fn _messages, _opts ->
        {:ok, Jason.encode!(%{code: "bad", test_code: "", reasoning: "x"})}
      end)

      Krait.Analyzer.QuickMock
      |> expect(:quick_validate, 3, fn _code, "elixir" ->
        {:syntax_error, [%{line: 1, message: "parse error"}]}
      end)

      Krait.GitHub.ClientMock
      |> expect(:get_default_branch_sha, fn _repo -> {:error, :not_configured} end)

      Krait.Evolution.evolve(@valid_params)

      assert_receive {:telemetry, ^ref, [:krait, :evolution, :start], %{},
                      %{skill_name: "telemetry_test"}},
                     5000

      :telemetry.detach(handler_id)
    end

    test "evolve/1 emits [:krait, :evolution, :complete] on success with duration" do
      ref = make_ref()
      self_pid = self()
      handler_id = "test-complete-#{inspect(ref)}"

      :telemetry.attach(
        handler_id,
        [:krait, :evolution, :complete],
        fn event, measurements, metadata, _config ->
          send(self_pid, {:telemetry, ref, event, measurements, metadata})
        end,
        nil
      )

      Krait.LLM.Mock
      |> expect(:complete, fn _messages, _opts ->
        {:ok,
         Jason.encode!(%{
           code: Krait.Test.Fixtures.valid_elixir_module(),
           test_code: Krait.Test.Fixtures.valid_test_module(),
           reasoning: "good"
         })}
      end)

      Krait.Analyzer.QuickMock
      |> expect(:quick_validate, fn _code, "elixir" ->
        {:ok, %{complexity: 10, hash: "abc"}}
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
        {:ok, %{"html_url" => "https://github.com/org/krait/pull/100"}}
      end)

      {:ok, _} = Krait.Evolution.evolve(@valid_params)

      assert_receive {:telemetry, ^ref, [:krait, :evolution, :complete], %{duration: duration},
                      %{skill_name: "telemetry_test"}},
                     5000

      assert is_integer(duration)
      assert duration > 0

      :telemetry.detach(handler_id)
    end

    test "evolve/1 emits [:krait, :evolution, :failure] on exhausted retries" do
      ref = make_ref()
      self_pid = self()
      handler_id = "test-failure-#{inspect(ref)}"

      :telemetry.attach(
        handler_id,
        [:krait, :evolution, :failure],
        fn event, measurements, metadata, _config ->
          send(self_pid, {:telemetry, ref, event, measurements, metadata})
        end,
        nil
      )

      Krait.LLM.Mock
      |> expect(:complete, 3, fn _messages, _opts ->
        {:ok, Jason.encode!(%{code: "bad", test_code: "", reasoning: "oops"})}
      end)

      Krait.Analyzer.QuickMock
      |> expect(:quick_validate, 3, fn _code, "elixir" ->
        {:syntax_error, [%{line: 1, message: "parse error"}]}
      end)

      Krait.GitHub.ClientMock
      |> expect(:get_default_branch_sha, fn _repo -> {:error, :not_configured} end)

      Krait.Evolution.evolve(@valid_params)

      assert_receive {:telemetry, ^ref, [:krait, :evolution, :failure], %{duration: duration},
                      %{skill_name: "telemetry_test"}},
                     10_000

      assert is_integer(duration)
      assert duration > 0

      :telemetry.detach(handler_id)
    end

    test "evolve/1 does not emit telemetry when kill switch is engaged" do
      ref = make_ref()
      self_pid = self()
      handler_id = "test-halted-#{inspect(ref)}"

      :telemetry.attach(
        handler_id,
        [:krait, :evolution, :start],
        fn event, measurements, metadata, _config ->
          send(self_pid, {:telemetry, ref, event, measurements, metadata})
        end,
        nil
      )

      Krait.KillSwitch.halt!("telemetry test")

      assert {:error, :system_halted} = Krait.Evolution.evolve(@valid_params)
      refute_receive {:telemetry, ^ref, _, _, _}, 200

      :telemetry.detach(handler_id)
    end
  end
end
