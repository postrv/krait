defmodule Krait.Sandbox.DockerBackendTest do
  use ExUnit.Case, async: false

  alias Krait.Sandbox.DockerBackend

  describe "init/1" do
    @describetag :docker_required
    test "initializes with default configuration" do
      {:ok, state} = DockerBackend.init([])

      assert %DockerBackend{} = state
      assert state.image == "elixir:1.17-otp-27-slim"
      assert state.memory_mb == 2048
      assert state.cpus == 2
      assert state.boot_timeout == 30_000
      assert state.network == "none"
      assert state.env == %{}
      assert state.container_id == nil
    end

    test "initializes with custom configuration" do
      {:ok, state} =
        DockerBackend.init(
          image: "elixir:1.17",
          memory_mb: 4096,
          cpus: 4,
          env: %{"MIX_ENV" => "test"},
          network: "bridge"
        )

      assert state.image == "elixir:1.17"
      assert state.memory_mb == 4096
      assert state.cpus == 4
      assert state.env == %{"MIX_ENV" => "test"}
      assert state.network == "bridge"
    end

    test "creates a parent_ref on init" do
      {:ok, state} = DockerBackend.init([])
      assert is_reference(state.parent_ref)
    end

    test "rejects invalid options" do
      assert_raise ArgumentError, ~r/unknown keys/, fn ->
        DockerBackend.init(invalid_option: true)
      end
    end

    test "accepts valid Docker image names" do
      assert {:ok, _} = DockerBackend.init(image: "elixir:1.17-otp-27-slim")
      assert {:ok, _} = DockerBackend.init(image: "myregistry.io/foo/bar:latest")
      assert {:ok, _} = DockerBackend.init(image: "ubuntu")
    end

    test "rejects invalid Docker image names" do
      assert_raise ArgumentError, ~r/invalid Docker image/, fn ->
        DockerBackend.init(image: "'; rm -rf /")
      end

      assert_raise ArgumentError, ~r/invalid Docker image/, fn ->
        DockerBackend.init(image: "../escape")
      end

      assert_raise ArgumentError, ~r/invalid Docker image/, fn ->
        DockerBackend.init(image: "")
      end
    end
  end

  describe "remote_spawn_monitor/2" do
    @describetag :docker_required

    test "spawns and monitors a zero-arity function" do
      {:ok, state} = DockerBackend.init([])

      {:ok, {pid, ref}} = DockerBackend.remote_spawn_monitor(state, fn -> :ok end)

      assert is_pid(pid)
      assert is_reference(ref)
    end

    test "spawns and monitors an MFA tuple" do
      {:ok, state} = DockerBackend.init([])

      {:ok, {pid, ref}} =
        DockerBackend.remote_spawn_monitor(state, {Kernel, :send, [self(), :hello]})

      assert is_pid(pid)
      assert is_reference(ref)
      assert_receive :hello, 1_000
    end

    test "raises on invalid term" do
      {:ok, state} = DockerBackend.init([])

      assert_raise ArgumentError, ~r/expected a zero-arity function/, fn ->
        DockerBackend.remote_spawn_monitor(state, :not_a_function)
      end
    end
  end

  describe "system_shutdown/0" do
    @describetag :docker_required

    test "does not raise" do
      # system_shutdown/0 calls System.stop() which we cannot safely test
      # in a unit test, but we verify the function exists with the correct arity.
      assert function_exported?(DockerBackend, :system_shutdown, 0)
    end
  end

  describe "handle_info/2" do
    @describetag :docker_required

    test "handles unexpected messages gracefully" do
      {:ok, state} = DockerBackend.init([])

      assert {:noreply, ^state} = DockerBackend.handle_info(:unexpected, state)
    end

    test "handles remote_shutdown message" do
      {:ok, state} = DockerBackend.init([])
      ref = state.parent_ref

      assert {:stop, {:remote_shutdown, :idle}, _new_state} =
               DockerBackend.handle_info({ref, {:remote_shutdown, :idle}}, state)
    end
  end

  describe "filter_env/1" do
    test "allows safe env keys" do
      env = %{
        "MIX_ENV" => "test",
        "LANG" => "en_US.UTF-8",
        "PATH" => "/usr/bin",
        "HOME" => "/root",
        "TERM" => "xterm"
      }

      result = DockerBackend.filter_env(env)
      assert result == env
    end

    test "strips secret keys" do
      env = %{
        "MIX_ENV" => "test",
        "SECRET_KEY_BASE" => "supersecret",
        "ANTHROPIC_API_KEY" => "sk-ant-...",
        "OPENROUTER_API_KEY" => "sk-or-...",
        "GITHUB_TOKEN" => "ghp_...",
        "RELEASE_COOKIE" => "cookie",
        "AWS_SECRET_ACCESS_KEY" => "AKIA..."
      }

      result = DockerBackend.filter_env(env)
      assert result == %{"MIX_ENV" => "test"}
    end

    test "only allowed keys pass through in mixed env" do
      env = %{
        "MIX_ENV" => "test",
        "LANG" => "en_US.UTF-8",
        "SECRET_KEY_BASE" => "supersecret",
        "DATABASE_URL" => "ecto://...",
        "KRAIT_API_TOKEN" => "tok123"
      }

      result = DockerBackend.filter_env(env)
      assert result == %{"MIX_ENV" => "test", "LANG" => "en_US.UTF-8"}
    end

    test "returns empty map for all-secret input" do
      env = %{
        "SECRET_KEY_BASE" => "x",
        "DATABASE_URL" => "y",
        "ANTHROPIC_API_KEY" => "z"
      }

      result = DockerBackend.filter_env(env)
      assert result == %{}
    end
  end

  describe "struct" do
    @describetag :docker_required

    test "has expected fields" do
      state = %DockerBackend{}

      assert Map.has_key?(state, :image)
      assert Map.has_key?(state, :memory_mb)
      assert Map.has_key?(state, :cpus)
      assert Map.has_key?(state, :env)
      assert Map.has_key?(state, :container_id)
      assert Map.has_key?(state, :container_name)
      assert Map.has_key?(state, :boot_timeout)
      assert Map.has_key?(state, :network)
      assert Map.has_key?(state, :runner_node_name)
      assert Map.has_key?(state, :remote_terminator_pid)
      assert Map.has_key?(state, :parent_ref)
      assert Map.has_key?(state, :terminator_sup)
      assert Map.has_key?(state, :log)
    end
  end

  describe "build_container_args/2" do
    test "includes security hardening flags" do
      state = %DockerBackend{
        memory_mb: 2048,
        cpus: 2,
        network: "none"
      }

      args = DockerBackend.build_container_args("test-container", state)

      assert "--security-opt=no-new-privileges" in args
      assert "--cap-drop=ALL" in args
      assert "--pids-limit=256" in args
      assert "--read-only" in args
      assert "--tmpfs" in args
    end

    test "runs as non-root user (nobody:nogroup)" do
      state = %DockerBackend{
        memory_mb: 2048,
        cpus: 2,
        network: "none"
      }

      args = DockerBackend.build_container_args("test-container", state)

      assert "--user" in args
      user_idx = Enum.find_index(args, &(&1 == "--user"))
      assert Enum.at(args, user_idx + 1) == "65534:65534"
    end

    test "includes basic docker flags" do
      state = %DockerBackend{
        memory_mb: 1024,
        cpus: 1,
        network: "none"
      }

      args = DockerBackend.build_container_args("my-sandbox", state)

      assert "--name" in args
      assert "my-sandbox" in args
      assert "--memory" in args
      assert "1024m" in args
      assert "--network" in args
      assert "none" in args
    end
  end
end
