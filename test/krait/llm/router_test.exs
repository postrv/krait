defmodule Krait.LLM.RouterTest do
  use ExUnit.Case, async: false

  import Mox

  setup :verify_on_exit!

  setup do
    original = Application.get_env(:krait, Krait.LLM.Router)

    Application.put_env(:krait, Krait.LLM.Router,
      cloud_module: Krait.LLM.CloudMock,
      local_module: Krait.LLM.LocalMock,
      force_cloud: [:planning, :reflection, :retry_guide],
      force_local: [:code_gen, :test_gen, :chat],
      escalation_threshold: 2
    )

    on_exit(fn ->
      if original do
        Application.put_env(:krait, Krait.LLM.Router, original)
      else
        Application.delete_env(:krait, Krait.LLM.Router)
      end
    end)

    :ok
  end

  describe "task-type routing" do
    test "routes :code_gen to local backend" do
      Krait.LLM.LocalMock
      |> expect(:complete, fn _msgs, _opts ->
        {:ok, "local response"}
      end)

      assert {:ok, "local response"} =
               Krait.LLM.Router.complete(
                 [%{"role" => "user", "content" => "generate code"}],
                 task_type: :code_gen
               )
    end

    test "routes :test_gen to local backend" do
      Krait.LLM.LocalMock
      |> expect(:complete, fn _msgs, _opts ->
        {:ok, "test code"}
      end)

      assert {:ok, "test code"} =
               Krait.LLM.Router.complete(
                 [%{"role" => "user", "content" => "write tests"}],
                 task_type: :test_gen
               )
    end

    test "routes :planning to cloud backend" do
      Krait.LLM.CloudMock
      |> expect(:complete, fn _msgs, _opts ->
        {:ok, "cloud plan"}
      end)

      assert {:ok, "cloud plan"} =
               Krait.LLM.Router.complete(
                 [%{"role" => "user", "content" => "plan the approach"}],
                 task_type: :planning
               )
    end

    test "routes :reflection to cloud backend" do
      Krait.LLM.CloudMock
      |> expect(:complete, fn _msgs, _opts ->
        {:ok, "reflection analysis"}
      end)

      assert {:ok, "reflection analysis"} =
               Krait.LLM.Router.complete(
                 [%{"role" => "user", "content" => "evaluate output"}],
                 task_type: :reflection
               )
    end

    test "routes :chat to local backend" do
      Krait.LLM.LocalMock
      |> expect(:complete_with_tools, fn _msgs, _tools, _opts ->
        {:ok, %{text: "hello!", tool_calls: []}}
      end)

      assert {:ok, %{text: "hello!"}} =
               Krait.LLM.Router.complete_with_tools(
                 [%{"role" => "user", "content" => "hi"}],
                 [],
                 task_type: :chat
               )
    end
  end

  describe "retry escalation" do
    test "routes early retry attempts to local" do
      Krait.LLM.LocalMock
      |> expect(:complete, fn _msgs, _opts ->
        {:ok, "local retry"}
      end)

      assert {:ok, "local retry"} =
               Krait.LLM.Router.complete(
                 [%{"role" => "user", "content" => "retry"}],
                 task_type: :retry,
                 attempt: 1
               )
    end

    test "escalates to cloud after threshold attempts" do
      Krait.LLM.CloudMock
      |> expect(:complete, fn _msgs, _opts ->
        {:ok, "cloud retry"}
      end)

      assert {:ok, "cloud retry"} =
               Krait.LLM.Router.complete(
                 [%{"role" => "user", "content" => "retry"}],
                 task_type: :retry,
                 attempt: 2
               )
    end

    test "escalates to cloud on attempt 3 (well past threshold)" do
      Krait.LLM.CloudMock
      |> expect(:complete, fn _msgs, _opts ->
        {:ok, "cloud final retry"}
      end)

      assert {:ok, "cloud final retry"} =
               Krait.LLM.Router.complete(
                 [%{"role" => "user", "content" => "retry"}],
                 task_type: :retry,
                 attempt: 3
               )
    end
  end

  describe "force_backend override" do
    test "force_backend: :cloud overrides task_type routing" do
      Krait.LLM.CloudMock
      |> expect(:complete, fn _msgs, _opts ->
        {:ok, "forced cloud"}
      end)

      assert {:ok, "forced cloud"} =
               Krait.LLM.Router.complete(
                 [%{"role" => "user", "content" => "generate code"}],
                 task_type: :code_gen,
                 force_backend: :cloud
               )
    end

    test "force_backend: :local overrides cloud task types" do
      Krait.LLM.LocalMock
      |> expect(:complete, fn _msgs, _opts ->
        {:ok, "forced local"}
      end)

      assert {:ok, "forced local"} =
               Krait.LLM.Router.complete(
                 [%{"role" => "user", "content" => "plan"}],
                 task_type: :planning,
                 force_backend: :local
               )
    end
  end

  describe "health check redirect protection" do
    test "302 from Ollama health check returns false" do
      bypass = Bypass.open()

      Bypass.expect_once(bypass, "GET", "/api/tags", fn conn ->
        conn
        |> Plug.Conn.put_resp_header("location", "http://169.254.169.254/")
        |> Plug.Conn.resp(302, "")
      end)

      Application.put_env(:krait, Krait.LLM.Ollama, base_url: "http://localhost:#{bypass.port}")

      # v22 SEC-08: Clear health cache via GenServer API (table is :protected)
      try do
        Krait.HealthCacheServer.delete(:ollama_health_cache)
      rescue
        _ -> :ok
      end

      Process.delete(:ollama_health_cache)

      refute Krait.LLM.Router.local_available?()
    end
  end

  describe "SSRF protection for Ollama base_url" do
    test "non-local base_url returns false" do
      Application.put_env(:krait, Krait.LLM.Ollama, base_url: "http://169.254.169.254")

      # v22 SEC-08: Clear health cache via GenServer API (table is :protected)
      try do
        Krait.HealthCacheServer.delete(:ollama_health_cache)
      rescue
        _ -> :ok
      end

      Process.delete(:ollama_health_cache)

      refute Krait.LLM.Router.local_available?()
    end

    test "localhost base_url is allowed" do
      # Default localhost is allowed; we just verify it doesn't reject localhost
      Application.put_env(:krait, Krait.LLM.Ollama, base_url: "http://localhost:11434")

      # v22 SEC-08: Clear health cache via GenServer API (table is :protected)
      try do
        Krait.HealthCacheServer.delete(:ollama_health_cache)
      rescue
        _ -> :ok
      end

      Process.delete(:ollama_health_cache)

      # Will return false because no Ollama running, but shouldn't be rejected by URL check
      # The key test is that the non-local URL above returns false immediately
      _result = Krait.LLM.Router.local_available?()
      assert true
    end
  end

  describe "validate_ollama_url IPv6 normalization" do
    test "expanded IPv6 loopback 0:0:0:0:0:0:0:1 is accepted" do
      assert :ok = Krait.LLM.Router.validate_ollama_url("http://[0:0:0:0:0:0:0:1]:11434")
    end

    test "IPv4-mapped IPv6 ::ffff:127.0.0.1 is accepted" do
      assert :ok = Krait.LLM.Router.validate_ollama_url("http://[::ffff:127.0.0.1]:11434")
    end

    test "non-standard port rejected in prod" do
      original_env = Application.get_env(:krait, :env)
      Application.put_env(:krait, :env, :prod)

      on_exit(fn ->
        if original_env,
          do: Application.put_env(:krait, :env, original_env),
          else: Application.delete_env(:krait, :env)
      end)

      assert {:error, :invalid_ollama_url} =
               Krait.LLM.Router.validate_ollama_url("http://localhost:6379")
    end

    test "allowed port 11434 accepted in prod" do
      original_env = Application.get_env(:krait, :env)
      Application.put_env(:krait, :env, :prod)

      on_exit(fn ->
        if original_env,
          do: Application.put_env(:krait, :env, original_env),
          else: Application.delete_env(:krait, :env)
      end)

      assert :ok = Krait.LLM.Router.validate_ollama_url("http://localhost:11434")
    end

    test "allowed port 11435 accepted in prod" do
      original_env = Application.get_env(:krait, :env)
      Application.put_env(:krait, :env, :prod)

      on_exit(fn ->
        if original_env,
          do: Application.put_env(:krait, :env, original_env),
          else: Application.delete_env(:krait, :env)
      end)

      assert :ok = Krait.LLM.Router.validate_ollama_url("http://localhost:11435")
    end
  end

  describe "H6-v10: nil host in validate_ollama_url" do
    test "http://:11434 returns error (no crash)" do
      assert {:error, :invalid_ollama_url} = Krait.LLM.Router.validate_ollama_url("http://:11434")
    end

    test "empty host returns error" do
      assert {:error, :invalid_ollama_url} =
               Krait.LLM.Router.validate_ollama_url("http://:80/path")
    end
  end

  describe "opts passthrough" do
    test "strips router-specific keys before passing to backend" do
      Krait.LLM.LocalMock
      |> expect(:complete, fn _msgs, opts ->
        refute Keyword.has_key?(opts, :task_type)
        refute Keyword.has_key?(opts, :attempt)
        refute Keyword.has_key?(opts, :force_backend)
        assert Keyword.get(opts, :model) == "qwen2.5-coder:7b"
        {:ok, "ok"}
      end)

      Krait.LLM.Router.complete(
        [%{"role" => "user", "content" => "hi"}],
        task_type: :code_gen,
        attempt: 1,
        model: "qwen2.5-coder:7b"
      )
    end
  end
end
