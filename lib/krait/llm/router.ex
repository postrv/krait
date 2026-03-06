defmodule Krait.LLM.Router do
  @moduledoc """
  Task-aware LLM router that dispatches to the cheapest capable backend.

  The Router implements `Krait.LLM.Behaviour` so it's a drop-in replacement
  for any direct LLM client module.

  ## Configuration

      config :krait, Krait.LLM.Router,
        local_module: Krait.LLM.Ollama,
        cloud_module: Krait.LLM.OpenRouter,
        force_cloud: [:planning, :reflection],
        force_local: [:code_gen, :test_gen, :chat],
        escalation_threshold: 2
  """

  @behaviour Krait.LLM.Behaviour

  require Logger

  @cloud_tasks [:planning, :reflection, :retry_guide]
  @local_tasks [:code_gen, :test_gen, :chat]

  @impl true
  def complete(messages, opts \\ []) do
    {backend, backend_opts} = select_backend(opts)

    Logger.debug("Router dispatching complete/2",
      backend: inspect(backend),
      task: opts[:task_type]
    )

    backend.complete(messages, backend_opts)
  end

  @impl true
  def complete_with_tools(messages, tools, opts \\ []) do
    {backend, backend_opts} = select_backend(opts)

    Logger.debug("Router dispatching complete_with_tools/3",
      backend: inspect(backend),
      task: opts[:task_type]
    )

    backend.complete_with_tools(messages, tools, backend_opts)
  end

  @impl true
  def stream(messages, opts \\ []) do
    {backend, backend_opts} = select_backend(opts)
    backend.stream(messages, backend_opts)
  end

  # ---------------------------------------------------------------------------
  # Backend selection
  # ---------------------------------------------------------------------------

  defp select_backend(opts) do
    task_type = Keyword.get(opts, :task_type)
    attempt = Keyword.get(opts, :attempt, 1)

    backend_opts =
      opts
      |> Keyword.drop([:task_type, :attempt, :force_backend])
      |> ensure_api_key_for_cloud()
      |> pass_through_openrouter_opts(opts)

    case Keyword.get(opts, :force_backend) do
      :cloud -> {cloud_module(), backend_opts}
      :local -> {local_module(), backend_opts}
      nil -> route_by_task(task_type, attempt, backend_opts)
    end
  end

  defp route_by_task(task_type, attempt, opts) do
    force_cloud = router_config(:force_cloud, @cloud_tasks)
    force_local = router_config(:force_local, @local_tasks)
    threshold = router_config(:escalation_threshold, 2)

    cond do
      task_type in force_cloud ->
        {cloud_module(), opts}

      task_type in force_local ->
        {local_module(), opts}

      task_type == :retry ->
        if attempt >= threshold do
          Logger.info("Escalating retry to cloud", attempt: attempt, threshold: threshold)
          {cloud_module(), opts}
        else
          {local_module(), opts}
        end

      true ->
        if local_available?() do
          {local_module(), opts}
        else
          {cloud_module(), opts}
        end
    end
  end

  # ---------------------------------------------------------------------------
  # Health check
  # ---------------------------------------------------------------------------

  @ollama_health_key :ollama_health_cache
  @ollama_cache_ttl 30

  @doc "Check if the local Ollama instance is reachable."
  def local_available? do
    # Try shared ETS cache first, fall back to per-process cache
    case read_health_cache() do
      {:ok, result} ->
        result

      :miss ->
        check_ollama()
    end
  end

  # v22 SEC-08: Route through HealthCacheServer (protected table)
  defp read_health_cache do
    now = System.monotonic_time(:second)

    case Krait.HealthCacheServer.read(@ollama_health_key) do
      {:ok, {result, checked_at}} when now - checked_at < @ollama_cache_ttl ->
        {:ok, result}

      _ ->
        :miss
    end
  end

  defp write_health_cache(result) do
    now = System.monotonic_time(:second)

    try do
      Krait.HealthCacheServer.write(@ollama_health_key, {result, now})
    rescue
      # GenServer not started (e.g. in some tests)
      _ -> :ok
    end

    # Also keep per-process fallback
    Process.put(@ollama_health_key, {result, now})
    result
  end

  defp check_ollama do
    base_url =
      get_in(Application.get_env(:krait, Krait.LLM.Ollama, []), [:base_url]) ||
        "http://localhost:11434"

    case validate_ollama_url(base_url) do
      :ok ->
        result =
          case Req.get("#{base_url}/api/tags", receive_timeout: 2_000, redirect: false) do
            {:ok, %{status: 200}} -> true
            _ -> false
          end

        write_health_cache(result)

      {:error, :invalid_ollama_url} ->
        Logger.warning("Ollama base_url rejected (non-local): redacted")
        write_health_cache(false)
    end
  rescue
    e in [Req.TransportError, RuntimeError, ArgumentError] ->
      Logger.debug("Ollama health check failed: #{Exception.message(e)}")
      false
  end

  @allowed_ollama_ports [11_434, 11_435]

  @doc "Validate that an Ollama URL points to a local host only."
  def validate_ollama_url(url) do
    case URI.parse(url) do
      %URI{scheme: scheme, host: host, port: port}
      when scheme in ["http", "https"] and is_binary(host) and host != "" ->
        cond do
          not local_host?(host) ->
            {:error, :invalid_ollama_url}

          Application.get_env(:krait, :env) == :prod and port not in @allowed_ollama_ports ->
            {:error, :invalid_ollama_url}

          true ->
            :ok
        end

      _ ->
        {:error, :invalid_ollama_url}
    end
  end

  defp local_host?(host) when host in ["localhost", "127.0.0.1", "::1"], do: true

  defp local_host?(host) do
    ip_str = host |> String.trim_leading("[") |> String.trim_trailing("]")

    case :inet.parse_address(String.to_charlist(ip_str)) do
      {:ok, {127, 0, 0, 1}} -> true
      {:ok, {0, 0, 0, 0, 0, 0, 0, 1}} -> true
      {:ok, {0, 0, 0, 0, 0, 0xFFFF, 0x7F00, 0x0001}} -> true
      _ -> false
    end
  end

  # ---------------------------------------------------------------------------
  # Config helpers
  # ---------------------------------------------------------------------------

  defp cloud_module do
    router_config(:cloud_module, Krait.LLM.OpenRouter)
  end

  defp local_module do
    router_config(:local_module, Krait.LLM.Ollama)
  end

  defp router_config(key, default) do
    get_in(Application.get_env(:krait, __MODULE__, []), [key]) || default
  end

  defp ensure_api_key_for_cloud(opts) do
    if Keyword.has_key?(opts, :api_key) do
      opts
    else
      key =
        Application.get_env(:krait, :openrouter_api_key) ||
          Application.get_env(:krait, :anthropic_api_key)

      case key do
        nil -> opts
        k -> Keyword.put(opts, :api_key, k)
      end
    end
  end

  defp pass_through_openrouter_opts(backend_opts, original_opts) do
    Enum.reduce([:models, :provider], backend_opts, fn key, acc ->
      case Keyword.get(original_opts, key) do
        nil -> acc
        val -> Keyword.put_new(acc, key, val)
      end
    end)
  end
end
