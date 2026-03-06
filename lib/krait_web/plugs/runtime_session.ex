defmodule KraitWeb.Plugs.RuntimeSession do
  @moduledoc """
  A Plug.Session wrapper that merges runtime configuration over compile-time defaults.

  Solves the session salt compile-time mismatch: `@session_options` in endpoint.ex
  bakes dev salts at compile time, while `runtime.exs` sets production salts.
  This plug reads the runtime `:session_options` from the endpoint config and merges
  them over the compile-time defaults before delegating to `Plug.Session`.

  Merged options are cached via `:persistent_term` for zero-overhead after first request.
  """

  @behaviour Plug

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, default_opts) do
    opts = merged_session_opts(default_opts)
    # Plug.Session.init expects to be called once, but since we cache the result
    # of Plug.Session.init, this is safe.
    session_init = cached_session_init(opts)
    Plug.Session.call(conn, session_init)
  end

  @doc false
  def merged_session_opts(default_opts) do
    case safe_persistent_term_get(:krait_session_opts) do
      {:ok, cached} ->
        cached

      :miss ->
        runtime_overrides =
          Application.get_env(:krait, KraitWeb.Endpoint, [])
          |> Keyword.get(:session_options, [])

        merged = Keyword.merge(default_opts, runtime_overrides)
        :persistent_term.put(:krait_session_opts, merged)
        merged
    end
  end

  defp cached_session_init(opts) do
    case safe_persistent_term_get(:krait_session_init) do
      {:ok, cached} ->
        cached

      :miss ->
        init = Plug.Session.init(opts)
        :persistent_term.put(:krait_session_init, init)
        init
    end
  end

  @doc """
  Invalidate the cached session options and init, forcing fresh merge on next request.

  v22 SEC-07: Ensures config changes (e.g. salt rotation) take effect without restart.
  Idempotent — safe to call on empty cache.
  """
  @spec invalidate_cache() :: :ok
  def invalidate_cache do
    try do
      :persistent_term.erase(:krait_session_opts)
    rescue
      ArgumentError -> :ok
    end

    try do
      :persistent_term.erase(:krait_session_init)
    rescue
      ArgumentError -> :ok
    end

    :ok
  end

  defp safe_persistent_term_get(key) do
    {:ok, :persistent_term.get(key)}
  rescue
    ArgumentError -> :miss
  end
end
