defmodule Krait.Brain.Reflector do
  @moduledoc "Post-action learning: generates insights and stores them in memory"

  require Logger

  @doc "Reflect on an action result and store insights"
  @spec reflect(map(), keyword()) :: :ok | {:error, term()}
  def reflect(context, opts \\ []) do
    hot =
      Keyword.get(
        opts,
        :memory,
        Application.get_env(:krait, :memory_hot_server, Krait.Memory.Hot)
      )

    action = Map.get(context, :action, "unknown")
    result = Map.get(context, :result)
    success = Map.get(context, :success, true)

    insight = build_insight(action, result, success)
    key = "reflection:#{action}:#{System.system_time(:second)}"

    Logger.debug("Storing reflection", key: key, action: action, success: success)

    insight_str = inspect(insight)

    case Krait.Memory.Guard.validate_write(key, insight_str) do
      :ok ->
        try do
          Krait.Memory.Hot.put(hot, key, insight)
          :ok
        rescue
          e in [ArgumentError, ErlangError] ->
            Logger.warning("Failed to store reflection", error: Exception.message(e))
            {:error, :storage_failed}
        end

      {:rejected, reason} ->
        Logger.warning("Reflection rejected by guard", key: key, reason: reason)
        {:error, :guard_rejected}
    end
  end

  @doc "Retrieve recent reflections for a given action type"
  @spec recent_reflections(keyword()) :: [term()]
  def recent_reflections(opts \\ []) do
    hot =
      Keyword.get(
        opts,
        :memory,
        Application.get_env(:krait, :memory_hot_server, Krait.Memory.Hot)
      )

    prefix = Keyword.get(opts, :prefix, "reflection:")

    Krait.Memory.Hot.list_keys(hot, prefix)
  end

  defp build_insight(action, result, true) do
    %{
      action: action,
      outcome: :success,
      summary: "Action '#{action}' completed successfully",
      result_preview: truncate(inspect(result), 500),
      timestamp: DateTime.utc_now()
    }
  end

  defp build_insight(action, result, false) do
    %{
      action: action,
      outcome: :failure,
      summary: "Action '#{action}' failed",
      error: truncate(inspect(result), 500),
      timestamp: DateTime.utc_now()
    }
  end

  defp truncate(str, max) when byte_size(str) <= max, do: str
  defp truncate(str, max), do: String.slice(str, 0, max) <> "..."
end
