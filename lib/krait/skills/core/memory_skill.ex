defmodule Krait.Skills.Core.MemorySkill do
  @moduledoc "Read/write agent memory"
  @behaviour Krait.Skills.Skill

  @impl true
  def name, do: "memory"

  @impl true
  def description, do: "Store and recall agent memories"

  @impl true
  def execute(%{"action" => "store", "key" => key, "value" => value}) do
    case Krait.Memory.Guard.validate_write(key, value) do
      :ok ->
        hot = memory_server()
        Krait.Memory.Hot.put(hot, key, value)
        {:ok, %{stored: key}}

      {:rejected, reason} ->
        {:error, reason}
    end
  end

  def execute(%{"action" => "recall", "key" => key}) do
    hot = memory_server()

    case Krait.Memory.Hot.get(hot, key) do
      {:ok, value} -> {:ok, %{key: key, value: value}}
      :not_found -> {:ok, %{key: key, value: nil}}
    end
  end

  def execute(%{"action" => "list", "prefix" => prefix}) do
    hot = memory_server()
    keys = Krait.Memory.Hot.list_keys(hot, prefix)
    {:ok, %{memories: keys}}
  end

  def execute(%{"action" => "list"}) do
    hot = memory_server()
    keys = Krait.Memory.Hot.list_keys(hot, "")
    {:ok, %{memories: keys}}
  end

  def execute(%{action: _} = params) do
    params = Map.new(params, fn {k, v} -> {to_string(k), to_string(v)} end)
    execute(params)
  end

  def execute(_), do: {:error, "Missing required parameter: action"}

  defp memory_server do
    Application.get_env(:krait, :memory_hot_server, Krait.Memory.Hot)
  end
end
