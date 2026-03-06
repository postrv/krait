defmodule Krait.HealthCacheServer do
  @moduledoc """
  GenServer owning a `:protected` ETS table for health check caching.

  v22 SEC-08: Replaces the public `:krait_health_cache` ETS table
  with a protected one owned by this GenServer. Writes route through
  the GenServer; reads are direct ETS lookups.
  """

  use GenServer

  @table :krait_health_cache

  # -- Public API --

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc "Write a key-value pair to the health cache."
  @spec write(term(), term()) :: :ok
  def write(key, value) do
    GenServer.call(__MODULE__, {:write, key, value})
  end

  @doc "Read a value from the health cache. Direct ETS lookup (fast path)."
  @spec read(term()) :: {:ok, term()} | :miss
  def read(key) do
    case :ets.lookup(@table, key) do
      [{_, value}] -> {:ok, value}
      [] -> :miss
    end
  rescue
    ArgumentError -> :miss
  end

  @doc "Delete a key from the health cache."
  @spec delete(term()) :: :ok
  def delete(key) do
    GenServer.call(__MODULE__, {:delete, key})
  end

  # -- GenServer callbacks --

  @impl true
  def init(_opts) do
    if :ets.whereis(@table) != :undefined do
      :ets.delete(@table)
    end

    table =
      :ets.new(@table, [
        :set,
        :protected,
        :named_table,
        read_concurrency: true
      ])

    {:ok, %{table: table}}
  end

  @impl true
  def handle_call({:write, key, value}, _from, state) do
    :ets.insert(@table, {key, value})
    {:reply, :ok, state}
  end

  def handle_call({:delete, key}, _from, state) do
    :ets.delete(@table, key)
    {:reply, :ok, state}
  end
end
