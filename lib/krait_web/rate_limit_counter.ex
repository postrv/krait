defmodule KraitWeb.RateLimitCounter do
  @moduledoc """
  GenServer owning a `:protected` ETS table for rate limiting.

  Writes (increment, sweep) route through the GenServer to enforce
  ownership. Reads are direct ETS lookups — `:protected` allows reads
  from any process.

  Follows the `Krait.Memory.Hot` pattern: `:protected` + GenServer writes,
  direct ETS reads.
  """

  use GenServer

  @table :krait_rate_limit

  # -- Public API --

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc "Atomically increment the counter for `bucket_key`. Returns new count."
  @spec increment(term()) :: non_neg_integer()
  def increment(bucket_key) do
    GenServer.call(__MODULE__, {:increment, bucket_key})
  end

  @doc "Read counter for `bucket_key`. Returns 0 if not found. Direct ETS read."
  @spec get_count(term()) :: non_neg_integer()
  def get_count(bucket_key) do
    case :ets.lookup(@table, bucket_key) do
      [{_, count}] -> count
      [] -> 0
    end
  end

  @doc "Current number of entries in the rate limit table."
  @spec table_size() :: non_neg_integer()
  def table_size do
    :ets.info(@table, :size)
  end

  @doc "Remove entries from epochs older than `window_ms`."
  @spec sweep_stale(non_neg_integer()) :: :ok
  def sweep_stale(window_ms) do
    GenServer.call(__MODULE__, {:sweep, window_ms})
  end

  # -- GenServer callbacks --

  @impl true
  def init(_opts) do
    # If the table already exists (e.g. from a prior process that crashed
    # but left the named table behind), delete it first so we can recreate
    # with :protected ownership.
    if :ets.whereis(@table) != :undefined do
      :ets.delete(@table)
    end

    table = :ets.new(@table, [:set, :protected, :named_table, read_concurrency: true])
    {:ok, %{table: table}}
  end

  @impl true
  def handle_call({:increment, bucket_key}, _from, state) do
    count = :ets.update_counter(@table, bucket_key, {2, 1}, {bucket_key, 0})
    {:reply, count, state}
  end

  def handle_call({:sweep, window_ms}, _from, state) do
    now = System.monotonic_time(:millisecond)
    current_epoch = div(now, window_ms)

    # v26 L-5: Sweep both 2-tuple IP keys {ip, epoch} and 3-tuple token keys {:token, hash, epoch}
    :ets.select_delete(@table, [
      {{{:_, :"$1"}, :_}, [{:<, :"$1", current_epoch}], [true]},
      {{{:_, :_, :"$1"}, :_}, [{:<, :"$1", current_epoch}], [true]}
    ])

    {:reply, :ok, state}
  end

  # For testing: insert raw tuples
  def handle_call({:insert_raw, tuple}, _from, state) do
    :ets.insert(@table, tuple)
    {:reply, :ok, state}
  end

  # For testing: clear all entries
  def handle_call({:sweep_all}, _from, state) do
    :ets.delete_all_objects(@table)
    {:reply, :ok, state}
  end

  @impl true
  def handle_cast({:sweep, window_ms}, state) do
    now = System.monotonic_time(:millisecond)
    current_epoch = div(now, window_ms)

    # v26 L-5: Sweep both 2-tuple IP keys and 3-tuple token keys
    :ets.select_delete(@table, [
      {{{:_, :"$1"}, :_}, [{:<, :"$1", current_epoch}], [true]},
      {{{:_, :_, :"$1"}, :_}, [{:<, :"$1", current_epoch}], [true]}
    ])

    {:noreply, state}
  end
end
