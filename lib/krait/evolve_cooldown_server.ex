defmodule Krait.EvolveCooldownServer do
  @moduledoc """
  GenServer owning a `:protected` ETS table for evolution cooldown tracking.

  v22 SEC-08: Replaces the public `:krait_evolve_cooldown` ETS table
  with a protected one owned by this GenServer. Writes route through
  the GenServer; reads are direct ETS lookups.
  """

  use GenServer

  @table :krait_evolve_cooldown

  # -- Public API --

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc "Atomically update a counter. Returns new value."
  @spec update_counter(term(), tuple(), tuple()) :: integer()
  def update_counter(key, update_op, default) do
    GenServer.call(__MODULE__, {:update_counter, key, update_op, default})
  end

  @doc "Insert a tuple into the cooldown table."
  @spec insert(tuple()) :: :ok
  def insert(tuple) do
    GenServer.call(__MODULE__, {:insert, tuple})
  end

  @doc "Lookup a key. Direct ETS read (fast path)."
  @spec lookup(term()) :: list()
  def lookup(key) do
    :ets.lookup(@table, key)
  rescue
    ArgumentError -> []
  end

  @doc "Delete all entries (for testing)."
  @spec delete_all() :: :ok
  def delete_all do
    GenServer.call(__MODULE__, :delete_all)
  end

  @doc """
  Atomically try to acquire a slot. Returns `:ok` if under capacity,
  `{:error, :at_capacity}` if at or over max.

  v24 F-05: Serialized by GenServer to prevent race conditions.
  """
  @spec try_acquire_slot(term(), non_neg_integer()) :: :ok | {:error, :at_capacity}
  def try_acquire_slot(key, max) do
    GenServer.call(__MODULE__, {:try_acquire_slot, key, max})
  end

  @doc """
  Release a slot (decrement with floor at 0).

  v24 F-05: Serialized by GenServer.
  """
  @spec release_slot(term()) :: :ok
  def release_slot(key) do
    GenServer.call(__MODULE__, {:release_slot, key})
  end

  @doc """
  Monitor a process and auto-release its slot on crash.

  v24 F-24: Safety net for slot cleanup on task crash.
  """
  @spec register_slot_owner(term(), pid()) :: :ok
  def register_slot_owner(key, pid) do
    GenServer.cast(__MODULE__, {:register_slot_owner, key, pid})
  end

  @doc """
  Sweep old lockout entries from previous time buckets.

  v24 F-03: Removes entries keyed by `{:admin_login_failures, ip, bucket}`
  where bucket is older than the current window.
  """
  @spec sweep_old_lockouts(non_neg_integer()) :: :ok
  def sweep_old_lockouts(window_seconds) do
    GenServer.cast(__MODULE__, {:sweep_old_lockouts, window_seconds})
  end

  # -- GenServer callbacks --

  @dets_table :krait_lockout_persist

  @impl true
  def init(_opts) do
    if :ets.whereis(@table) != :undefined do
      :ets.delete(@table)
    end

    table = :ets.new(@table, [:set, :protected, :named_table])

    # v25 L-4: Open DETS for lockout persistence across restarts
    dets_path = lockout_dets_path()
    File.mkdir_p!(Path.dirname(dets_path))

    dets_ref =
      case :dets.open_file(@dets_table, file: String.to_charlist(dets_path), type: :set) do
        {:ok, ref} ->
          restore_lockouts_from_dets(ref, table)
          ref

        {:error, _reason} ->
          nil
      end

    {:ok, %{table: table, monitors: %{}, dets: dets_ref}}
  end

  @impl true
  def handle_call({:update_counter, key, update_op, default}, _from, state) do
    count = :ets.update_counter(@table, key, update_op, default)
    # v25 L-4: Persist lockout counters to DETS
    maybe_persist_lockout(state.dets, key, count)
    {:reply, count, state}
  end

  def handle_call({:insert, tuple}, _from, state) do
    :ets.insert(@table, tuple)
    # v25 L-4: Persist lockout resets to DETS
    {key, _} = tuple
    maybe_persist_lockout_tuple(state.dets, key, tuple)
    {:reply, :ok, state}
  end

  def handle_call(:delete_all, _from, state) do
    :ets.delete_all_objects(@table)
    {:reply, :ok, %{state | monitors: %{}}}
  end

  # v24 F-05: Atomic slot acquisition — serialized by GenServer, no race
  def handle_call({:try_acquire_slot, key, max}, _from, state) do
    case :ets.lookup(@table, key) do
      [{_, count}] when count >= max ->
        {:reply, {:error, :at_capacity}, state}

      [{_, count}] ->
        :ets.insert(@table, {key, count + 1})
        {:reply, :ok, state}

      [] ->
        :ets.insert(@table, {key, 1})
        {:reply, :ok, state}
    end
  end

  # v24 F-05: Slot release — decrement with floor at 0
  def handle_call({:release_slot, key}, _from, state) do
    case :ets.lookup(@table, key) do
      [{_, count}] when count > 0 -> :ets.insert(@table, {key, count - 1})
      _ -> :ets.insert(@table, {key, 0})
    end

    {:reply, :ok, state}
  end

  @impl true
  def handle_cast({:register_slot_owner, key, pid}, state) do
    ref = Process.monitor(pid)
    monitors = Map.put(state.monitors, ref, key)
    {:noreply, %{state | monitors: monitors}}
  end

  # v24 F-03: Sweep old lockout entries from previous time buckets
  def handle_cast({:sweep_old_lockouts, window_seconds}, state) do
    current_bucket = div(System.system_time(:second), window_seconds)

    :ets.foldl(
      fn
        {{:admin_login_failures, _ip, bucket} = key, _count}, acc when bucket < current_bucket ->
          :ets.delete(@table, key)
          # v25 L-4: Also sweep from DETS
          if state.dets, do: :dets.delete(state.dets, key)
          acc

        _, acc ->
          acc
      end,
      :ok,
      @table
    )

    {:noreply, state}
  end

  # v24 F-24: Auto-release slot when monitored process dies
  @impl true
  def handle_info({:DOWN, ref, :process, _pid, _reason}, state) do
    case Map.pop(state.monitors, ref) do
      {nil, monitors} ->
        {:noreply, %{state | monitors: monitors}}

      {key, monitors} ->
        # Release the slot
        case :ets.lookup(@table, key) do
          [{_, count}] when count > 0 -> :ets.insert(@table, {key, count - 1})
          _ -> :ets.insert(@table, {key, 0})
        end

        {:noreply, %{state | monitors: monitors}}
    end
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # v25 L-4: Close DETS on termination
  @impl true
  def terminate(_reason, state) do
    if state.dets, do: :dets.close(state.dets)
    :ok
  end

  # --- DETS persistence helpers (L-4) ---

  defp lockout_dets_path do
    data_dir = Application.get_env(:krait, :data_dir, "priv/data")
    Path.join(data_dir, "lockout.dets")
  end

  # Restore lockout entries from DETS into ETS on boot
  defp restore_lockouts_from_dets(dets_ref, ets_table) do
    :dets.foldl(
      fn {_key, _count} = entry, acc ->
        :ets.insert(ets_table, entry)
        acc
      end,
      :ok,
      dets_ref
    )
  end

  # Only persist lockout-related keys to DETS (not cooldown slots)
  defp lockout_key?({:admin_login_failures, _ip, _bucket}), do: true
  defp lockout_key?(_), do: false

  defp maybe_persist_lockout(nil, _key, _count), do: :ok

  defp maybe_persist_lockout(dets, key, count) do
    if lockout_key?(key) do
      :dets.insert(dets, {key, count})
    end

    :ok
  end

  defp maybe_persist_lockout_tuple(nil, _key, _tuple), do: :ok

  defp maybe_persist_lockout_tuple(dets, key, tuple) do
    if lockout_key?(key) do
      :dets.insert(dets, tuple)
    end

    :ok
  end
end
