defmodule Krait.KillSwitch do
  @moduledoc """
  Global kill switch for the evolution system — the "K" in KRAIT.

  Provides immediate halt/resume of all evolution activity system-wide.
  State is backed by both ETS (fast reads) and PostgreSQL (survives restarts).

  ## Features
  - `halt!/1` — immediately blocks all evolution entry points
  - `resume!/0` — restores normal operation (with 30s cooldown between resumes)
  - `record_failure/0` — increments consecutive failure counter; auto-trips after threshold
  - `record_success/0` — resets consecutive failure counter
  - `halted?/0` — fast ETS read for integration checks
  - `status/0` — full state map for dashboards

  ## PubSub
  Broadcasts on topic "kill_switch" for LiveView real-time updates.
  """

  use GenServer

  require Logger

  import Ecto.Query

  alias Krait.{KillSwitchState, Repo}

  @table :krait_kill_switch
  @pubsub_topic "kill_switch"

  # -- Public API --

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @doc "Returns true if evolution is halted."
  @spec halted?() :: boolean()
  def halted? do
    case :ets.lookup(@table, :halted) do
      [{:halted, true}] -> true
      _ -> false
    end
  rescue
    ArgumentError -> false
  end

  @doc "Halt all evolution with a reason string."
  @spec halt!(String.t()) :: :ok
  def halt!(reason) do
    GenServer.call(__MODULE__, {:halt, reason})
  end

  @doc """
  Halt evolution in the current node without persisting the halt.

  This is intended for graceful shutdown drains: the node must stop accepting
  new evolution work while it waits for active work to finish, but a normal
  restart must not come back with the global kill switch still engaged.
  """
  @spec halt_transient!(String.t()) :: :ok
  def halt_transient!(reason) do
    GenServer.call(__MODULE__, {:halt_transient, reason})
  end

  @doc """
  Resume evolution. Returns `{:error, :resume_cooldown, seconds_remaining}`
  if called within 30 seconds of the last resume.
  """
  @spec resume!() :: :ok | {:error, :resume_cooldown, non_neg_integer()}
  def resume! do
    GenServer.call(__MODULE__, :resume)
  end

  @doc "Record a validation failure. Auto-trips after threshold consecutive failures."
  @spec record_failure() :: :ok | {:halted, String.t()}
  def record_failure do
    GenServer.call(__MODULE__, :record_failure)
  end

  @doc "Record a successful evolution. Resets consecutive failure counter."
  @spec record_success() :: :ok
  def record_success do
    GenServer.call(__MODULE__, :record_success)
  end

  @doc "Returns full state map for dashboards."
  @spec status() :: map()
  def status do
    GenServer.call(__MODULE__, :status)
  end

  # -- GenServer Callbacks --

  @impl true
  def init(opts) do
    table_name = Keyword.get(opts, :table_name, @table)

    table =
      if :ets.whereis(table_name) != :undefined do
        :ets.delete(table_name)
        :ets.new(table_name, [:set, :protected, :named_table])
      else
        :ets.new(table_name, [:set, :protected, :named_table])
      end

    skip_db = Keyword.get(opts, :skip_db, false)

    # Restore persisted state from DB (survives restarts)
    # Skip DB access when skip_db: true (used in tests where sandbox isn't ready)
    state =
      if skip_db do
        %{
          table: table,
          halted: false,
          halted_at: nil,
          halted_by: nil,
          consecutive_failures: 0,
          db_record_id: nil,
          skip_db: true
        }
      else
        restore_from_db(table) |> Map.put(:skip_db, false)
      end

    {:ok, state}
  end

  @impl true
  def handle_call({:halt, reason}, _from, state) do
    new_state = put_halted_state(state, reason)
    new_state = maybe_update_db_id(new_state, persist_to_db(new_state))

    Phoenix.PubSub.broadcast(Krait.PubSub, @pubsub_topic, {:kill_switch_engaged, reason})

    Logger.warning("[KillSwitch] Evolution halted: " <> reason)

    {:reply, :ok, new_state}
  end

  def handle_call({:halt_transient, reason}, _from, %{halted: true} = state) do
    Logger.info(
      "[KillSwitch] Transient halt requested during existing halt: " <>
        (state.halted_by || reason)
    )

    {:reply, :ok, state}
  end

  def handle_call({:halt_transient, reason}, _from, state) do
    new_state = put_halted_state(state, reason)

    Phoenix.PubSub.broadcast(Krait.PubSub, @pubsub_topic, {:kill_switch_engaged, reason})

    Logger.warning("[KillSwitch] Evolution transiently halted: " <> reason)

    {:reply, :ok, new_state}
  end

  def handle_call(:resume, _from, state) do
    # Check resume cooldown (30 seconds between resumes)
    case :ets.lookup(@table, :last_resumed_at) do
      [{:last_resumed_at, last}] when is_integer(last) ->
        elapsed = System.monotonic_time(:second) - last
        resume_cooldown = Application.get_env(:krait, :kill_switch_resume_cooldown, 30)

        if elapsed < resume_cooldown do
          {:reply, {:error, :resume_cooldown, resume_cooldown - elapsed}, state}
        else
          do_resume(state)
        end

      _ ->
        do_resume(state)
    end
  end

  def handle_call(:record_failure, _from, state) do
    new_count = state.consecutive_failures + 1
    threshold = Application.get_env(:krait, :kill_switch_failure_threshold, 5)

    :ets.insert(@table, {:consecutive_failures, new_count})
    new_state = %{state | consecutive_failures: new_count}

    if new_count >= threshold and not state.halted do
      reason = "auto_trip: #{new_count} consecutive validation failures"
      now = DateTime.utc_now()

      :ets.insert(@table, {:halted, true})
      :ets.insert(@table, {:halted_at, now})
      :ets.insert(@table, {:halted_by, reason})

      final_state = %{new_state | halted: true, halted_at: now, halted_by: reason}
      final_state = maybe_update_db_id(final_state, persist_to_db(final_state))

      Phoenix.PubSub.broadcast(Krait.PubSub, @pubsub_topic, {:kill_switch_engaged, reason})

      Logger.warning("[KillSwitch] Auto-tripped: " <> reason)

      {:reply, {:halted, reason}, final_state}
    else
      new_state = maybe_update_db_id(new_state, persist_to_db(new_state))
      {:reply, :ok, new_state}
    end
  end

  def handle_call(:record_success, _from, state) do
    :ets.insert(@table, {:consecutive_failures, 0})
    new_state = %{state | consecutive_failures: 0}
    new_state = maybe_update_db_id(new_state, persist_to_db(new_state))
    {:reply, :ok, new_state}
  end

  # Test-only: reset state without DB interaction
  def handle_call(:reset_for_test, _from, state) do
    :ets.insert(@table, {:halted, false})
    :ets.insert(@table, {:halted_at, nil})
    :ets.insert(@table, {:halted_by, nil})
    :ets.insert(@table, {:consecutive_failures, 0})
    :ets.delete(@table, :last_resumed_at)

    new_state = %{
      state
      | halted: false,
        halted_at: nil,
        halted_by: nil,
        consecutive_failures: 0
    }

    {:reply, :ok, new_state}
  end

  def handle_call(:status, _from, state) do
    status = %{
      halted: state.halted,
      halted_at: state.halted_at,
      halted_by: state.halted_by,
      consecutive_failures: state.consecutive_failures
    }

    {:reply, status, state}
  end

  # -- Private --

  defp put_halted_state(state, reason) do
    now = DateTime.utc_now()

    # Only update timestamp on first halt (idempotent)
    halted_at =
      case :ets.lookup(state.table, :halted_at) do
        [{:halted_at, existing}] when state.halted -> existing
        _ -> now
      end

    :ets.insert(state.table, {:halted, true})
    :ets.insert(state.table, {:halted_at, halted_at})
    :ets.insert(state.table, {:halted_by, reason})

    %{state | halted: true, halted_at: halted_at, halted_by: reason}
  end

  defp do_resume(state) do
    :ets.insert(@table, {:halted, false})
    :ets.insert(@table, {:halted_at, nil})
    :ets.insert(@table, {:halted_by, nil})
    :ets.insert(@table, {:consecutive_failures, 0})
    :ets.insert(@table, {:last_resumed_at, System.monotonic_time(:second)})

    new_state = %{state | halted: false, halted_at: nil, halted_by: nil, consecutive_failures: 0}
    new_state = maybe_update_db_id(new_state, persist_to_db(new_state))

    Phoenix.PubSub.broadcast(Krait.PubSub, @pubsub_topic, :kill_switch_disengaged)

    Logger.info("[KillSwitch] Evolution resumed")

    {:reply, :ok, new_state}
  end

  defp restore_from_db(table) do
    default = %{
      table: table,
      halted: false,
      halted_at: nil,
      halted_by: nil,
      consecutive_failures: 0,
      db_record_id: nil
    }

    try do
      case Repo.one(from(ks in KillSwitchState, limit: 1)) do
        nil ->
          default

        persisted ->
          if persisted.halted do
            :ets.insert(table, {:halted, true})
            :ets.insert(table, {:halted_at, persisted.halted_at})
            :ets.insert(table, {:halted_by, persisted.halted_by})

            Logger.warning(
              "[KillSwitch] Restored halted state from DB: " <> (persisted.halted_by || "unknown")
            )
          end

          :ets.insert(table, {:consecutive_failures, persisted.consecutive_failures})

          %{
            default
            | halted: persisted.halted,
              halted_at: persisted.halted_at,
              halted_by: persisted.halted_by,
              consecutive_failures: persisted.consecutive_failures,
              db_record_id: persisted.id
          }
      end
    rescue
      DBConnection.ConnectionError ->
        Logger.warning("[KillSwitch] DB unavailable during init, starting with default state")
        default

      Ecto.QueryError ->
        Logger.warning(
          "[KillSwitch] kill_switch_state table not yet migrated, using default state"
        )

        default

      Postgrex.Error ->
        Logger.warning("[KillSwitch] DB error during init, starting with default state")
        default
    end
  end

  defp maybe_update_db_id(state, {:ok, id}), do: %{state | db_record_id: id}
  defp maybe_update_db_id(state, :skip), do: state
  defp maybe_update_db_id(state, _), do: state

  defp persist_to_db(%{skip_db: true}), do: :skip

  defp persist_to_db(state) do
    attrs = %{
      halted: state.halted,
      halted_at: state.halted_at,
      halted_by: state.halted_by,
      consecutive_failures: state.consecutive_failures
    }

    try do
      case state.db_record_id do
        nil ->
          record =
            %KillSwitchState{}
            |> KillSwitchState.changeset(attrs)
            |> Repo.insert!()

          # Return the new id so caller can update state
          {:ok, record.id}

        id ->
          Repo.get!(KillSwitchState, id)
          |> KillSwitchState.changeset(attrs)
          |> Repo.update!()

          {:ok, id}
      end
    rescue
      DBConnection.ConnectionError ->
        Logger.error("[KillSwitch] Failed to persist state to DB: connection error")
        :error

      Postgrex.Error ->
        Logger.error("[KillSwitch] Failed to persist state to DB: postgrex error")
        :error

      Ecto.QueryError ->
        Logger.error("[KillSwitch] Failed to persist state to DB: query error")
        :error
    end
  end
end
