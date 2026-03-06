defmodule Krait.LLM.QualityGate do
  @moduledoc """
  Tracks LLM output quality across backends and recommends escalation.

  The QualityGate observes validation outcomes and maintains a rolling
  success rate per (backend, task_type) pair. When a local model's
  success rate drops below a threshold for a given task type, the gate
  recommends routing that task type to the cloud backend instead.

  ## Configuration

      config :krait, Krait.LLM.QualityGate,
        escalation_threshold: 0.60,
        window_size: 20,
        cooldown_after_escalation: 10
  """

  use GenServer

  require Logger

  @default_threshold 0.60
  @default_window 20
  @default_cooldown 10

  # ---------------------------------------------------------------------------
  # Client API
  # ---------------------------------------------------------------------------

  def start_link(opts \\ []) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc "Record an outcome for a backend + task_type pair"
  @spec record(atom(), atom(), :success | :failure) :: :ok
  def record(backend, task_type, outcome, name \\ __MODULE__) do
    GenServer.cast(name, {:record, backend, task_type, outcome})
  end

  @doc "Should the given task type be escalated from local to cloud?"
  @spec should_escalate?(atom(), atom()) :: boolean()
  def should_escalate?(task_type, name \\ __MODULE__) do
    GenServer.call(name, {:should_escalate?, task_type})
  end

  @doc "Get all tracked stats"
  @spec stats(atom()) :: map()
  def stats(name \\ __MODULE__) do
    GenServer.call(name, :stats)
  end

  @doc "Reset all stats (useful in tests)"
  @spec reset(atom()) :: :ok
  def reset(name \\ __MODULE__) do
    GenServer.call(name, :reset)
  end

  # ---------------------------------------------------------------------------
  # GenServer callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init(opts) do
    state = %{
      windows: %{},
      escalated: %{},
      threshold:
        Keyword.get(
          opts,
          :escalation_threshold,
          config(:escalation_threshold, @default_threshold)
        ),
      window_size: Keyword.get(opts, :window_size, config(:window_size, @default_window)),
      cooldown:
        Keyword.get(
          opts,
          :cooldown_after_escalation,
          config(:cooldown_after_escalation, @default_cooldown)
        )
    }

    {:ok, state}
  end

  @impl true
  def handle_cast({:record, backend, task_type, outcome}, state) do
    key = {backend, task_type}

    window =
      state.windows
      |> Map.get(key, [])
      |> then(&[outcome | &1])
      |> Enum.take(state.window_size)

    windows = Map.put(state.windows, key, window)
    escalated = update_escalation(state, windows, task_type)

    {:noreply, %{state | windows: windows, escalated: escalated}}
  end

  @impl true
  def handle_call({:should_escalate?, task_type}, _from, state) do
    {:reply, Map.get(state.escalated, task_type, false), state}
  end

  @impl true
  def handle_call(:stats, _from, state) do
    stats =
      state.windows
      |> Enum.map(fn {key, window} ->
        successes = Enum.count(window, &(&1 == :success))
        total = length(window)
        rate = if total > 0, do: successes / total, else: 0.0

        {key,
         %{
           success: successes,
           failure: total - successes,
           total: total,
           rate: Float.round(rate, 3)
         }}
      end)
      |> Map.new()

    {:reply, Map.put(stats, :escalated, state.escalated), state}
  end

  @impl true
  def handle_call(:reset, _from, state) do
    {:reply, :ok, %{state | windows: %{}, escalated: %{}}}
  end

  # ---------------------------------------------------------------------------
  # Escalation logic
  # ---------------------------------------------------------------------------

  defp update_escalation(state, windows, task_type) do
    local_key = {:local, task_type}
    cloud_key = {:cloud, task_type}

    local_window = Map.get(windows, local_key, [])
    cloud_window = Map.get(windows, cloud_key, [])

    local_rate = success_rate(local_window)
    currently_escalated = Map.get(state.escalated, task_type, false)

    cond do
      length(local_window) < 3 ->
        state.escalated

      local_rate < state.threshold and not currently_escalated ->
        Logger.warning("QualityGate: escalating #{task_type} to cloud",
          local_rate: Float.round(local_rate, 2),
          threshold: state.threshold,
          window_size: length(local_window)
        )

        Map.put(state.escalated, task_type, true)

      currently_escalated ->
        cloud_successes = Enum.count(cloud_window, &(&1 == :success))

        if cloud_successes >= state.cooldown do
          Logger.info("QualityGate: de-escalating #{task_type} back to local",
            cloud_successes: cloud_successes,
            cooldown: state.cooldown
          )

          Map.put(state.escalated, task_type, false)
        else
          state.escalated
        end

      true ->
        state.escalated
    end
  end

  defp success_rate([]), do: 0.0

  defp success_rate(window) do
    Enum.count(window, &(&1 == :success)) / length(window)
  end

  defp config(key, default) do
    get_in(Application.get_env(:krait, __MODULE__, []), [key]) || default
  end
end
