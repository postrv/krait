defmodule Krait.Gateway.Router do
  @moduledoc "Routes incoming messages from channels to Brain instances"

  use GenServer
  require Logger

  @sweep_interval :timer.minutes(5)
  @conversation_ttl :timer.minutes(30)
  @default_max_conversations 100

  # --- Client API ---

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @doc "Route a message from a channel to the appropriate Brain instance"
  @spec route_message(GenServer.server(), atom(), String.t(), String.t()) ::
          {:ok, String.t()} | {:error, term()}
  def route_message(server \\ __MODULE__, channel_type, conversation_id, message) do
    GenServer.call(server, {:route_message, channel_type, conversation_id, message}, 60_000)
  end

  @doc "Register a channel with the router"
  @spec register_channel(GenServer.server(), atom(), pid()) :: :ok
  def register_channel(server \\ __MODULE__, channel_type, channel_pid) do
    GenServer.call(server, {:register_channel, channel_type, channel_pid})
  end

  @doc "List active conversations"
  @spec list_conversations(GenServer.server()) :: [map()]
  def list_conversations(server \\ __MODULE__) do
    GenServer.call(server, :list_conversations)
  end

  # --- GenServer Callbacks ---

  @impl true
  def init(opts) do
    brain_opts = Keyword.get(opts, :brain_opts, [])
    sweep_interval = Keyword.get(opts, :sweep_interval, @sweep_interval)

    if sweep_interval > 0 do
      Process.send_after(self(), :sweep_conversations, sweep_interval)
    end

    max_conversations =
      Keyword.get(opts, :max_conversations, @default_max_conversations)

    {:ok,
     %{
       channels: %{},
       conversations: %{},
       last_activity: %{},
       brain_opts: brain_opts,
       sweep_interval: sweep_interval,
       max_conversations: max_conversations
     }}
  end

  @impl true
  def handle_call({:route_message, channel_type, conversation_id, message}, _from, state) do
    session_key = {channel_type, conversation_id}

    case get_or_create_brain(session_key, state) do
      {:ok, brain_pid, state} ->
        now = System.monotonic_time(:millisecond)
        new_activity = Map.put(state.last_activity, session_key, now)
        result = Krait.Brain.Brain.process_message(brain_pid, message)
        {:reply, result, %{state | last_activity: new_activity}}

      {:error, :at_capacity} ->
        {:reply, {:error, :at_capacity}, state}
    end
  end

  def handle_call({:register_channel, channel_type, channel_pid}, _from, state) do
    channels = Map.put(state.channels, channel_type, channel_pid)
    {:reply, :ok, %{state | channels: channels}}
  end

  def handle_call(:list_conversations, _from, state) do
    convos =
      Enum.map(state.conversations, fn {{channel_type, conversation_id}, pid} ->
        %{channel: channel_type, conversation_id: conversation_id, brain_pid: pid}
      end)

    {:reply, convos, state}
  end

  # v24 F-27: Enforce max concurrent conversations
  defp get_or_create_brain(session_key, state) do
    case Map.get(state.conversations, session_key) do
      nil ->
        # New conversation — check capacity
        if map_size(state.conversations) >= state.max_conversations do
          Logger.warning("[SECURITY] Max concurrent conversations reached",
            max: state.max_conversations
          )

          {:error, :at_capacity}
        else
          opts =
            Keyword.merge(state.brain_opts,
              session_id: "#{elem(session_key, 0)}-#{elem(session_key, 1)}"
            )

          {:ok, pid} = Krait.Brain.Brain.start_link(opts)
          new_convos = Map.put(state.conversations, session_key, pid)
          {:ok, pid, %{state | conversations: new_convos}}
        end

      pid ->
        if Process.alive?(pid) do
          {:ok, pid, state}
        else
          opts =
            Keyword.merge(state.brain_opts,
              session_id: "#{elem(session_key, 0)}-#{elem(session_key, 1)}"
            )

          {:ok, new_pid} = Krait.Brain.Brain.start_link(opts)
          new_convos = Map.put(state.conversations, session_key, new_pid)
          {:ok, new_pid, %{state | conversations: new_convos}}
        end
    end
  end

  @impl true
  def handle_info(:sweep_conversations, state) do
    now = System.monotonic_time(:millisecond)

    {keep, remove} =
      Enum.split_with(state.conversations, fn {key, pid} ->
        alive = Process.alive?(pid)
        last = Map.get(state.last_activity, key, 0)
        alive and now - last < @conversation_ttl
      end)

    if remove != [] do
      Logger.debug("Sweeping #{length(remove)} stale conversation(s)")
    end

    remove_keys = Enum.map(remove, fn {key, _} -> key end)

    new_state = %{
      state
      | conversations: Map.new(keep),
        last_activity: Map.drop(state.last_activity, remove_keys)
    }

    if state.sweep_interval > 0 do
      Process.send_after(self(), :sweep_conversations, state.sweep_interval)
    end

    {:noreply, new_state}
  end

  def handle_info(_msg, state), do: {:noreply, state}
end
