defmodule Krait.Gateway.Channels.Console do
  @moduledoc """
  A synchronous, in-process channel for testing and development.
  Messages go in, responses come out. No network involved.
  """

  use GenServer

  # --- Client API ---

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  def send_user_message(pid, message) do
    GenServer.call(pid, {:user_message, message}, 60_000)
  end

  def get_brain_pid(pid) do
    GenServer.call(pid, :get_brain_pid)
  end

  # --- GenServer Callbacks ---

  @impl true
  def init(opts) do
    brain_opts = Keyword.get(opts, :brain_opts, [])

    # Ensure session_id is set
    brain_opts =
      if Keyword.has_key?(brain_opts, :session_id) do
        brain_opts
      else
        Keyword.put(brain_opts, :session_id, "console-#{System.unique_integer([:positive])}")
      end

    {:ok, brain_pid} = Krait.Brain.Brain.start_link(brain_opts)

    {:ok, %{brain_pid: brain_pid}}
  end

  @impl true
  def handle_call(:get_brain_pid, _from, state) do
    {:reply, state.brain_pid, state}
  end

  @impl true
  def handle_call({:user_message, message}, _from, state) do
    result = Krait.Brain.Brain.process_message(state.brain_pid, message)
    {:reply, result, state}
  end
end
