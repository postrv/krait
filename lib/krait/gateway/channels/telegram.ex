defmodule Krait.Gateway.Channels.Telegram do
  @moduledoc "Telegram Bot API channel with polling support"
  @behaviour Krait.Gateway.Channel

  use GenServer
  require Logger

  @default_base_url "https://api.telegram.org"
  @default_poll_interval 1_000

  @impl Krait.Gateway.Channel
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  @impl Krait.Gateway.Channel
  def send_message(pid, recipient, message) do
    GenServer.call(pid, {:send_message, recipient, message})
  end

  @impl Krait.Gateway.Channel
  def channel_type, do: :telegram

  @doc "Start the polling loop for incoming messages"
  def start_polling(pid) do
    GenServer.cast(pid, :start_polling)
  end

  @doc "Stop the polling loop"
  def stop_polling(pid) do
    GenServer.cast(pid, :stop_polling)
  end

  @impl GenServer
  def init(opts) do
    raw_token = Keyword.fetch!(opts, :token)
    base_url = Keyword.get(opts, :base_url, @default_base_url)
    poll_interval = Keyword.get(opts, :poll_interval, @default_poll_interval)
    handler = Keyword.get(opts, :handler)
    auto_poll = Keyword.get(opts, :auto_poll, false)

    # v25 M-7: Store token in :persistent_term keyed by this process.
    # :persistent_term values don't appear in crash dumps and are isolated
    # per key. Combined with v24 F-17 closure for defense-in-depth.
    pt_key = {__MODULE__, :token, self()}
    :persistent_term.put(pt_key, raw_token)
    token_fn = fn -> :persistent_term.get(pt_key) end

    state = %{
      token: token_fn,
      token_pt_key: pt_key,
      base_url: base_url,
      poll_interval: poll_interval,
      last_update_id: 0,
      polling: false,
      handler: handler
    }

    if auto_poll do
      send(self(), :poll)
      {:ok, %{state | polling: true}}
    else
      {:ok, state}
    end
  end

  @impl GenServer
  def handle_call({:send_message, chat_id, text}, _from, state) do
    url = "#{state.base_url}/bot#{state.token.()}/sendMessage"

    case Req.post(url,
           json: %{chat_id: chat_id, text: text, parse_mode: "Markdown"},
           redirect: false
         ) do
      {:ok, %{status: 200, body: %{"ok" => true}}} ->
        {:reply, :ok, state}

      {:ok, %{status: status, body: body}} ->
        {:reply, {:error, {status, body}}, state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl GenServer
  def handle_cast(:start_polling, state) do
    unless state.polling do
      send(self(), :poll)
    end

    {:noreply, %{state | polling: true}}
  end

  def handle_cast(:stop_polling, state) do
    {:noreply, %{state | polling: false}}
  end

  @impl GenServer
  def handle_info(:poll, %{polling: false} = state) do
    {:noreply, state}
  end

  def handle_info(:poll, state) do
    state = poll_updates(state)
    Process.send_after(self(), :poll, state.poll_interval)
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # v25 M-7: Clean up persistent_term token on process termination
  @impl GenServer
  def terminate(_reason, state) do
    if pt_key = Map.get(state, :token_pt_key) do
      :persistent_term.erase(pt_key)
    end

    :ok
  end

  # v22 SEC-11: Redact bot token from crash logs and :sys.get_status output
  # v24 F-17: Token is already a closure (opaque in crash dumps), but
  # format_status still replaces it for :sys.get_status readability.
  @impl GenServer
  def format_status(_opt, [_pdict, state]) do
    %{state | token: fn -> "**redacted**" end}
  end

  # --- Polling ---

  defp poll_updates(state) do
    url = "#{state.base_url}/bot#{state.token.()}/getUpdates"

    params = %{
      offset: state.last_update_id + 1,
      timeout: 0
    }

    case Req.get(url, params: params, redirect: false) do
      {:ok, %{status: 200, body: %{"ok" => true, "result" => updates}}} ->
        process_updates(updates, state)

      {:ok, %{status: status, body: _body}} ->
        Logger.warning("Telegram poll failed", status: status)
        state

      {:error, reason} ->
        Logger.warning("Telegram poll error",
          error: Exception.message(reason)
        )

        state
    end
  end

  defp process_updates([], state), do: state

  defp process_updates(updates, state) do
    Enum.each(updates, fn update ->
      handle_update(update, state)
    end)

    last_id =
      updates
      |> Enum.map(& &1["update_id"])
      |> Enum.max()

    %{state | last_update_id: last_id}
  end

  defp handle_update(%{"message" => %{"chat" => %{"id" => chat_id}, "text" => text}}, state) do
    Logger.info("Telegram message received", chat_id: chat_id)

    if state.handler do
      state.handler.(:telegram, to_string(chat_id), text)
    end
  end

  defp handle_update(_update, _state), do: :ok
end
