defmodule Krait.Memory.Hot do
  @moduledoc """
  Hot memory layer backed by ETS.

  Provides fast in-process key/value storage with optional TTL-based expiry.
  Reads go directly to the public ETS table for maximum throughput; writes
  are serialised through the GenServer to guarantee ownership and ordering.
  """

  use GenServer

  # ---------------------------------------------------------------------------
  # Client API
  # ---------------------------------------------------------------------------

  @doc """
  Starts the Hot memory GenServer.

  ## Options

    * `:name` — the atom used as both the GenServer registration name and the
      ETS table name. Required.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    name = Keyword.fetch!(opts, :name)
    GenServer.start_link(__MODULE__, name, name: name)
  end

  @doc """
  Stores `value` under `key`. Overwrites any previous value.

  Returns `:ok`.
  """
  @spec put(GenServer.server(), term(), term(), keyword()) :: :ok
  def put(server, key, value, opts \\ []) do
    GenServer.call(server, {:put, key, value, opts})
  end

  @doc """
  Retrieves the value stored under `key`.

  Returns `{:ok, value}` if the key exists and has not expired, or `:not_found`
  otherwise.
  """
  @spec get(GenServer.server(), term()) :: {:ok, term()} | :not_found
  def get(server, key) do
    table = table_for(server)

    case :ets.lookup(table, key) do
      [{^key, value, nil}] ->
        {:ok, value}

      [{^key, value, expires_at}] ->
        if System.monotonic_time(:millisecond) < expires_at do
          {:ok, value}
        else
          :not_found
        end

      [] ->
        :not_found
    end
  end

  @doc """
  Deletes `key` from the table.

  Returns `:ok` regardless of whether the key existed.
  """
  @spec delete(GenServer.server(), term()) :: :ok
  def delete(server, key) do
    GenServer.call(server, {:delete, key})
  end

  @doc """
  Returns a list of keys whose string representation starts with `prefix`.

  Only non-expired keys are returned.
  """
  @spec list_keys(GenServer.server(), String.t()) :: [term()]
  def list_keys(server, prefix) do
    table = table_for(server)
    now = System.monotonic_time(:millisecond)

    :ets.tab2list(table)
    |> Enum.filter(fn {key, _value, expires_at} ->
      String.starts_with?(to_string(key), prefix) and
        (is_nil(expires_at) or now < expires_at)
    end)
    |> Enum.map(fn {key, _value, _expires_at} -> key end)
  end

  # ---------------------------------------------------------------------------
  # Server callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init(name) do
    table = :ets.new(name, [:set, :protected, :named_table, read_concurrency: true])
    {:ok, %{table: table}}
  end

  @impl true
  def handle_call({:put, key, value, opts}, _from, %{table: table} = state) do
    ttl = Keyword.get(opts, :ttl)

    expires_at =
      if ttl do
        deadline = System.monotonic_time(:millisecond) + ttl
        Process.send_after(self(), {:expire, key, deadline}, ttl)
        deadline
      end

    :ets.insert(table, {key, value, expires_at})
    {:reply, :ok, state}
  end

  def handle_call({:delete, key}, _from, %{table: table} = state) do
    :ets.delete(table, key)
    {:reply, :ok, state}
  end

  @impl true
  def handle_info({:expire, key, deadline}, %{table: table} = state) do
    # Only delete if the entry still has the same deadline — a newer `put` for
    # the same key may have installed a later (or no) expiry.
    case :ets.lookup(table, key) do
      [{^key, _value, ^deadline}] -> :ets.delete(table, key)
      _ -> :ok
    end

    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  # Resolves the ETS table name from a server reference.  When the server is
  # registered under an atom (the common path), that atom doubles as the table
  # name, so we can skip a GenServer round-trip entirely.
  defp table_for(server) when is_atom(server), do: server

  defp table_for(server) when is_pid(server) do
    case Process.info(server, :registered_name) do
      {:registered_name, name} when is_atom(name) -> name
      _ -> GenServer.call(server, :table)
    end
  end
end
