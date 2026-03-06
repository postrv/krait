defmodule Krait.Analyzer.Deep do
  @moduledoc """
  Bridges to narsil-mcp running as a managed sidecar process.

  Uses MCP protocol (JSON-RPC 2.0 over stdio) for deep analysis.
  The GenServer owns a Port to the narsil-mcp binary and multiplexes
  concurrent `tools/call` requests over the single stdio channel,
  correlating responses by JSON-RPC id.

  ## Configuration

      config :krait, Krait.Analyzer.Deep,
        narsil_binary: "narsil-mcp",
        preset: "security"

  When the binary is unavailable (dev machines without narsil-mcp),
  tests are excluded via `@moduletag :narsil_required` and the
  `Krait.Analyzer.DeepMock` (Mox) is used instead.
  """

  @behaviour Krait.Analyzer.DeepBehaviour

  use GenServer

  require Logger

  @default_timeout 30_000

  # ---------------------------------------------------------------------------
  # Client API
  # ---------------------------------------------------------------------------

  @doc "Start the Deep Analyzer GenServer, opening a port to narsil-mcp."
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @impl Krait.Analyzer.DeepBehaviour
  def security_scan(file_path) do
    case call_tool("scan_security", %{repo: repo_name(), path: file_path, severity: "low"}) do
      {:ok, result} -> {:ok, extract_content_text(result)}
      error -> error
    end
  end

  @impl Krait.Analyzer.DeepBehaviour
  def taint_analysis(function_name, file_path) do
    case call_tool("analyze_taint", %{
           repo: repo_name(),
           function: function_name,
           file: file_path
         }) do
      {:ok, result} -> {:ok, extract_content_text(result)}
      error -> error
    end
  end

  @impl Krait.Analyzer.DeepBehaviour
  def call_graph(file_path) do
    case call_tool("get_call_graph", %{repo: repo_name(), file: file_path, depth: 3}) do
      {:ok, result} -> {:ok, extract_content_text(result)}
      error -> error
    end
  end

  @impl Krait.Analyzer.DeepBehaviour
  def infer_types(file_path, function_name) do
    case call_tool("infer_types", %{
           repo: repo_name(),
           file: file_path,
           function: function_name
         }) do
      {:ok, result} -> {:ok, extract_content_text(result)}
      error -> error
    end
  end

  @impl Krait.Analyzer.DeepBehaviour
  def dead_code(file_path) do
    case call_tool("detect_dead_code", %{repo: repo_name(), path: file_path}) do
      {:ok, result} -> {:ok, extract_content_text(result)}
      error -> error
    end
  end

  @impl Krait.Analyzer.DeepBehaviour
  def dependency_audit(repo_path) do
    case call_tool("generate_sbom", %{
           repo: repo_name(),
           path: repo_path,
           format: "cyclonedx"
         }) do
      {:ok, result} -> {:ok, extract_content_text(result)}
      error -> error
    end
  end

  # ---------------------------------------------------------------------------
  # GenServer Callbacks
  # ---------------------------------------------------------------------------

  @impl GenServer
  def init(opts) do
    repo_path = Keyword.fetch!(opts, :repo_path)

    narsil_binary =
      Application.get_env(:krait, Krait.Analyzer.Deep)[:narsil_binary] || "narsil-mcp"

    preset = Application.get_env(:krait, Krait.Analyzer.Deep)[:preset] || "security"

    case validate_binary_path(narsil_binary) do
      :ok -> :ok
      {:error, reason} -> raise "Invalid narsil binary path: #{reason}"
    end

    # v20 H-5: In prod, require absolute path (no PATH hijacking via System.find_executable)
    executable =
      if Application.get_env(:krait, :env) == :prod do
        if Path.type(narsil_binary) != :absolute do
          raise "In production, narsil_binary must be an absolute path (got: #{narsil_binary})"
        end

        narsil_binary
      else
        System.find_executable(narsil_binary) || narsil_binary
      end

    port =
      Port.open(
        {:spawn_executable, executable},
        [
          :binary,
          :exit_status,
          :use_stdio,
          {:args, ["--repos", repo_path, "--call-graph", "--preset", preset]}
        ]
      )

    Logger.info("Narsil MCP sidecar started: #{executable} (preset=#{preset})")

    {:ok, %{port: port, pending: %{}, next_id: 1, buffer: ""}}
  end

  @impl GenServer
  def handle_call({:tool_call, tool, params}, from, state) do
    id = state.next_id

    request =
      Jason.encode!(%{
        jsonrpc: "2.0",
        id: id,
        method: "tools/call",
        params: %{name: tool, arguments: params}
      })

    Port.command(state.port, request <> "\n")
    pending = Map.put(state.pending, id, from)
    {:noreply, %{state | pending: pending, next_id: id + 1}}
  end

  @impl GenServer
  def handle_info({port, {:data, data}}, %{port: port} = state) do
    buffer = state.buffer <> data
    {messages, remaining} = extract_messages(buffer)

    state = %{state | buffer: remaining}

    state =
      Enum.reduce(messages, state, fn msg, acc ->
        case Jason.decode(msg) do
          {:ok, %{"id" => id, "result" => result}} ->
            case Map.pop(acc.pending, id) do
              {nil, _pending} ->
                Logger.warning("Narsil MCP: received response for unknown id=#{id}")
                acc

              {from, pending} ->
                GenServer.reply(from, {:ok, result})
                %{acc | pending: pending}
            end

          {:ok, %{"id" => id, "error" => error}} ->
            case Map.pop(acc.pending, id) do
              {nil, _pending} ->
                Logger.warning("Narsil MCP: received error for unknown id=#{id}")
                acc

              {from, pending} ->
                GenServer.reply(from, {:error, error})
                %{acc | pending: pending}
            end

          {:ok, _notification} ->
            # JSON-RPC notifications (no id) are silently ignored
            acc

          {:error, decode_error} ->
            Logger.warning("Narsil MCP: failed to decode message",
              error: Exception.message(decode_error)
            )

            acc
        end
      end)

    {:noreply, state}
  end

  def handle_info({port, {:exit_status, status}}, %{port: port} = state) do
    Logger.error("Narsil MCP sidecar exited with status #{status}")

    # Reply to all pending callers with an error
    for {_id, from} <- state.pending do
      GenServer.reply(from, {:error, :narsil_exited})
    end

    {:stop, :narsil_exited, %{state | pending: %{}}}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  @impl GenServer
  def terminate(_reason, %{port: port}) do
    # Attempt graceful shutdown: close stdin so narsil-mcp gets EOF
    try do
      Port.close(port)
    rescue
      e in ArgumentError ->
        Logger.debug("Port already closed: #{inspect(e)}")
        :ok

      e in ErlangError ->
        Logger.debug("Port close error: #{inspect(e)}")
        :ok

      e in [RuntimeError, SystemLimitError] ->
        Logger.warning(
          "Unexpected port close error (#{inspect(e.__struct__)}): #{Exception.message(e)}"
        )

        :ok
    end

    :ok
  end

  def terminate(_reason, _state), do: :ok

  # ---------------------------------------------------------------------------
  # Private helpers
  # ---------------------------------------------------------------------------

  @doc false
  def validate_binary_path(path) when is_binary(path) do
    cond do
      String.contains?(path, "..") ->
        {:error, "path contains '..'"}

      Path.type(path) == :absolute and not File.exists?(path) ->
        {:error, "absolute path does not exist"}

      true ->
        :ok
    end
  end

  def validate_binary_path(_), do: {:error, "invalid path type"}

  defp repo_name do
    Application.get_env(:krait, :repo_name_short, "krait")
  end

  # MCP tools/call returns {"content" => [%{"text" => "...", "type" => "text"}]}
  # Extract the text content, attempting JSON parse for structured results.
  defp extract_content_text(%{"content" => content}) when is_list(content) do
    text =
      content
      |> Enum.filter(&(&1["type"] == "text"))
      |> Enum.map_join("\n", & &1["text"])

    # Try to parse as JSON (some tools return structured JSON in text)
    case Jason.decode(text) do
      {:ok, parsed} -> parsed
      {:error, _} -> text
    end
  end

  defp extract_content_text(result) when is_map(result), do: result
  defp extract_content_text(result), do: result

  defp call_tool(tool_name, params) do
    GenServer.call(__MODULE__, {:tool_call, tool_name, params}, @default_timeout)
  end

  @doc false
  def extract_messages(buffer) do
    lines = String.split(buffer, "\n")
    {complete, [remaining]} = Enum.split(lines, -1)
    {Enum.reject(complete, &(&1 == "")), remaining}
  end
end
