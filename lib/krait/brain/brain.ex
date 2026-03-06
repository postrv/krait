defmodule Krait.Brain.Brain do
  @moduledoc """
  Main cognitive GenServer implementing the ReAct loop.
  Observe -> Think -> Act -> Observe.
  """

  use GenServer
  require Logger

  alias Krait.Brain.Planner
  alias Krait.Security.PromptSanitizer

  @default_max_tool_depth 10
  @max_conversation_messages 50
  @default_max_message_bytes 102_400
  @max_response_bytes 524_288

  # --- Client API ---

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  @spec process_message(pid(), String.t()) :: {:ok, String.t()} | {:error, term()}
  def process_message(pid, message) do
    GenServer.call(pid, {:process_message, message}, 60_000)
  end

  # --- GenServer Callbacks ---

  @impl true
  def init(opts) do
    llm_opts =
      Keyword.get(opts, :llm_opts, []) ++
        default_llm_opts()

    state = %{
      session_id: Keyword.fetch!(opts, :session_id),
      llm: Keyword.get(opts, :llm, Application.get_env(:krait, :llm_module)),
      llm_opts: llm_opts,
      skills: Keyword.get(opts, :skills, []),
      max_tool_depth: Keyword.get(opts, :max_tool_depth, @default_max_tool_depth),
      max_message_bytes: Keyword.get(opts, :max_message_bytes, @default_max_message_bytes),
      messages: []
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:process_message, user_message}, _from, state) do
    if byte_size(user_message) > state.max_message_bytes do
      {:reply, {:error, :message_too_large}, state}
    else
      do_process_message(user_message, state)
    end
  end

  defp do_process_message(user_message, state) do
    Logger.info("Processing message", conversation_id: state.session_id)
    sanitized = PromptSanitizer.wrap_untrusted(user_message, "user_message")

    case maybe_plan(user_message, state) do
      {:ok, steps} when length(steps) > 1 ->
        Logger.info("Executing multi-step plan", steps: length(steps))
        execute_plan(steps, state)

      _ ->
        # Single-step or no plan — fall through to existing react_loop
        messages = state.messages ++ [%{"role" => "user", "content" => sanitized}]
        tools = build_tool_defs(state.skills)

        case react_loop(
               state.llm,
               messages,
               tools,
               state.skills,
               state.llm_opts,
               state.max_tool_depth,
               0
             ) do
          {:ok, response_text, final_messages} ->
            {:reply, {:ok, response_text}, %{state | messages: trim_messages(final_messages)}}

          {:error, reason} ->
            {:reply, {:error, reason}, state}
        end
    end
  end

  # --- Planning ---

  @multi_step_pattern ~r/(first|then|after that|and also|next|finally|step \d)/i

  defp maybe_plan(message, state) do
    if length(state.skills) > 1 and warrants_planning?(message) do
      Planner.decompose(message,
        skills: state.skills,
        llm: state.llm,
        llm_opts: state.llm_opts
      )
    else
      {:ok, []}
    end
  rescue
    e ->
      Logger.warning("Planning failed, falling back to react loop",
        error: Exception.message(e)
      )

      {:ok, []}
  end

  defp warrants_planning?(message) do
    token_estimate = div(byte_size(message), 4)
    token_estimate > 100 or Regex.match?(@multi_step_pattern, message)
  end

  defp execute_plan(steps, state) do
    result =
      Enum.reduce_while(steps, {:ok, []}, fn step, {:ok, results} ->
        # Check kill switch between steps
        if function_exported?(Krait.KillSwitch, :halted?, 0) and Krait.KillSwitch.halted?() do
          {:halt, {:error, :system_halted_mid_plan}}
        else
          case execute_step(step, state) do
            {:ok, result} -> {:cont, {:ok, results ++ [result]}}
            {:error, _} = err -> {:halt, err}
          end
        end
      end)

    case result do
      {:ok, results} ->
        summary = Enum.map_join(results, "\n\n", & &1)
        {:reply, {:ok, summary}, state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  defp execute_step(%{action: :skill_call, skill: skill_name, params: params}, state) do
    case Enum.find(state.skills, fn s -> s.name == skill_name end) do
      nil -> {:error, "Unknown skill: #{skill_name}"}
      skill -> skill.execute.(params)
    end
  end

  defp execute_step(%{action: :respond, description: desc}, _state) do
    {:ok, desc || "Done."}
  end

  defp execute_step(_step, _state) do
    {:ok, "Step completed."}
  end

  # --- ReAct Loop ---

  defp react_loop(_llm, messages, _tools, _skills, _llm_opts, max_depth, depth)
       when depth >= max_depth do
    Logger.warning("Max tool depth reached", depth: depth)

    last_text =
      messages
      |> Enum.reverse()
      |> Enum.find_value("Max tool depth reached.", fn
        %{"role" => "assistant", "content" => content} when is_binary(content) ->
          content

        %{"role" => "assistant", "content" => blocks} when is_list(blocks) ->
          blocks
          |> Enum.find_value(fn
            %{"type" => "text", "text" => text} -> text
            _ -> nil
          end)

        _ ->
          nil
      end)

    {:ok, last_text, messages}
  end

  defp react_loop(llm, messages, tools, skills, llm_opts, max_depth, depth) do
    Logger.debug("ReAct loop iteration", depth: depth, tool_calls: length(tools))

    case llm.complete_with_tools(messages, tools, llm_opts) do
      {:ok, %{text: text, tool_calls: []}} ->
        text = truncate_response(text)
        final_messages = messages ++ [%{"role" => "assistant", "content" => text}]
        {:ok, text, final_messages}

      {:ok, %{text: text, tool_calls: tool_calls}} ->
        text = truncate_response(text)

        # Build assistant content blocks per Claude API spec
        text_blocks =
          if text != "", do: [%{"type" => "text", "text" => text}], else: []

        tool_use_blocks =
          Enum.map(tool_calls, fn tc ->
            %{"type" => "tool_use", "id" => tc.id, "name" => tc.name, "input" => tc.input}
          end)

        assistant_msg = %{"role" => "assistant", "content" => text_blocks ++ tool_use_blocks}
        messages = messages ++ [assistant_msg]

        # Tool results go in a single user message with tool_result blocks
        tool_result_blocks =
          Enum.map(tool_calls, fn tc ->
            result = execute_tool(tc.name, tc.input, skills)

            %{
              "type" => "tool_result",
              "tool_use_id" => tc.id,
              "content" => format_result(result)
            }
          end)

        messages = messages ++ [%{"role" => "user", "content" => tool_result_blocks}]
        react_loop(llm, messages, tools, skills, llm_opts, max_depth, depth + 1)

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp truncate_response(text) when byte_size(text) > @max_response_bytes do
    Logger.warning("LLM response truncated",
      original_size: byte_size(text),
      max: @max_response_bytes
    )

    PromptSanitizer.truncate(text, @max_response_bytes)
  end

  defp truncate_response(text), do: text

  # --- Tool execution ---

  defp execute_tool(name, input, skills) do
    case Enum.find(skills, fn s -> s.name == name end) do
      nil -> {:error, "Unknown skill: #{name}"}
      skill -> skill.execute.(input)
    end
  end

  # v24 F-10: Full sanitization on tool results (not just XML escaping)
  # v27 M-1: Upgraded to sanitize_strict/1 (double-pass) for all LLM-facing text
  defp format_result({:ok, result}) when is_binary(result),
    do: "<tool_result>#{PromptSanitizer.sanitize_strict(result)}</tool_result>"

  defp format_result({:ok, result}),
    do: "<tool_result>#{PromptSanitizer.sanitize_strict(inspect(result))}</tool_result>"

  defp format_result({:error, reason}),
    do: "<tool_result>Error: #{PromptSanitizer.sanitize_strict(inspect(reason))}</tool_result>"

  # --- Tool definition building ---

  defp build_tool_defs(skills) do
    Enum.map(skills, fn s ->
      %{
        name: s.name,
        description: Map.get(s, :description, ""),
        input_schema: build_schema(Map.get(s, :params, %{}))
      }
    end)
  end

  defp build_schema(params) when params == %{}, do: %{"type" => "object", "properties" => %{}}

  defp build_schema(params) do
    props =
      Enum.map(params, fn {k, v} ->
        {to_string(k), %{"type" => to_string(v)}}
      end)
      |> Map.new()

    %{"type" => "object", "properties" => props}
  end

  defp trim_messages(messages) when length(messages) <= @max_conversation_messages, do: messages

  defp trim_messages([%{"role" => "system"} = system_msg | rest]) do
    # Keep system message + most recent N-1 messages
    [system_msg | Enum.take(rest, -(@max_conversation_messages - 1))]
  end

  defp trim_messages(messages) do
    Enum.take(messages, -@max_conversation_messages)
  end

  defp default_llm_opts do
    key =
      Application.get_env(:krait, :openrouter_api_key) ||
        Application.get_env(:krait, :anthropic_api_key)

    case key do
      nil -> []
      k -> [api_key: k]
    end
  end
end
