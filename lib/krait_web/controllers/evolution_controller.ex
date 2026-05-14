defmodule KraitWeb.EvolutionController do
  use KraitWeb, :controller

  require Logger

  alias Krait.Evolution.Naming
  alias Krait.Security.PromptSanitizer

  @max_description_length 2000

  def trigger(conn, %{"skill_name" => raw_name, "description" => description}) do
    with :ok <- check_kill_switch(),
         {:ok, skill_name} <- Naming.validate_skill_name(raw_name),
         {:ok, clean_desc} <- validate_description(description),
         :ok <- acquire_evolution_slot() do
      {:ok, task_pid} =
        Task.Supervisor.start_child(Krait.TaskSupervisor, fn ->
          try do
            Logger.info("Evolution task starting for #{skill_name}")

            result =
              evolution_runner().evolve(%{
                skill_name: skill_name,
                description: clean_desc,
                trigger: clean_desc,
                target_path: "lib/krait/skills/community/#{skill_name}.ex",
                test_path: "test/krait/skills/community/#{skill_name}_test.exs"
              })

            Logger.info("Evolution task completed",
              status: if(match?({:ok, _}, result), do: :ok, else: :error)
            )
          rescue
            e ->
              Logger.error("Evolution task failed",
                skill_name: skill_name,
                error: Exception.message(e)
              )
          after
            release_evolution_slot()
          end
        end)

      # v24 F-24: Safety net — auto-release slot if task crashes without running `after`
      Krait.EvolveCooldownServer.register_slot_owner(:active_evolutions, task_pid)

      json(conn, %{status: "evolution_started", skill_name: skill_name})
    else
      {:error, :invalid_skill_name} ->
        conn
        |> put_status(422)
        |> json(%{
          error: "invalid_skill_name",
          message:
            "Skill name must be lowercase alphanumeric with underscores, " <>
              "starting with a letter, max 64 chars"
        })

      {:error, :description_too_long} ->
        conn
        |> put_status(422)
        |> json(%{
          error: "invalid_description",
          message: "Description must be #{@max_description_length} characters or fewer"
        })

      {:error, :description_contains_null_bytes} ->
        conn
        |> put_status(422)
        |> json(%{
          error: "invalid_description",
          message: "Description contains invalid characters"
        })

      {:error, :at_capacity} ->
        conn
        |> put_status(429)
        |> json(%{
          error: "at_capacity",
          message: "Maximum concurrent evolutions reached. Try again later."
        })

      {:error, :system_halted} ->
        conn
        |> put_status(503)
        |> json(%{
          error: "system_halted",
          message: "Evolution is currently disabled."
        })
    end
  end

  def trigger(conn, _params) do
    conn
    |> put_status(400)
    |> json(%{error: "missing_params", message: "skill_name and description are required"})
  end

  # v24 F-18: Redact description/draft/reasoning — expose only safe fields
  def feed(conn, _params) do
    events =
      Krait.Evolution.Feed.list(limit: 50)
      |> Enum.map(fn e ->
        %{
          id: e.id,
          skill_name: e.skill_name,
          status: if(e.draft, do: "draft", else: "completed"),
          attempts: e.attempts,
          pr_url: e.pr_url,
          timestamp:
            (Map.get(e, :inserted_at) || Map.get(e, :timestamp)) &&
              DateTime.to_string(Map.get(e, :inserted_at) || Map.get(e, :timestamp))
        }
      end)

    json(conn, %{count: length(events), events: events})
  end

  defp check_kill_switch do
    if Krait.KillSwitch.halted?(), do: {:error, :system_halted}, else: :ok
  end

  defp evolution_runner do
    Application.get_env(:krait, :evolution_runner, Krait.Evolution)
  end

  # v24 F-05: Atomic slot acquisition — serialized by GenServer, no race condition
  defp acquire_evolution_slot do
    max = Application.get_env(:krait, :max_concurrent_evolutions, 2)
    Krait.EvolveCooldownServer.try_acquire_slot(:active_evolutions, max)
  end

  defp release_evolution_slot do
    Krait.EvolveCooldownServer.release_slot(:active_evolutions)
  end

  # v24 F-19: Character-based length check (String.length, not byte_size)
  # Multi-byte chars like emoji should count as 1, not 3-4.
  # v25 H-3: Uses PromptSanitizer to strip injection patterns before LLM
  defp validate_description(desc) do
    cond do
      String.contains?(desc, "\0") ->
        {:error, :description_contains_null_bytes}

      String.length(desc) > @max_description_length ->
        {:error, :description_too_long}

      true ->
        {:ok, PromptSanitizer.sanitize_strict(desc)}
    end
  end
end
