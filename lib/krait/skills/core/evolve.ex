defmodule Krait.Skills.Core.Evolve do
  @moduledoc "Skill that triggers self-evolution from conversation"
  @behaviour Krait.Skills.Skill

  alias Krait.Evolution.Naming

  @impl true
  def name, do: "evolve"

  @impl true
  def description, do: "Propose a new skill by triggering self-evolution"

  @impl true
  def trigger_phrases, do: ["evolve", "learn", "add skill", "teach yourself"]

  @impl true
  def execute(%{"skill_name" => skill_name, "description" => description} = params) do
    with :ok <- check_kill_switch(),
         :ok <- check_cooldown(),
         :ok <- acquire_slot(),
         {:ok, validated_name} <- Naming.validate_skill_name(skill_name) do
      try do
        evolution_params = %{
          skill_name: validated_name,
          description: description,
          trigger: Map.get(params, "trigger", description),
          target_path: "lib/krait/skills/community/#{validated_name}.ex",
          test_path: "test/krait/skills/community/#{validated_name}_test.exs"
        }

        case Krait.Evolution.evolve(evolution_params) do
          {:ok, result} ->
            record_cooldown()
            {:ok, result}

          {:error, :max_retries_exhausted, details} ->
            {:error, "Evolution failed after #{details.attempts} attempts"}

          {:error, reason} ->
            {:error, "Evolution failed: #{inspect(reason)}"}
        end
      after
        release_slot()
      end
    else
      {:error, :system_halted} ->
        {:error, "Evolution is currently disabled by the kill switch."}

      {:error, :cooldown} ->
        {:error, "Evolution is rate limited. Please wait before trying again."}

      {:error, :at_capacity} ->
        {:error, "Maximum concurrent evolutions reached. Try again later."}

      {:error, :invalid_skill_name} ->
        {:error,
         "Invalid skill name: must be lowercase alphanumeric with underscores, 1-64 chars"}
    end
  end

  def execute(_), do: {:error, "Required parameters: skill_name, description"}

  defp check_kill_switch do
    if Krait.KillSwitch.halted?(), do: {:error, :system_halted}, else: :ok
  end

  defp cooldown_ms do
    Application.get_env(:krait, :evolve_cooldown_ms, 300_000)
  end

  # v22 SEC-08: Route through EvolveCooldownServer (protected table)
  defp check_cooldown do
    case Krait.EvolveCooldownServer.lookup(:last_evolution) do
      [{:last_evolution, last_time}] ->
        elapsed = System.monotonic_time(:millisecond) - last_time

        if elapsed < cooldown_ms() do
          {:error, :cooldown}
        else
          :ok
        end

      [] ->
        :ok
    end
  end

  defp record_cooldown do
    Krait.EvolveCooldownServer.insert({:last_evolution, System.monotonic_time(:millisecond)})
  end

  # Phase 4: Slot acquisition — chat-triggered evolution must respect max_concurrent_evolutions
  defp acquire_slot do
    max = Application.get_env(:krait, :max_concurrent_evolutions, 2)
    Krait.EvolveCooldownServer.try_acquire_slot(:active_evolutions, max)
  end

  defp release_slot do
    Krait.EvolveCooldownServer.release_slot(:active_evolutions)
  end
end
