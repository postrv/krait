defmodule Krait.Skills.CapabilityInjector do
  @moduledoc """
  Builds and injects capability maps for CapableSkill execution.

  Given a skill module implementing `Krait.Skills.CapableSkill`, this module:
  1. Reads the skill's `required_capabilities/0`
  2. Maps each capability name to its implementation module
  3. Calls `skill.execute(params, capabilities_map)`

  Only declared capabilities are injected — undeclared ones are not available.
  """

  alias Krait.Skills.Capabilities.FilesystemCap
  alias Krait.Skills.Capabilities.MemoryCap
  alias Krait.Skills.Capabilities.NetworkCap

  @capability_registry %{
    filesystem: FilesystemCap,
    network: NetworkCap,
    memory: MemoryCap
  }

  @doc "Execute a CapableSkill with its declared capabilities injected"
  @spec execute_with_capabilities(module(), map()) :: {:ok, term()} | {:error, term()}
  def execute_with_capabilities(skill_module, params) do
    required = skill_module.required_capabilities()
    caps = build_capabilities(required)
    skill_module.execute(params, caps)
  end

  @doc false
  @spec build_capabilities([Krait.Skills.CapableSkill.capability_name()]) ::
          Krait.Skills.CapableSkill.capabilities()
  def build_capabilities(required) when is_list(required) do
    Map.new(required, fn cap_name ->
      case Map.fetch(@capability_registry, cap_name) do
        {:ok, module} -> {cap_name, module}
        :error -> raise ArgumentError, "Unknown capability: #{inspect(cap_name)}"
      end
    end)
  end
end
