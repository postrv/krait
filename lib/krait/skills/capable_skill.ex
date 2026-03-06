defmodule Krait.Skills.CapableSkill do
  @moduledoc """
  Contract for capability-aware skill implementations.

  Unlike `Krait.Skills.Skill`, which allows direct calls to framework
  modules (WebFetch, Filesystem, etc.), CapableSkill receives only the
  capabilities it declares via `required_capabilities/0`. This enforces
  the principle of least privilege: a skill that only needs network
  access cannot touch the filesystem.

  ## Usage

      defmodule MySkill do
        @behaviour Krait.Skills.CapableSkill

        @impl true
        def name, do: "my_skill"

        @impl true
        def description, do: "Does something useful"

        @impl true
        def required_capabilities, do: [:network]

        @impl true
        def execute(params, capabilities) do
          network = capabilities.network
          network.fetch("https://example.com/api")
        end
      end
  """

  @type capability_name :: :filesystem | :network | :memory
  @type capabilities :: %{optional(capability_name()) => module()}

  @callback name() :: String.t()
  @callback description() :: String.t()
  @callback trigger_phrases() :: [String.t()]
  @callback required_capabilities() :: [capability_name()]
  @callback execute(params :: map(), capabilities :: capabilities()) ::
              {:ok, term()} | {:error, term()}

  @optional_callbacks [trigger_phrases: 0]
end
