defmodule Krait.Skills.Skill do
  @moduledoc "Contract for skill implementations"

  @callback name() :: String.t()
  @callback description() :: String.t()
  @callback trigger_phrases() :: [String.t()]
  @callback execute(params :: map()) :: {:ok, term()} | {:error, term()}

  @optional_callbacks [trigger_phrases: 0]
end
