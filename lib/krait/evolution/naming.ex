defmodule Krait.Evolution.Naming do
  @moduledoc """
  Validates and normalizes skill names for safe filesystem use.

  Skill names are used directly in file paths and module names,
  so they must be constrained to prevent path traversal and
  module injection attacks.
  """

  # Only lowercase alphanumeric + underscores, 1-64 chars, must start with letter
  @valid_skill_name ~r/^[a-z][a-z0-9_]{0,63}$/

  @doc """
  Validates a skill name is safe for use in file paths and module names.

  Returns `{:ok, sanitized_name}` or `{:error, :invalid_skill_name}`.

  ## Examples

      iex> Naming.validate_skill_name("greeting")
      {:ok, "greeting"}

      iex> Naming.validate_skill_name("../../hack")
      {:error, :invalid_skill_name}
  """
  @spec validate_skill_name(String.t()) :: {:ok, String.t()} | {:error, :invalid_skill_name}
  def validate_skill_name(name) when is_binary(name) do
    name = String.trim(name)

    if Regex.match?(@valid_skill_name, name) do
      {:ok, name}
    else
      {:error, :invalid_skill_name}
    end
  end

  def validate_skill_name(_), do: {:error, :invalid_skill_name}

  @doc "Converts a validated skill_name to a PascalCase module name suffix"
  @spec to_module_name(String.t()) :: String.t()
  def to_module_name(skill_name) do
    skill_name
    |> String.split("_")
    |> Enum.map_join(&String.capitalize/1)
  end
end
