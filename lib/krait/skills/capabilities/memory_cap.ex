defmodule Krait.Skills.Capabilities.MemoryCap do
  @moduledoc """
  Memory capability — provides key-value store operations.
  Delegates to `Krait.Skills.Core.MemorySkill` under the hood.
  """

  alias Krait.Skills.Core.MemorySkill

  @spec read(String.t()) :: {:ok, term()} | {:error, term()}
  def read(key) when is_binary(key) do
    MemorySkill.execute(%{"action" => "recall", "key" => key})
  end

  @spec write(String.t(), String.t()) :: {:ok, term()} | {:error, term()}
  def write(key, value) when is_binary(key) and is_binary(value) do
    MemorySkill.execute(%{"action" => "store", "key" => key, "value" => value})
  end

  @spec list() :: {:ok, term()} | {:error, term()}
  def list do
    MemorySkill.execute(%{"action" => "list"})
  end

  @spec list(String.t()) :: {:ok, term()} | {:error, term()}
  def list(prefix) when is_binary(prefix) do
    MemorySkill.execute(%{"action" => "list", "prefix" => prefix})
  end
end
