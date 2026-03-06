defmodule Krait.Skills.Capabilities.FilesystemCap do
  @moduledoc """
  Filesystem capability — provides sandboxed file read/list operations.
  Delegates to `Krait.Skills.Core.Filesystem` under the hood.
  """

  alias Krait.Skills.Core.Filesystem

  @spec read(String.t()) :: {:ok, String.t()} | {:error, term()}
  def read(path) when is_binary(path) do
    if String.starts_with?(path, "~/") do
      {:error, :forbidden_path}
    else
      Filesystem.execute(%{"action" => "read", "path" => path})
    end
  end

  @spec list(String.t()) :: {:ok, [String.t()]} | {:error, term()}
  def list(path) when is_binary(path) do
    if String.starts_with?(path, "~/") do
      {:error, :forbidden_path}
    else
      Filesystem.execute(%{"action" => "list", "path" => path})
    end
  end
end
