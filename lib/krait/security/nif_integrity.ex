defmodule Krait.Security.NifIntegrity do
  @moduledoc """
  Verifies NIF binary hash at application boot in production.

  The expected hash is stored in a `.sha256` sidecar file alongside the NIF
  binary, computed during `mix release`. This detects binary swaps between
  build and boot time.
  """

  require Logger

  @doc """
  Verify the NIF binary matches its expected hash.

  - If the `.sha256` sidecar file exists, verifies the hash and raises on mismatch.
  - If the sidecar file is absent, logs a warning and returns `:ok` (dev environments).
  - If the NIF binary itself is absent, returns `:ok` (NIF may be optional).
  """
  @spec verify!() :: :ok
  def verify! do
    nif_path = nif_binary_path()

    cond do
      is_nil(nif_path) ->
        Logger.info("[NifIntegrity] NIF binary path not found, skipping verification")
        :ok

      not File.exists?(nif_path) ->
        Logger.info("[NifIntegrity] NIF binary not found at #{nif_path}, skipping verification")
        :ok

      true ->
        verify_with_sidecar(nif_path)
    end
  end

  @doc """
  Compute SHA256 hash of a file. Used by release steps and tests.
  """
  @spec compute_hash(String.t()) :: String.t()
  def compute_hash(path) do
    :crypto.hash(:sha256, File.read!(path)) |> Base.encode16(case: :lower)
  end

  defp verify_with_sidecar(nif_path) do
    hash_path = nif_path <> ".sha256"

    if File.exists?(hash_path) do
      expected = File.read!(hash_path) |> String.trim()
      actual = compute_hash(nif_path)

      if actual != expected do
        raise "[SECURITY] NIF binary hash mismatch! Expected #{expected}, got #{actual}. " <>
                "The NIF binary may have been tampered with."
      end

      Logger.info("[NifIntegrity] NIF binary hash verified: #{String.slice(actual, 0, 16)}...")
      :ok
    else
      # v25 L-6: Fail-closed in prod when sidecar is missing
      if Application.get_env(:krait, :env) == :prod do
        raise "[SECURITY] NIF .sha256 sidecar missing in production — " <>
                "NIF integrity cannot be verified. Build the release with hash generation."
      else
        Logger.warning("[NifIntegrity] No .sha256 sidecar found for NIF, skipping verification")
        :ok
      end
    end
  end

  defp nif_binary_path do
    priv_dir = :code.priv_dir(:krait) |> to_string()

    # Try common NIF binary names (macOS .dylib, Linux .so)
    Enum.find_value(["libkrait_analyzer.so", "libkrait_analyzer.dylib"], fn name ->
      path = Path.join([priv_dir, "native", name])
      if File.exists?(path), do: path
    end)
  rescue
    _ -> nil
  end
end
