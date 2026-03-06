defmodule KraitWeb.Auth do
  @moduledoc """
  Shared authentication helpers for admin access.

  Centralizes the admin token resolution logic used by RequireAdminAuth plug,
  EvolutionLive mount, and AdminSessionController.
  """

  require Logger

  @doc """
  Returns the configured admin token.

  v23 H-4: No longer falls back to `:api_auth_token`. Returns nil when
  `:admin_auth_token` is not set, which disables admin login. Production
  enforces via `validate_admin_token!/0` in application.ex.
  """
  @spec admin_token() :: String.t() | nil
  def admin_token do
    case Application.get_env(:krait, :admin_auth_token) do
      nil ->
        Logger.warning("KRAIT_ADMIN_TOKEN not set — admin login disabled")
        nil

      "" ->
        Logger.warning("KRAIT_ADMIN_TOKEN is empty — admin login disabled")
        nil

      token ->
        token
    end
  end

  @doc """
  Verify an admin session signed token against the expected admin token.

  v23 H-2: Compares SHA-256 hash of expected token against the hash stored
  in the session. Raw token is never stored in the signed session cookie.
  Returns `:ok` if the session is valid, `:error` otherwise.
  """
  @spec verify_admin_session(String.t() | nil) :: :ok | :error
  def verify_admin_session(nil), do: :error

  def verify_admin_session(session_signed) do
    expected = admin_token()

    if is_nil(expected) do
      :error
    else
      case KraitWeb.AdminSessionController.verify_session_token(session_signed) do
        {:ok, token_hash} ->
          expected_hash = :crypto.hash(:sha256, expected) |> Base.encode64()
          if Plug.Crypto.secure_compare(token_hash, expected_hash), do: :ok, else: :error

        {:error, _} ->
          :error
      end
    end
  end
end
