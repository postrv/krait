defmodule KraitWeb.Plugs.AdminApiAuth do
  @moduledoc """
  Bearer token authentication for admin API routes.

  Reads the expected token from config at runtime:

      config :krait, :admin_auth_token, "your-admin-secret"

  v25 H-1: Separates admin operations (kill switch) from read-only API
  access. The regular `KRAIT_API_TOKEN` is NOT accepted on admin routes.
  """

  import Plug.Conn
  require Logger

  @behaviour Plug

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, _opts) do
    case expected_token() do
      nil ->
        cond do
          Application.get_env(:krait, :env, :dev) == :test and
              Application.get_env(:krait, :disable_auth, false) ->
            conn

          true ->
            Logger.warning("Admin API auth rejected: admin token not configured",
              env: Application.get_env(:krait, :env, :dev)
            )

            conn
            |> put_status(503)
            |> Phoenix.Controller.json(%{error: "Service unavailable"})
            |> halt()
        end

      expected ->
        case get_req_header(conn, "authorization") do
          ["Bearer " <> token] ->
            if Plug.Crypto.secure_compare(token, expected) do
              conn
            else
              conn
              |> put_status(401)
              |> Phoenix.Controller.json(%{error: "unauthorized"})
              |> halt()
            end

          _ ->
            conn
            |> put_status(401)
            |> Phoenix.Controller.json(%{error: "unauthorized"})
            |> halt()
        end
    end
  end

  defp expected_token do
    Application.get_env(:krait, :admin_auth_token)
  end
end
