defmodule KraitWeb.Plugs.JsonDepthLimit do
  @moduledoc """
  Rejects JSON payloads that exceed a maximum nesting depth.

  v25 L-8: Prevents deeply nested JSON DoS attacks (e.g., {"a":{"a":{"a":...}}}
  that can exhaust memory or cause excessive processing time.
  """

  import Plug.Conn

  @behaviour Plug

  @default_max_depth 20

  @impl true
  def init(opts), do: Keyword.get(opts, :max_depth, @default_max_depth)

  @impl true
  def call(%{body_params: %Plug.Conn.Unfetched{}} = conn, _max_depth), do: conn

  def call(%{body_params: params} = conn, max_depth) when is_map(params) do
    if json_depth(params) > max_depth do
      conn
      |> put_status(413)
      |> Phoenix.Controller.json(%{error: "JSON nesting exceeds maximum depth of #{max_depth}"})
      |> halt()
    else
      conn
    end
  end

  def call(conn, _max_depth), do: conn

  defp json_depth(value) when is_map(value) do
    if map_size(value) == 0 do
      1
    else
      1 + (value |> Map.values() |> Enum.map(&json_depth/1) |> Enum.max())
    end
  end

  defp json_depth(value) when is_list(value) do
    if value == [] do
      1
    else
      1 + (value |> Enum.map(&json_depth/1) |> Enum.max())
    end
  end

  defp json_depth(_), do: 0
end
