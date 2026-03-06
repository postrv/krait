defmodule Krait.Skills.Capabilities.NetworkCap do
  @moduledoc """
  Network capability — provides HTTP fetch via the WebFetch skill.
  Delegates to `Krait.Skills.Core.WebFetch` under the hood.
  """

  alias Krait.Skills.Core.WebFetch

  @spec fetch(String.t()) :: {:ok, map()} | {:error, term()}
  def fetch(url) when is_binary(url) do
    WebFetch.execute(%{"url" => url})
  end
end
