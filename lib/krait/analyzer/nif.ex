defmodule Krait.Analyzer.Nif do
  @moduledoc """
  Rust NIF bindings for high-performance code analysis.
  Falls back to Krait.Analyzer.Quick if the NIF is not available.
  """

  use Rustler,
    otp_app: :krait,
    crate: "krait_analyzer"

  @behaviour Krait.Analyzer.QuickBehaviour

  @impl true
  def quick_validate(_code, _language), do: :erlang.nif_error(:nif_not_loaded)
end
