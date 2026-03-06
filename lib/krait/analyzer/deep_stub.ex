defmodule Krait.Analyzer.DeepStub do
  @moduledoc "Stub Deep analyzer for dev — returns empty findings when Narsil unavailable"
  @behaviour Krait.Analyzer.DeepBehaviour

  require Logger

  @impl true
  def security_scan(_path) do
    Logger.debug("DeepStub: security_scan (stubbed)")
    {:ok, []}
  end

  @impl true
  def taint_analysis(_fn, _path), do: {:ok, []}

  @impl true
  def call_graph(_path), do: {:ok, %{edges: []}}

  @impl true
  def infer_types(_path, _fn), do: {:ok, []}

  @impl true
  def dead_code(_path), do: {:ok, []}

  @impl true
  def dependency_audit(_path), do: {:ok, %{}}
end
