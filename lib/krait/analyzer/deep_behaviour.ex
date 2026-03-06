defmodule Krait.Analyzer.DeepBehaviour do
  @moduledoc "Contract for deep (Narsil MCP sidecar) code analysis"

  @callback security_scan(file_path :: String.t()) :: {:ok, [map()]} | {:error, term()}
  @callback taint_analysis(function :: String.t(), file :: String.t()) ::
              {:ok, [map()]} | {:error, term()}
  @callback call_graph(file_path :: String.t()) :: {:ok, map()} | {:error, term()}
  @callback infer_types(file_path :: String.t(), function :: String.t()) ::
              {:ok, [map()]} | {:error, term()}
  @callback dead_code(file_path :: String.t()) :: {:ok, [map()]} | {:error, term()}
  @callback dependency_audit(repo_path :: String.t()) :: {:ok, map()} | {:error, term()}
end
