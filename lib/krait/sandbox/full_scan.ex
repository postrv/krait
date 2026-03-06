defmodule Krait.Sandbox.FullScan do
  @moduledoc """
  Runs inside the ephemeral FLAME container after code is applied.
  Performs full-project analysis with narsil-mcp (Mode 3).

  This module is designed to execute within a sandboxed Docker container
  managed by `Krait.Sandbox.DockerBackend`. It shells out to the narsil-mcp
  binary with full analysis flags (call-graph, security preset, JSON output).

  ## Return Shape

  On success, returns `{:ok, result}` where result contains:

    * `:security_findings` - List of security issues found
    * `:taint_flows` - Taint analysis flow traces
    * `:complexity_delta` - Change in cyclomatic complexity
    * `:new_dependencies` - SBOM diff (new packages added)
    * `:dead_code` - Unreachable code detected
    * `:call_graph_impact` - New edges in the call graph
  """

  require Logger

  @type scan_result :: %{
          security_findings: list(map()),
          taint_flows: list(map()),
          complexity_delta: number(),
          new_dependencies: list(map()),
          dead_code: list(map()),
          call_graph_impact: list(map())
        }

  @doc """
  Runs a full narsil-mcp scan on the given workspace path.

  Returns `{:ok, scan_result}` or `{:error, reason}`.
  """
  @spec run(String.t()) :: {:ok, scan_result()} | {:error, term()}
  def run(workspace_path) do
    narsil = resolve_narsil_binary()

    Logger.info("Starting full scan on #{workspace_path}")

    case System.cmd(
           narsil,
           [
             "--repos",
             workspace_path,
             "--call-graph",
             "--preset",
             "security",
             "--json"
           ],
           stderr_to_stdout: true
         ) do
      {output, 0} ->
        parse_results(output)

      {error, exit_code} ->
        Logger.error("narsil-mcp failed (exit #{exit_code}): #{String.trim(error)}")
        {:error, {:narsil_failed, exit_code, String.trim(error)}}
    end
  end

  @doc """
  Runs a full scan and returns only security-relevant findings.

  Convenience wrapper around `run/1` that filters to security_findings
  and taint_flows only.
  """
  @spec security_scan(String.t()) :: {:ok, map()} | {:error, term()}
  def security_scan(workspace_path) do
    case run(workspace_path) do
      {:ok, results} ->
        {:ok,
         %{
           security_findings: results.security_findings,
           taint_flows: results.taint_flows
         }}

      error ->
        error
    end
  end

  # ---------------------------------------------------------------------------
  # Binary resolution — mirrors deep.ex pattern (v22 SEC-04)
  # ---------------------------------------------------------------------------

  @doc """
  Resolves the narsil-mcp binary path.

  In production, requires an absolute path from config (no PATH hijacking).
  In dev/test, allows `System.find_executable` fallback.
  Always rejects paths containing `..`.
  """
  @spec resolve_narsil_binary() :: String.t()
  def resolve_narsil_binary do
    configured =
      (Application.get_env(:krait, Krait.Analyzer.Deep) || [])
      |> Keyword.get(:narsil_binary, "narsil-mcp")

    if String.contains?(configured, "..") do
      raise "narsil binary path must not contain '..': #{configured}"
    end

    if Application.get_env(:krait, :env) == :prod do
      if Path.type(configured) != :absolute do
        raise "In production, narsil_binary must be an absolute path (got: #{configured})"
      end

      configured
    else
      System.find_executable(configured) || configured
    end
  end

  # ---------------------------------------------------------------------------
  # Private helpers
  # ---------------------------------------------------------------------------

  defp parse_results(output) do
    case Jason.decode(output) do
      {:ok, results} ->
        {:ok,
         %{
           security_findings: results["security"] || [],
           taint_flows: results["taint"] || [],
           complexity_delta: results["complexity_delta"] || 0,
           new_dependencies: results["sbom_diff"] || [],
           dead_code: results["dead_code"] || [],
           call_graph_impact: results["call_graph_new_edges"] || []
         }}

      {:error, reason} ->
        Logger.error("Failed to parse narsil-mcp output",
          error: Exception.message(reason)
        )

        {:error, {:parse_error, reason}}
    end
  end
end
