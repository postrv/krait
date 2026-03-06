defmodule Krait.Evolution.Validator do
  @moduledoc """
  Validation pipeline: Quick (NIF) -> Deep (MCP) -> Policy.
  Returns a validated proposal with all metadata.

  Deep scan behavior:
  - If Narsil IS available but errors -> fail closed (reject)
  - If Narsil is NOT available -> check `require_deep_scan` config
    - dev/test: require_deep_scan=false -> pass with empty findings
    - prod: require_deep_scan=true -> reject
  - Taint analysis + call graph are best-effort (not blocking)
  """

  require Logger

  alias Krait.Analyzer.Policy
  alias Krait.Evolution.ValidatedProposal

  @spec validate(map()) ::
          {:ok, %Krait.Evolution.ValidatedProposal{}} | {:error, atom(), term()}
  def validate(proposal) do
    Logger.info("Validating proposal",
      skill_name: proposal.spec[:skill_name] || proposal.spec["skill_name"]
    )

    quick_mod = Application.get_env(:krait, :analyzer_quick, Krait.Analyzer.Quick)
    deep_mod = Application.get_env(:krait, :analyzer_deep, Krait.Analyzer.Deep)

    language = get_in(proposal, [:spec, :language]) || "elixir"

    with {:ok, quick_result} <- run_quick_validate(quick_mod, proposal.code, language),
         {:ok, deep_result} <- run_deep_scan(deep_mod, proposal),
         :ok <- run_policy_checks(quick_result, proposal) do
      {:ok,
       %ValidatedProposal{
         code: proposal.code,
         test_code: proposal.test_code,
         ast_hash: quick_result.hash,
         complexity: quick_result.complexity,
         security_findings: deep_result.security_findings,
         taint_flows: deep_result.taint_flows,
         spec: proposal.spec
       }}
    end
  end

  defp run_quick_validate(quick_mod, code, language) do
    case quick_mod.quick_validate(code, language) do
      {:ok, result} ->
        {:ok, result}

      {:syntax_error, errors} ->
        Logger.warning("Validation failed", stage: :quick_validate, reason: :syntax_error)
        {:error, :syntax_error, errors}

      {:policy_violation, details} ->
        Logger.warning("Validation failed", stage: :quick_validate, reason: :policy_violation)
        {:error, :policy_violation, details}
    end
  end

  @empty_deep_result %{security_findings: [], taint_flows: [], deep_scan_status: :skipped}

  defp run_deep_scan(deep_mod, proposal) do
    random_suffix = :crypto.strong_rand_bytes(16) |> Base.url_encode64(padding: false)
    language = get_in(proposal, [:spec, :language]) || "elixir"
    ext = language_extension(language)
    tmp_path = Path.join(System.tmp_dir!(), "krait_validate_#{random_suffix}.#{ext}")

    # v26 L-12: Atomic create with exclusive flag (prevents race), then chmod 0600
    case :file.open(String.to_charlist(tmp_path), [:write, :exclusive]) do
      {:ok, fd} ->
        File.chmod!(tmp_path, 0o600)
        :file.write(fd, proposal.code)
        :file.close(fd)

      {:error, reason} ->
        raise File.Error,
          reason: reason,
          action: "open",
          path: tmp_path
    end

    try do
      case deep_mod.security_scan(tmp_path) do
        {:ok, findings} ->
          # Normalize findings: text reports (no structured findings) → empty list
          findings = if is_list(findings), do: findings, else: []

          case check_blocking_findings(findings) do
            :ok ->
              # Taint + call graph are best-effort
              taint_flows = best_effort_taint(deep_mod, tmp_path)
              _call_graph = best_effort_call_graph(deep_mod, tmp_path)

              {:ok,
               %{
                 security_findings: findings,
                 taint_flows: taint_flows,
                 deep_scan_status: :completed
               }}

            {:error, :blocking_findings, all_findings} ->
              Logger.warning("Validation failed",
                stage: :deep_scan,
                reason: :blocking_findings
              )

              {:error, :security_findings, all_findings}
          end

        {:error, :unavailable} ->
          handle_narsil_unavailable()

        {:error, :narsil_exited} ->
          handle_narsil_unavailable()

        {:error, reason} ->
          # Narsil was available but returned an error -> fail closed
          Logger.warning("Deep scan failed — failing closed",
            stage: :deep_scan,
            reason: if(is_atom(reason), do: reason, else: "deep_scan_error")
          )

          {:error, :deep_scan_failed, reason}
      end
    rescue
      # Narsil protocol mismatch — fail closed (not "unavailable")
      e in [MatchError, FunctionClauseError] ->
        Logger.warning("Deep scan protocol mismatch (fail-closed): #{Exception.message(e)}")
        {:error, :deep_scan_failed, {:protocol_mismatch, Exception.message(e)}}

      # All other exceptions — fail closed
      e ->
        Logger.warning(
          "Deep scan failed (fail-closed, #{inspect(e.__struct__)}): #{Exception.message(e)}"
        )

        {:error, :deep_scan_failed, Exception.message(e)}
    catch
      :exit, {:noproc, _} ->
        Logger.info("Deep scan skipped — process not running")
        handle_narsil_unavailable()

      :exit, {:normal, _} ->
        Logger.info("Deep scan skipped — process exited normally")
        handle_narsil_unavailable()

      # All other exits — fail closed
      :exit, reason ->
        reason_str = if is_atom(reason), do: Atom.to_string(reason), else: "exit_error"
        Logger.warning("Deep scan exit (fail-closed)", reason: reason_str)
        {:error, :deep_scan_failed, reason_str}
    after
      File.rm(tmp_path)
    end
  end

  defp handle_narsil_unavailable do
    if Application.get_env(:krait, :require_deep_scan, false) do
      # v20 H-2: Clear error message when deep scan is required but unavailable
      Logger.error(
        "[SECURITY] Deep scan required but Narsil unavailable — rejecting proposal. " <>
          "Ensure narsil-mcp binary is installed and accessible."
      )

      {:error, :deep_scan_required, :narsil_unavailable}
    else
      Logger.warning(
        "[SECURITY] Deep scan SKIPPED — Narsil not available. " <>
          "Set require_deep_scan: true to enforce deep scanning."
      )

      {:ok, @empty_deep_result}
    end
  end

  defp best_effort_taint(deep_mod, tmp_path) do
    case deep_mod.taint_analysis("execute", tmp_path) do
      {:ok, flows} -> flows
      _ -> []
    end
  rescue
    e in [MatchError, FunctionClauseError, ArgumentError, RuntimeError] ->
      Logger.debug("Taint analysis failed: #{Exception.message(e)}")
      []
  catch
    :exit, reason ->
      Logger.debug("Taint analysis exit: #{inspect(reason)}")
      []
  end

  defp best_effort_call_graph(deep_mod, tmp_path) do
    case deep_mod.call_graph(tmp_path) do
      {:ok, graph} -> graph
      _ -> %{edges: []}
    end
  rescue
    e in [MatchError, FunctionClauseError, ArgumentError, RuntimeError] ->
      Logger.debug("Call graph failed: #{Exception.message(e)}")
      %{edges: []}
  catch
    :exit, reason ->
      Logger.debug("Call graph exit: #{inspect(reason)}")
      %{edges: []}
  end

  defp run_policy_checks(quick_result, proposal) do
    with :ok <- Policy.check_complexity_budget(quick_result.complexity),
         :ok <- Policy.check_immutable_manifest(proposal.code) do
      :ok
    else
      {:rejected, :complexity_exceeded, explanation} ->
        Logger.warning("Policy check failed", reason: :complexity_exceeded)
        {:error, :policy_violation, %{rule: "COMPLEXITY", explanation: explanation}}

      {:rejected, rule, explanation} ->
        Logger.warning("Policy check failed", rule: rule, explanation: explanation)
        {:error, :policy_violation, %{rule: rule, explanation: explanation}}
    end
  end

  @blocking_severities ["critical", "high"]

  defp language_extension("python"), do: "py"
  defp language_extension("javascript"), do: "js"
  defp language_extension("typescript"), do: "ts"
  defp language_extension("go"), do: "go"
  defp language_extension("rust"), do: "rs"
  defp language_extension(_), do: "ex"

  defp check_blocking_findings(findings) do
    blocking =
      Enum.filter(findings, fn f ->
        severity = Map.get(f, "severity") || Map.get(f, :severity)
        severity in @blocking_severities
      end)

    if blocking == [] do
      :ok
    else
      {:error, :blocking_findings, findings}
    end
  end
end
