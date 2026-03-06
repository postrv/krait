defmodule Krait.Evolution do
  @moduledoc "Top-level orchestrator: Proposer -> Validator -> Deployer with retry"

  require Logger

  alias Krait.Evolution.{Deployer, Feed, Proposer, Spec, Validator}

  @spec evolve(map()) :: {:ok, map()} | {:error, :max_retries_exhausted, map()} | {:error, term()}
  def evolve(params) do
    # halted?/0 uses direct ETS read, safe even if GenServer is down
    if Krait.KillSwitch.halted?() do
      {:error, :system_halted}
    else
      skill_name = params[:skill_name] || params["skill_name"]
      Logger.info("Starting evolution", skill_name: skill_name)
      :telemetry.execute([:krait, :evolution, :start], %{}, %{skill_name: skill_name})
      start_time = System.monotonic_time()

      with {:ok, spec} <- Spec.new(params) do
        result = attempt_evolution(spec, 1, [])
        record_event(spec, result)
        emit_result_telemetry(result, start_time, skill_name)
        result
      end
    end
  end

  defp attempt_evolution(spec, attempt, errors) do
    if attempt > max_retries() do
      Logger.error("Evolution failed",
        skill_name: spec.skill_name,
        reason: :max_retries_exhausted
      )

      case open_draft_pr(spec, errors) do
        {:ok, pr_url} ->
          {:ok, %{pr_url: pr_url, draft: true, attempts: attempt - 1, errors: errors}}

        {:error, _reason} ->
          {:error, :max_retries_exhausted, %{attempts: attempt - 1, errors: errors}}
      end
    else
      do_attempt_evolution(spec, attempt, errors)
    end
  end

  defp do_attempt_evolution(spec, attempt, errors) do
    # v25 M-2: Re-check kill switch before each stage to close TOCTOU gap
    if Krait.KillSwitch.halted?() do
      {:error, :system_halted}
    else
      do_attempt_evolution_stages(spec, attempt, errors)
    end
  end

  defp do_attempt_evolution_stages(spec, attempt, errors) do
    Logger.info("Evolution attempt", attempt: attempt, skill_name: spec.skill_name)
    llm = Application.get_env(:krait, :llm_module, Krait.LLM.Router)

    with {:ok, proposal} <-
           Proposer.generate(spec,
             llm: llm,
             attempt: attempt,
             previous_errors: errors
           ),
         # v25 M-2: Re-check between propose and validate
         :ok <- check_not_halted(),
         {:ok, validated} <-
           Validator.validate(%{
             code: proposal.code,
             test_code: proposal.test_code,
             spec: Map.from_struct(spec)
           }),
         # v25 M-2: Re-check between validate and deploy
         :ok <- check_not_halted(),
         {:ok, pr_url} <- Deployer.propose_evolution(validated),
         # v26 L-1: Post-deploy halt check — log warning if kill switch engaged during evolution
         :ok <- post_deploy_halt_check() do
      safe_record_success()
      Logger.info("Evolution succeeded", skill_name: spec.skill_name, pr_url: pr_url)

      # Phase 1.5: Thread attestation data for Feed recording
      {:ok,
       %{
         pr_url: pr_url,
         attempts: attempt,
         draft: false,
         ast_hash: validated.ast_hash,
         complexity: validated.complexity,
         security_findings: length(validated.security_findings || []),
         taint_flows: length(validated.taint_flows || [])
       }}
    else
      {:error, :policy_violation, _} = err ->
        safe_record_failure()
        {_, type, details} = err
        attempt_evolution(spec, attempt + 1, [{attempt, type, details} | errors])

      {:error, type, details} ->
        attempt_evolution(spec, attempt + 1, [{attempt, type, details} | errors])

      {:error, reason} ->
        attempt_evolution(spec, attempt + 1, [{attempt, :error, reason} | errors])
    end
  end

  defp record_event(spec, result) do
    event =
      case result do
        {:ok, result} ->
          %{
            skill_name: spec.skill_name,
            description: spec.description,
            pr_url: result[:pr_url],
            attempts: result[:attempts],
            draft: result[:draft] || false,
            ast_hash: result[:ast_hash],
            complexity: result[:complexity],
            security_findings: result[:security_findings] || 0,
            taint_flows: result[:taint_flows] || 0
          }

        {:error, :max_retries_exhausted, %{attempts: attempts}} ->
          %{
            skill_name: spec.skill_name,
            description: spec.description,
            attempts: attempts,
            draft: true
          }

        {:error, reason} ->
          %{
            skill_name: spec.skill_name,
            description: spec.description,
            attempts: 0,
            draft: true,
            error: reason
          }
      end

    try do
      Feed.record(event)
    rescue
      e in [
        Ecto.QueryError,
        DBConnection.ConnectionError,
        DBConnection.OwnershipError,
        Ecto.InvalidChangesetError
      ] ->
        Logger.debug("Feed record failed: #{Exception.message(e)}")
        :ok
    catch
      :exit, reason ->
        Logger.debug("Feed record exit: #{inspect(reason)}")
        :ok
    end
  end

  defp open_draft_pr(spec, errors) do
    github = Application.get_env(:krait, :github_client, Krait.GitHub.Client)
    repo = Application.get_env(:krait, :repo_name, "postrv/krait")

    error_summary =
      Enum.map_join(errors, "\n", fn {attempt, type, details} ->
        "- Attempt #{attempt}: #{type} — #{inspect(details)}"
      end)

    body = """
    ## Draft Evolution: #{spec.skill_name}

    This evolution failed after #{length(errors)} attempt(s).

    ### Failure Log
    #{error_summary}

    ---
    *Generated by Krait Evolution System (draft — needs manual intervention)*
    """

    with {:ok, base_sha} <- github.get_default_branch_sha(repo),
         {:ok, _} <- github.create_branch(repo, spec.branch_name, base_sha),
         {:ok, pr} <-
           github.create_pull_request(repo, %{
             title: "Draft Evolution: #{spec.skill_name}",
             body: body,
             head: spec.branch_name,
             base: "main",
             labels: ["krait-evolution", "needs-human-review"],
             draft: true
           }) do
      {:ok, pr["html_url"] || pr[:html_url]}
    end
  end

  defp safe_record_success do
    if GenServer.whereis(Krait.KillSwitch),
      do: Krait.KillSwitch.record_success(),
      else: :ok
  rescue
    _ -> :ok
  end

  defp safe_record_failure do
    if GenServer.whereis(Krait.KillSwitch),
      do: Krait.KillSwitch.record_failure(),
      else: :ok
  rescue
    _ -> :ok
  end

  defp emit_result_telemetry(result, start_time, skill_name) do
    duration = System.monotonic_time() - start_time

    case result do
      {:ok, _} ->
        :telemetry.execute([:krait, :evolution, :complete], %{duration: duration}, %{
          skill_name: skill_name
        })

      _ ->
        :telemetry.execute([:krait, :evolution, :failure], %{duration: duration}, %{
          skill_name: skill_name
        })
    end
  end

  # v25 M-2: Check kill switch not halted (returns :ok or {:error, :system_halted})
  defp check_not_halted do
    if Krait.KillSwitch.halted?(), do: {:error, :system_halted}, else: :ok
  end

  # v26 L-1: Post-deploy halt check — warns if kill switch engaged during evolution
  # but does NOT fail the already-completed deployment. Documents the 5-point
  # TOCTOU checking strategy: (1) pre-evolve, (2) pre-validate, (3) pre-deploy,
  # (4) between stages, (5) post-deploy (advisory). Accepted residual risk:
  # a PR may land between check-points; human review is the final gate.
  defp post_deploy_halt_check do
    if Krait.KillSwitch.halted?() do
      Logger.warning(
        "[SECURITY] Kill switch engaged DURING evolution — PR was already submitted. " <>
          "Manual review recommended."
      )
    end

    # Always return :ok — the PR is already submitted, failing here would
    # discard the successful result. The warning is sufficient.
    :ok
  end

  defp max_retries, do: Application.get_env(:krait, :max_evolution_retries, 3)
end
