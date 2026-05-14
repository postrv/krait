defmodule Krait.Evolution.PromotionDecision do
  @moduledoc """
  Deterministic promotion policy for reviewed capability candidates.

  This module is intentionally pure: callers provide candidate metadata and
  review evidence, and receive an auditable approval/rejection decision.

  Review evidence is trusted input from KRAIT-owned provider adapters, not from
  generated code, prompts, or user-supplied payloads. Until provider attestations
  are wired into the immutable evolution pipeline, callers must bind evidence to
  real provider execution before using this module as an enforcement decision.
  """

  alias Krait.Evolution.ReviewEvidence

  @type status :: :approved | :rejected | :manual_review
  @type t :: %__MODULE__{
          status: status(),
          risk_class: String.t(),
          score: non_neg_integer(),
          threshold: non_neg_integer() | nil,
          reasons: [String.t()],
          required_providers: [String.t()],
          evidence_count: non_neg_integer()
        }

  @enforce_keys [:status, :risk_class, :score, :reasons, :required_providers, :evidence_count]
  defstruct [
    :status,
    :risk_class,
    :score,
    :threshold,
    :reasons,
    :required_providers,
    :evidence_count
  ]

  @policies %{
    "pure-compute" => %{threshold: 90, required_providers: ["narsil", "sandbox"]},
    "local-read" => %{threshold: 92, required_providers: ["narsil", "llm-review", "sandbox"]},
    "memory" => %{threshold: 92, required_providers: ["narsil", "llm-review", "sandbox"]},
    "network" => %{
      threshold: 95,
      required_providers: ["narsil", "llm-review", "sandbox", "ssrf"]
    },
    "privileged" => %{threshold: nil, required_providers: ["narsil", "sandbox"]}
  }

  @allowed_capabilities ["filesystem", "memory", "network"]
  @required_provenance [:model, :prompt_hash, :source_hash, :test_hash]

  @doc """
  Decides whether a candidate clears promotion policy.

  The function returns `{:ok, decision}` for both approvals and rejections so
  callers can persist and publish the complete decision.
  """
  @spec decide(map(), keyword()) :: {:ok, t()} | {:error, term()}
  def decide(candidate, opts \\ []) when is_map(candidate) do
    with {:ok, risk_class, policy} <- policy_for(candidate),
         {:ok, evidence_by_provider} <- evidence_by_provider(candidate),
         {:ok, requested_caps, declared_caps} <- normalized_capabilities(candidate) do
      required_providers = policy.required_providers
      score = score(evidence_by_provider, required_providers)

      reasons =
        []
        |> add_required_provider_reasons(evidence_by_provider, required_providers)
        |> add_blocking_findings(evidence_by_provider)
        |> add_capability_mismatch(requested_caps, declared_caps)
        |> add_dependency_delta(candidate, opts)
        |> add_provenance_gaps(candidate)
        |> add_score_gap(score, policy.threshold)
        |> maybe_add_privileged_reason(risk_class)
        |> Enum.reverse()

      status = status_for(risk_class, reasons)

      {:ok,
       %__MODULE__{
         status: status,
         risk_class: risk_class,
         score: score,
         threshold: policy.threshold,
         reasons: reasons,
         required_providers: required_providers,
         evidence_count: map_size(evidence_by_provider)
       }}
    end
  end

  @doc "Returns true when a decision approved automatic promotion."
  @spec approved?(t()) :: boolean()
  def approved?(%__MODULE__{status: :approved}), do: true
  def approved?(%__MODULE__{}), do: false

  defp policy_for(candidate) do
    risk_class =
      risk_class_key(Map.get(candidate, :risk_class) || Map.get(candidate, "risk_class"))

    case Map.fetch(@policies, risk_class) do
      {:ok, policy} -> {:ok, risk_class, policy}
      :error -> {:error, {:unknown_risk_class, risk_class}}
    end
  end

  defp risk_class_key(nil), do: nil

  defp risk_class_key(risk_class) when is_atom(risk_class) do
    risk_class
    |> Atom.to_string()
    |> risk_class_key()
  end

  defp risk_class_key(risk_class) when is_binary(risk_class) do
    risk_class
    |> String.trim()
    |> String.downcase()
    |> String.replace("_", "-")
  end

  defp evidence_by_provider(candidate) do
    evidence = Map.get(candidate, :evidence) || Map.get(candidate, "evidence") || []

    if Enum.all?(evidence, &match?(%ReviewEvidence{}, &1)) do
      {:ok, Map.new(evidence, &{&1.provider, &1})}
    else
      {:error, :invalid_evidence}
    end
  end

  defp normalized_capabilities(candidate) do
    with {:ok, requested_raw} <- fetch_capabilities(candidate, :requested_capabilities),
         {:ok, declared_raw} <- fetch_capabilities(candidate, :declared_capabilities),
         {:ok, requested} <- capability_set(requested_raw),
         {:ok, declared} <- capability_set(declared_raw) do
      {:ok, requested, declared}
    end
  end

  defp fetch_capabilities(candidate, key) do
    cond do
      Map.has_key?(candidate, key) ->
        {:ok, Map.fetch!(candidate, key)}

      Map.has_key?(candidate, Atom.to_string(key)) ->
        {:ok, Map.fetch!(candidate, Atom.to_string(key))}

      true ->
        {:error, {:missing_capabilities, key}}
    end
  end

  defp capability_set(capabilities) when is_list(capabilities) do
    capabilities
    |> Enum.reduce_while({:ok, []}, fn capability, {:ok, acc} ->
      case capability_key(capability) do
        {:ok, normalized} -> {:cont, {:ok, [normalized | acc]}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
    |> case do
      {:ok, normalized} -> {:ok, Enum.sort(normalized)}
      error -> error
    end
  end

  defp capability_set(capabilities), do: {:error, {:invalid_capabilities, capabilities}}

  defp capability_key(capability) when is_atom(capability) do
    capability
    |> Atom.to_string()
    |> capability_key()
  end

  defp capability_key(capability) when is_binary(capability) do
    normalized =
      capability
      |> String.normalize(:nfc)
      |> String.trim()
      |> String.downcase()

    cond do
      normalized in @allowed_capabilities ->
        {:ok, normalized}

      normalized == "" ->
        {:error, {:invalid_capability, capability}}

      true ->
        {:error, {:unsupported_capability, capability}}
    end
  end

  defp capability_key(capability), do: {:error, {:invalid_capability, capability}}

  defp add_required_provider_reasons(reasons, evidence_by_provider, required_providers) do
    Enum.reduce(required_providers, reasons, fn provider, acc ->
      case Map.get(evidence_by_provider, provider) do
        %ReviewEvidence{status: :passed} ->
          acc

        %ReviewEvidence{status: status} ->
          ["required provider #{provider} returned #{status}" | acc]

        nil ->
          ["required provider unavailable: #{provider}" | acc]
      end
    end)
  end

  defp required_providers_present?(evidence_by_provider, required_providers) do
    Enum.all?(required_providers, &Map.has_key?(evidence_by_provider, &1))
  end

  defp score(evidence_by_provider, required_providers) do
    if required_providers_present?(evidence_by_provider, required_providers) do
      required_providers
      |> Enum.map(&Map.fetch!(evidence_by_provider, &1))
      |> Enum.map(& &1.confidence)
      |> Enum.min()
      |> Kernel.*(100)
      |> round()
    else
      0
    end
  end

  defp add_blocking_findings(reasons, evidence_by_provider) do
    Enum.reduce(evidence_by_provider, reasons, fn {provider, evidence}, acc ->
      if ReviewEvidence.blocking?(evidence) do
        ["blocking severity from #{provider}: #{evidence.max_severity}" | acc]
      else
        acc
      end
    end)
  end

  defp add_capability_mismatch(reasons, requested_caps, declared_caps) do
    if requested_caps == declared_caps do
      reasons
    else
      ["declared capabilities do not match requested capabilities" | reasons]
    end
  end

  defp add_dependency_delta(reasons, candidate, opts) do
    dependency_delta =
      Map.get(candidate, :dependency_delta, Map.get(candidate, "dependency_delta", []))

    if dependency_delta == [] or Keyword.get(opts, :dependency_approved?, false) do
      reasons
    else
      ["dependency changes require human approval" | reasons]
    end
  end

  defp add_provenance_gaps(reasons, candidate) do
    provenance = Map.get(candidate, :provenance, Map.get(candidate, "provenance", %{})) || %{}

    Enum.reduce(@required_provenance, reasons, fn key, acc ->
      value = Map.get(provenance, key) || Map.get(provenance, Atom.to_string(key))

      if present?(value) do
        acc
      else
        ["missing provenance: #{key}" | acc]
      end
    end)
  end

  defp add_score_gap(reasons, _score, nil), do: reasons

  defp add_score_gap(reasons, score, threshold) when score < threshold,
    do: ["score #{score} is below threshold #{threshold}" | reasons]

  defp add_score_gap(reasons, _score, _threshold), do: reasons

  defp maybe_add_privileged_reason(reasons, "privileged"),
    do: ["privileged risk class requires human security approval" | reasons]

  defp maybe_add_privileged_reason(reasons, _risk_class), do: reasons

  defp status_for("privileged", _reasons), do: :manual_review
  defp status_for(_risk_class, []), do: :approved
  defp status_for(_risk_class, _reasons), do: :rejected

  defp present?(value) when is_binary(value), do: String.trim(value) != ""
  defp present?(nil), do: false
  defp present?(_value), do: true
end
