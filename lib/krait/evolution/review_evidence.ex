defmodule Krait.Evolution.ReviewEvidence do
  @moduledoc """
  Normalized security-review evidence for promotion decisions.

  Review providers can produce wildly different payloads. This struct gives the
  evolution pipeline one small, predictable shape for threshold policy.
  """

  @type status :: :passed | :failed | :inconclusive | :unavailable
  @type severity :: :none | :low | :medium | :high | :critical

  @type t :: %__MODULE__{
          provider: String.t(),
          provider_version: String.t() | nil,
          status: status(),
          findings: [map()],
          max_severity: severity(),
          confidence: float(),
          artifacts: [map()],
          started_at: DateTime.t() | nil,
          completed_at: DateTime.t() | nil,
          metadata: map()
        }

  @enforce_keys [:provider, :status, :findings, :max_severity, :confidence, :artifacts]
  defstruct [
    :provider,
    :provider_version,
    :status,
    :findings,
    :max_severity,
    :confidence,
    :artifacts,
    :started_at,
    :completed_at,
    metadata: %{}
  ]

  @statuses [:passed, :failed, :inconclusive, :unavailable]
  @severities [:none, :low, :medium, :high, :critical]
  @blocking_severities [:high, :critical]

  @doc "Builds normalized review evidence from atom/string-keyed attributes."
  @spec new(map()) :: {:ok, t()} | {:error, term()}
  def new(attrs) when is_map(attrs) do
    with {:ok, provider} <- fetch_provider(attrs),
         {:ok, status} <- normalize_status(fetch(attrs, :status, :passed)),
         {:ok, findings} <- normalize_findings(fetch(attrs, :findings, [])),
         {:ok, explicit_severity} <- normalize_optional_severity(fetch(attrs, :max_severity, nil)),
         {:ok, confidence} <-
           normalize_confidence(fetch(attrs, :confidence, default_confidence(status))) do
      {:ok,
       %__MODULE__{
         provider: provider,
         provider_version: fetch(attrs, :provider_version, nil),
         status: status,
         findings: findings,
         max_severity: max_severity(findings, explicit_severity),
         confidence: confidence,
         artifacts: fetch(attrs, :artifacts, []),
         started_at: fetch(attrs, :started_at, nil),
         completed_at: fetch(attrs, :completed_at, nil),
         metadata: fetch(attrs, :metadata, %{})
       }}
    end
  end

  @doc "Returns true when evidence includes a high or critical finding."
  @spec blocking?(t(), [severity()]) :: boolean()
  def blocking?(%__MODULE__{} = evidence, blocking_severities \\ @blocking_severities) do
    evidence.max_severity in blocking_severities
  end

  @doc "Serializes evidence to an ordinary map for attestations or PR output."
  @spec to_map(t()) :: map()
  def to_map(%__MODULE__{} = evidence) do
    %{
      provider: evidence.provider,
      provider_version: evidence.provider_version,
      status: evidence.status,
      findings: evidence.findings,
      max_severity: evidence.max_severity,
      confidence: evidence.confidence,
      artifacts: evidence.artifacts,
      started_at: evidence.started_at,
      completed_at: evidence.completed_at,
      metadata: evidence.metadata
    }
  end

  @doc false
  @spec provider_key(String.t() | atom()) :: String.t()
  def provider_key(provider) when is_atom(provider) do
    provider
    |> Atom.to_string()
    |> provider_key()
  end

  def provider_key(provider) when is_binary(provider) do
    provider
    |> String.trim()
    |> String.downcase()
    |> String.replace("_", "-")
  end

  defp fetch_provider(attrs) do
    case fetch(attrs, :provider, nil) do
      nil ->
        {:error, :provider_required}

      provider when is_atom(provider) ->
        {:ok, provider_key(provider)}

      provider when is_binary(provider) ->
        key = provider_key(provider)

        if key == "" do
          {:error, :provider_required}
        else
          {:ok, key}
        end

      _ ->
        {:error, :provider_required}
    end
  end

  defp normalize_status(status) when is_atom(status) and status in @statuses, do: {:ok, status}

  defp normalize_status(status) when is_binary(status) do
    status
    |> String.downcase()
    |> String.to_existing_atom()
    |> normalize_status()
  rescue
    ArgumentError -> {:error, {:invalid_status, status}}
  end

  defp normalize_status(status), do: {:error, {:invalid_status, status}}

  defp normalize_findings(findings) when is_list(findings) do
    Enum.reduce_while(findings, {:ok, []}, fn finding, {:ok, acc} ->
      with true <- is_map(finding),
           {:ok, _severity} <- normalize_optional_severity(finding_severity(finding)) do
        {:cont, {:ok, [finding | acc]}}
      else
        false -> {:halt, {:error, {:invalid_finding, finding}}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
    |> case do
      {:ok, normalized} -> {:ok, Enum.reverse(normalized)}
      error -> error
    end
  end

  defp normalize_findings(findings), do: {:error, {:invalid_findings, findings}}

  defp normalize_optional_severity(nil), do: {:ok, nil}

  defp normalize_optional_severity(severity) when is_atom(severity) and severity in @severities,
    do: {:ok, severity}

  defp normalize_optional_severity(severity) when is_binary(severity) do
    normalized = String.downcase(severity)

    case Enum.find(@severities, &(Atom.to_string(&1) == normalized)) do
      nil -> {:error, {:invalid_severity, severity}}
      value -> {:ok, value}
    end
  end

  defp normalize_optional_severity(severity), do: {:error, {:invalid_severity, severity}}

  defp max_severity(findings, explicit_severity) do
    severities =
      findings
      |> Enum.map(&finding_severity/1)
      |> Enum.map(fn severity ->
        {:ok, normalized} = normalize_optional_severity(severity)
        normalized || :none
      end)

    [explicit_severity || :none | severities]
    |> Enum.max_by(&severity_rank/1)
  end

  defp severity_rank(severity), do: Enum.find_index(@severities, &(&1 == severity)) || 0

  defp finding_severity(finding) do
    Map.get(finding, :severity) || Map.get(finding, "severity")
  end

  defp normalize_confidence(confidence) when is_integer(confidence),
    do: normalize_confidence(confidence / 1)

  defp normalize_confidence(confidence)
       when is_float(confidence) and confidence >= 0.0 and confidence <= 1.0,
       do: {:ok, confidence}

  defp normalize_confidence(confidence), do: {:error, {:invalid_confidence, confidence}}

  defp default_confidence(:passed), do: 1.0
  defp default_confidence(_status), do: 0.0

  defp fetch(attrs, key, default) do
    Map.get(attrs, key, Map.get(attrs, Atom.to_string(key), default))
  end
end
