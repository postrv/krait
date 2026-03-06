defmodule Krait.Evolution.Attestation do
  @moduledoc """
  Builds and signs cryptographic attestations for validated evolution proposals.

  The attestation captures the full validation provenance chain: AST hash,
  complexity, security findings, taint flows, allowlist version (both Elixir
  and Rust), LLM model, and prompt hash.

  Signed with Ed25519 for compact signatures (64 bytes vs ~256 for RSA).
  """

  require Logger

  @type t :: %{
          ast_hash: String.t(),
          complexity: non_neg_integer(),
          security_findings_count: non_neg_integer(),
          taint_flows_count: non_neg_integer(),
          deep_scan_status: :completed | :skipped,
          allowlist_version: String.t(),
          validator_version: String.t(),
          llm_model: String.t(),
          llm_prompt_hash: String.t() | nil,
          timestamp: DateTime.t(),
          attestation_hash: String.t()
        }

  @doc """
  Build an attestation from a validated proposal.
  Captures all validation provenance fields and computes a deterministic hash.
  """
  @spec build(%Krait.Evolution.ValidatedProposal{}) :: t()
  def build(validated_proposal) do
    spec = validated_proposal.spec || %{}

    attestation = %{
      ast_hash: validated_proposal.ast_hash || "",
      complexity: validated_proposal.complexity || 0,
      security_findings_count: length(validated_proposal.security_findings || []),
      taint_flows_count: length(validated_proposal.taint_flows || []),
      deep_scan_status: detect_deep_scan_status(validated_proposal),
      allowlist_version: compute_allowlist_version(),
      validator_version: compute_validator_version(),
      llm_model: Map.get(spec, :llm_model) || Map.get(spec, "llm_model") || "unknown",
      llm_prompt_hash: Map.get(spec, :prompt_hash) || Map.get(spec, "prompt_hash") || nil,
      timestamp: DateTime.utc_now()
    }

    # Compute attestation hash over canonical form
    hash = compute_attestation_hash(attestation)
    Map.put(attestation, :attestation_hash, hash)
  end

  @doc """
  Sign an attestation with Ed25519 using the configured attestation key.
  Returns `{:ok, base64_signature}` or `{:error, reason}`.
  """
  @spec sign(t()) :: {:ok, String.t()} | {:error, :key_unavailable | :crypto_error}
  def sign(attestation) do
    key_path = Application.get_env(:krait, :attestation_key_path)

    cond do
      is_nil(key_path) ->
        {:error, :key_unavailable}

      not File.exists?(key_path) ->
        {:error, :key_unavailable}

      true ->
        try do
          pem = File.read!(key_path)
          private_key = decode_ed25519_private_key(pem)
          message = attestation.attestation_hash
          signature = :crypto.sign(:eddsa, :none, message, [private_key, :ed25519])

          # Phase 10: Audit log every signing operation (not the key material)
          Logger.info("[Attestation] Signed attestation",
            attestation_hash: String.slice(attestation.attestation_hash, 0, 16),
            skill: Map.get(attestation, :llm_model, "unknown")
          )

          {:ok, Base.encode64(signature)}
        rescue
          e ->
            Logger.error(
              "[Attestation] Signing failed: " <>
                Exception.message(e)
            )

            {:error, :crypto_error}
        end
    end
  end

  @doc """
  Verify an attestation signature against the attestation hash.
  """
  @spec verify(t(), String.t(), binary()) :: :ok | {:error, :invalid_signature}
  def verify(attestation, signature_b64, public_key) do
    signature = Base.decode64!(signature_b64)
    message = compute_attestation_hash(Map.delete(attestation, :attestation_hash))

    if :crypto.verify(:eddsa, :none, message, signature, [public_key, :ed25519]) do
      :ok
    else
      {:error, :invalid_signature}
    end
  end

  @doc """
  Format attestation as commit message trailer lines.
  """
  @spec to_commit_message(t(), String.t()) :: String.t()
  def to_commit_message(attestation, signature) do
    """
    Attestation-Hash: #{attestation.attestation_hash}
    Attestation-Signature: #{signature}
    AST-Hash: #{attestation.ast_hash}
    Complexity: #{attestation.complexity}
    Allowlist-Version: #{attestation.allowlist_version}
    LLM-Model: #{attestation.llm_model}
    """
  end

  @doc """
  Serialize attestation + signature as JSON for inclusion in commit.
  """
  @spec to_json(t(), String.t()) :: String.t()
  def to_json(attestation, signature) do
    attestation
    |> Map.put(:signature, signature)
    |> Map.update!(:timestamp, &DateTime.to_iso8601/1)
    |> Jason.encode!(pretty: true)
  end

  # -- Private --

  defp detect_deep_scan_status(validated_proposal) do
    # If security_findings is a non-empty list or a result map, deep scan ran
    case validated_proposal.security_findings do
      findings when is_list(findings) -> :completed
      _ -> :skipped
    end
  end

  @doc false
  def compute_allowlist_version do
    elixir_path = "lib/krait/analyzer/allowlist.ex"
    rust_path = "native/krait_analyzer/src/allowlist.rs"

    elixir_src = safe_read(elixir_path)
    rust_src = safe_read(rust_path)

    :crypto.hash(:sha256, elixir_src <> rust_src) |> Base.encode16(case: :lower)
  end

  defp compute_validator_version do
    quick_path = "lib/krait/analyzer/quick.ex"
    rules_path = "native/krait_analyzer/src/rules.rs"

    quick_src = safe_read(quick_path)
    rules_src = safe_read(rules_path)

    :crypto.hash(:sha256, quick_src <> rules_src) |> Base.encode16(case: :lower)
  end

  defp safe_read(path) do
    case File.read(path) do
      {:ok, content} -> content
      {:error, _} -> ""
    end
  end

  defp compute_attestation_hash(attestation) do
    # Canonical form: sorted key-value pairs, deterministic serialization
    canonical =
      [
        {"ast_hash", attestation.ast_hash || ""},
        {"complexity", to_string(attestation.complexity || 0)},
        {"security_findings_count", to_string(attestation.security_findings_count || 0)},
        {"taint_flows_count", to_string(attestation.taint_flows_count || 0)},
        {"allowlist_version", attestation.allowlist_version || ""},
        {"validator_version", attestation.validator_version || ""},
        {"llm_model", attestation.llm_model || ""},
        {"llm_prompt_hash", attestation.llm_prompt_hash || ""}
      ]
      |> Enum.map_join("\n", fn {k, v} -> "#{k}=#{v}" end)

    :crypto.hash(:sha256, canonical) |> Base.encode16(case: :lower)
  end

  defp decode_ed25519_private_key(pem) do
    # Use OTP's built-in PEM decoder for robust handling across OTP versions
    [pem_entry] = :public_key.pem_decode(pem)
    decoded = :public_key.pem_entry_decode(pem_entry)

    case decoded do
      # OTP 27+ decodes Ed25519 PKCS#8 directly to ECPrivateKey
      {:ECPrivateKey, 1, key_bytes, {:namedCurve, {1, 3, 101, 112}}, _, _} ->
        key_bytes

      # Older OTP versions return PrivateKeyInfo wrapper
      {:PrivateKeyInfo, _version, _algo, private_key_der, _} ->
        <<0x04, _len, key::binary-size(32)>> = private_key_der
        key

      _ ->
        raise "Unsupported Ed25519 private key format"
    end
  end
end
