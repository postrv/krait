defmodule Krait.Memory.Guard do
  @moduledoc """
  Pure-function module that validates memory writes before they are persisted.

  Checks for:
  - Reserved key namespaces (`_system:` prefix)
  - Value size limits (max 1MB after string conversion)
  - Credential patterns (API keys, PEM private keys, JWT tokens)

  All functions are pure — no GenServer, no state, no side effects.
  """

  @max_value_size 1_000_000

  @api_key_prefixes [
    "sk-ant-",
    "sk-proj-",
    "ghp_",
    "gho_",
    "ghs_",
    "github_pat_",
    "xoxb-",
    "xoxp-",
    # AWS access keys
    "AKIA",
    # Stripe keys
    "sk_live_",
    "sk_test_",
    "rk_live_",
    "pk_live_",
    # Google API keys
    "AIza",
    # HuggingFace tokens
    "hf_",
    # Databricks tokens (dapi_ prefix, not bare "dapi" to avoid false positives)
    "dapi_"
  ]

  @private_key_markers [
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----"
  ]

  @cloud_credential_markers [
    # Google Service Account JSON
    "\"type\": \"service_account\"",
    "\"private_key\":",
    # Azure connection strings
    "AccountKey=",
    "SharedAccessKey="
  ]

  @db_connection_pattern ~r{(postgres|mysql|mongodb)://[^:]+:[^@]+@}

  @jwt_pattern ~r/eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/

  @doc """
  Validates a memory write operation.

  Returns `:ok` if the write is allowed, or `{:rejected, reason}` if it is not.

  ## Parameters

    - `key` — the memory key (string)
    - `value` — the value to write (any term; non-strings are converted via `inspect/1`)

  ## Examples

      iex> Krait.Memory.Guard.validate_write("prefs:theme", "dark")
      :ok

      iex> Krait.Memory.Guard.validate_write("config", "sk-ant-api03-abc123")
      {:rejected, "Value contains a suspected API key"}
  """
  @spec validate_write(String.t(), term()) :: :ok | {:rejected, String.t()}
  def validate_write(key, value) do
    value_str = to_string_for_scan(value)

    with :ok <- check_namespace(key),
         :ok <- check_size(value_str),
         :ok <- check_credentials(value_str),
         :ok <- check_encoded_credentials(value_str),
         :ok <- check_entropy(value_str) do
      check_prompt_injection(value_str)
    end
  end

  # -- Private helpers --------------------------------------------------------

  defp to_string_for_scan(value) when is_binary(value), do: value
  defp to_string_for_scan(value), do: inspect(value)

  defp check_namespace(key) do
    if String.starts_with?(key, "_system:") do
      {:rejected, "Key namespace '_system:' is reserved for internal use"}
    else
      :ok
    end
  end

  defp check_size(value_str) do
    if byte_size(value_str) > @max_value_size do
      {:rejected, "Value exceeds maximum size of #{@max_value_size} bytes"}
    else
      :ok
    end
  end

  defp check_credentials(value_str) do
    cond do
      contains_api_key?(value_str) ->
        {:rejected, "Value contains a suspected API key"}

      contains_private_key?(value_str) ->
        {:rejected, "Value contains private key material"}

      contains_cloud_credential?(value_str) ->
        {:rejected, "Value contains cloud service credentials"}

      contains_db_connection?(value_str) ->
        {:rejected, "Value contains database connection string with credentials"}

      contains_jwt?(value_str) ->
        {:rejected, "Value contains a JWT token"}

      true ->
        :ok
    end
  end

  defp contains_api_key?(value_str) do
    downcased = String.downcase(value_str)

    Enum.any?(@api_key_prefixes, fn prefix ->
      String.contains?(downcased, String.downcase(prefix))
    end)
  end

  defp contains_private_key?(value_str) do
    Enum.any?(@private_key_markers, &String.contains?(value_str, &1))
  end

  defp contains_cloud_credential?(value_str) do
    Enum.any?(@cloud_credential_markers, &String.contains?(value_str, &1))
  end

  defp contains_db_connection?(value_str) do
    Regex.match?(@db_connection_pattern, value_str)
  end

  defp contains_jwt?(value_str) do
    Regex.match?(@jwt_pattern, value_str)
  end

  # Minimum length for encoded strings to check (avoids false positives on short values)
  @min_encoded_length 20

  defp check_encoded_credentials(value_str) do
    # Check hex first (hex chars are a subset of base64 chars)
    with :ok <- check_hex_encoded(value_str) do
      check_base64_encoded(value_str)
    end
  end

  defp check_hex_encoded(value_str) do
    if looks_like_hex?(value_str) do
      case Base.decode16(value_str, case: :mixed) do
        {:ok, decoded} ->
          if credential_in_decoded?(decoded),
            do: {:rejected, "Value contains encoded credential (hex)"},
            else: :ok

        :error ->
          :ok
      end
    else
      :ok
    end
  end

  defp check_base64_encoded(value_str) do
    if looks_like_base64?(value_str) do
      case Base.decode64(value_str) do
        {:ok, decoded} ->
          if credential_in_decoded?(decoded),
            do: {:rejected, "Value contains encoded credential (base64)"},
            else: :ok

        :error ->
          :ok
      end
    else
      :ok
    end
  end

  defp looks_like_base64?(str) do
    byte_size(str) >= @min_encoded_length and Regex.match?(~r/^[A-Za-z0-9+\/=]{20,}$/, str)
  end

  defp looks_like_hex?(str) do
    byte_size(str) >= @min_encoded_length and Regex.match?(~r/^[0-9a-fA-F]{20,}$/, str)
  end

  defp credential_in_decoded?(decoded) when is_binary(decoded) do
    contains_api_key?(decoded) or contains_private_key?(decoded) or
      contains_cloud_credential?(decoded) or contains_jwt?(decoded)
  end

  # -- Shannon entropy detection (v27 M-5) ------------------------------------

  # v27 M-5: Detect high-entropy strings that may be obfuscated secrets
  # (ROT13, split writes, custom encodings, etc.)
  @entropy_min_length 32
  @entropy_threshold 4.5

  defp check_entropy(value_str) do
    if byte_size(value_str) >= @entropy_min_length and not structured_encoding?(value_str) do
      entropy = shannon_entropy(value_str)

      if entropy > @entropy_threshold do
        {:rejected,
         "Value has high entropy (#{Float.round(entropy, 2)} bits/char) — potential secret"}
      else
        :ok
      end
    else
      :ok
    end
  end

  # Skip entropy check for values that are clearly structured encodings
  # (these are already checked by check_encoded_credentials)
  defp structured_encoding?(value_str) do
    looks_like_base64?(value_str) or looks_like_hex?(value_str) or
      String.contains?(value_str, " ")
  end

  @doc false
  def shannon_entropy(string) when is_binary(string) do
    len = byte_size(string)

    if len == 0 do
      0.0
    else
      string
      |> String.to_charlist()
      |> Enum.frequencies()
      |> Map.values()
      |> Enum.reduce(0.0, fn count, acc ->
        p = count / len
        acc - p * :math.log2(p)
      end)
    end
  end

  # -- Prompt injection detection ---------------------------------------------

  @prompt_injection_patterns [
    ~r/ignore\s+(previous|above|all)\s+instructions/i,
    ~r/disregard\s+(previous|above|all)\s+constraints/i,
    ~r/\bsystem\s*:\s*you\s+are\s+now\b/i,
    ~r/\byou\s+are\s+now\b/i,
    ~r/\bforget\s+(everything|all)\b/i,
    ~r/\bjailbreak\b/i,
    ~r/\bDAN\s+mode\b/i,
    ~r/\bnew\s+instructions?\b/i
  ]

  @xml_delimiter_patterns [
    ~r/<\/?(user_description|system|memory|user_request)>/i
  ]

  defp check_prompt_injection(value_str) do
    cond do
      Enum.any?(@prompt_injection_patterns, &Regex.match?(&1, value_str)) ->
        {:rejected, "Value contains suspected prompt injection"}

      Enum.any?(@xml_delimiter_patterns, &Regex.match?(&1, value_str)) ->
        {:rejected, "Value contains XML delimiter breakout attempt"}

      true ->
        :ok
    end
  end
end
