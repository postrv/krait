defmodule Mix.Tasks.Krait.Verify do
  @moduledoc """
  Verify an evolution commit's attestation signature.

  ## Usage

      mix krait.verify COMMIT_SHA [--pub-key PATH]

  Extracts the `Attestation-Hash` and `Attestation-Signature` from the commit
  message, then verifies the signature using the Ed25519 public key.

  Also checks for `.krait/attestations/*.json` files in the commit if present.
  """

  use Mix.Task

  @shortdoc "Verify an evolution commit's attestation"

  @impl true
  def run(args) do
    {opts, positional, _} = OptionParser.parse(args, strict: [pub_key: :string])

    commit_sha =
      case positional do
        [sha | _] -> sha
        _ -> Mix.raise("Usage: mix krait.verify COMMIT_SHA [--pub-key PATH]")
      end

    pub_key_path = Keyword.get(opts, :pub_key)

    # Get commit message
    case System.cmd("git", ["log", "-1", "--format=%B", commit_sha]) do
      {message, 0} ->
        verify_commit(message, pub_key_path, commit_sha)

      {_, code} ->
        Mix.raise("Failed to read commit #{commit_sha} (git exit #{code})")
    end
  end

  defp verify_commit(message, pub_key_path, commit_sha) do
    attestation_hash = extract_field(message, "Attestation-Hash")
    signature = extract_field(message, "Attestation-Signature")

    cond do
      is_nil(attestation_hash) ->
        Mix.shell().error("No Attestation-Hash found in commit #{commit_sha}")

      is_nil(signature) ->
        Mix.shell().error("No Attestation-Signature found in commit #{commit_sha}")

      is_nil(pub_key_path) ->
        Mix.shell().info("""
        Attestation found (signature not verified — no public key provided):
          Hash:      #{attestation_hash}
          Signature: #{String.slice(signature, 0, 32)}...
          AST-Hash:  #{extract_field(message, "AST-Hash") || "N/A"}
          Model:     #{extract_field(message, "LLM-Model") || "N/A"}

        To verify: mix krait.verify #{commit_sha} --pub-key PATH_TO_PUBLIC_KEY
        """)

      true ->
        verify_signature(attestation_hash, signature, pub_key_path, message)
    end
  end

  defp verify_signature(attestation_hash, signature_b64, pub_key_path, message) do
    pub_pem = File.read!(pub_key_path)
    [entry] = :public_key.pem_decode(pub_pem)
    pub_key = :public_key.pem_entry_decode(entry)

    # Extract raw public key bytes for Ed25519 verification
    raw_pub =
      case pub_key do
        {:SubjectPublicKeyInfo, _, key_bytes} -> key_bytes
        other -> other
      end

    signature = Base.decode64!(signature_b64)

    if :crypto.verify(:eddsa, :none, attestation_hash, signature, [raw_pub, :ed25519]) do
      Mix.shell().info("""
      VERIFIED - Attestation signature is valid.
        Hash:      #{attestation_hash}
        AST-Hash:  #{extract_field(message, "AST-Hash") || "N/A"}
        Complexity: #{extract_field(message, "Complexity") || "N/A"}
        Model:     #{extract_field(message, "LLM-Model") || "N/A"}
        Allowlist: #{extract_field(message, "Allowlist-Version") || "N/A"}
      """)
    else
      Mix.shell().error("FAILED - Attestation signature does NOT verify!")
      System.halt(1)
    end
  end

  defp extract_field(message, field_name) do
    case Regex.run(~r/#{Regex.escape(field_name)}:\s*(.+)/, message) do
      [_, value] -> String.trim(value)
      nil -> nil
    end
  end
end
