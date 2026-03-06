defmodule Krait.Evolution.AttestationTest do
  use ExUnit.Case, async: true

  alias Krait.Evolution.Attestation
  alias Krait.Evolution.ValidatedProposal

  @valid_proposal %ValidatedProposal{
    code: "defmodule Test do\nend",
    test_code: "defmodule TestTest do\nend",
    ast_hash: "abc123def456",
    complexity: 12,
    security_findings: [],
    taint_flows: [],
    spec: %{
      skill_name: "test_skill",
      description: "A test skill",
      llm_model: "qwen2.5-coder:14b",
      prompt_hash: "sha256hash123"
    }
  }

  describe "build/1" do
    test "captures all fields from ValidatedProposal" do
      attestation = Attestation.build(@valid_proposal)

      assert attestation.ast_hash == "abc123def456"
      assert attestation.complexity == 12
      assert attestation.security_findings_count == 0
      assert attestation.taint_flows_count == 0
      assert %DateTime{} = attestation.timestamp
      assert is_binary(attestation.attestation_hash)
    end

    test "computes allowlist_version from both allowlist.ex and allowlist.rs" do
      attestation = Attestation.build(@valid_proposal)

      assert is_binary(attestation.allowlist_version)
      # Should be a hex-encoded hash
      assert String.length(attestation.allowlist_version) == 64
    end

    test "produces deterministic attestation_hash for same input" do
      a1 = Attestation.build(@valid_proposal)
      a2 = Attestation.build(@valid_proposal)

      assert a1.attestation_hash == a2.attestation_hash
    end

    test "includes llm_model from proposal provenance" do
      attestation = Attestation.build(@valid_proposal)
      assert attestation.llm_model == "qwen2.5-coder:14b"
    end

    test "includes llm_prompt_hash from proposal provenance" do
      attestation = Attestation.build(@valid_proposal)
      assert attestation.llm_prompt_hash == "sha256hash123"
    end

    test "handles nil security_findings and taint_flows" do
      proposal = %{@valid_proposal | security_findings: nil, taint_flows: nil}
      attestation = Attestation.build(proposal)

      assert attestation.security_findings_count == 0
      assert attestation.taint_flows_count == 0
    end

    test "handles missing llm fields gracefully" do
      proposal = %{@valid_proposal | spec: %{skill_name: "test"}}
      attestation = Attestation.build(proposal)

      assert attestation.llm_model == "unknown"
      assert attestation.llm_prompt_hash == nil
    end
  end

  describe "sign/1 and verify/2" do
    test "sign/1 produces Ed25519 signature using test key" do
      attestation = Attestation.build(@valid_proposal)
      {:ok, _priv, pub} = generate_test_keypair()

      {:ok, signature} = Attestation.sign(attestation)
      assert is_binary(signature)
      # Ed25519 signatures are 64 bytes, base64 encoded
      assert byte_size(Base.decode64!(signature)) == 64

      assert :ok = Attestation.verify(attestation, signature, pub)
    end

    test "verify/2 returns error for tampered data" do
      attestation = Attestation.build(@valid_proposal)
      {:ok, _priv, pub} = generate_test_keypair()

      {:ok, signature} = Attestation.sign(attestation)

      # Tamper with attestation
      tampered = %{attestation | complexity: 999}
      assert {:error, :invalid_signature} = Attestation.verify(tampered, signature, pub)
    end

    test "sign/1 returns error when private key missing" do
      # Temporarily set key path to nonexistent file
      original = Application.get_env(:krait, :attestation_key_path)
      Application.put_env(:krait, :attestation_key_path, "/nonexistent/key.pem")

      attestation = Attestation.build(@valid_proposal)
      assert {:error, :key_unavailable} = Attestation.sign(attestation)

      if original, do: Application.put_env(:krait, :attestation_key_path, original)
    end
  end

  describe "to_commit_message/2" do
    test "formats attestation fields in commit message" do
      attestation = Attestation.build(@valid_proposal)
      msg = Attestation.to_commit_message(attestation, "test_sig_base64")

      assert msg =~ "Attestation-Hash:"
      assert msg =~ "Attestation-Signature: test_sig_base64"
      assert msg =~ "AST-Hash: abc123def456"
      assert msg =~ "Complexity: 12"
      assert msg =~ "Allowlist-Version:"
    end
  end

  describe "to_json/2" do
    test "produces valid JSON with all fields" do
      attestation = Attestation.build(@valid_proposal)
      json = Attestation.to_json(attestation, "test_sig")

      decoded = Jason.decode!(json)
      assert decoded["ast_hash"] == "abc123def456"
      assert decoded["complexity"] == 12
      assert decoded["signature"] == "test_sig"
      assert is_binary(decoded["attestation_hash"])
    end
  end

  # Helper to generate test Ed25519 keypair using openssl
  defp generate_test_keypair do
    path = Path.join(System.tmp_dir!(), "krait_test_ed25519_#{:rand.uniform(100_000)}.pem")

    # Generate Ed25519 key using openssl
    {_, 0} = System.cmd("openssl", ["genpkey", "-algorithm", "ed25519", "-out", path])

    # Read PEM to extract public key for verification
    pem = File.read!(path)
    [entry] = :public_key.pem_decode(pem)
    decoded = :public_key.pem_entry_decode(entry)

    # Extract raw 32-byte private key (OTP versions decode to different formats)
    raw_priv =
      case decoded do
        {:ECPrivateKey, 1, priv_bytes, {:namedCurve, {1, 3, 101, 112}}, _, _} ->
          priv_bytes

        {:PrivateKeyInfo, _version, _algo, priv_key_der, _} ->
          <<0x04, 0x20, key::binary-size(32)>> = priv_key_der
          key
      end

    # Derive public key
    {pub, ^raw_priv} = :crypto.generate_key(:eddsa, :ed25519, raw_priv)

    Application.put_env(:krait, :attestation_key_path, path)

    on_exit(fn ->
      File.rm(path)
      Application.delete_env(:krait, :attestation_key_path)
    end)

    {:ok, raw_priv, pub}
  end
end
