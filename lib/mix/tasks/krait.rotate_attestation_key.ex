defmodule Mix.Tasks.Krait.RotateAttestationKey do
  @moduledoc """
  Generate a new Ed25519 keypair for attestation signing.

  ## Usage

      mix krait.rotate_attestation_key [--output-dir PATH]

  Generates:
  - `krait-attestation-ed25519.pem` (private key - keep secret)
  - `krait-attestation-ed25519.pub` (public key - distribute for verification)

  The task does NOT automatically replace the active key. A human must:
  1. Review the new keypair
  2. Deploy the private key to the KRAIT_ATTESTATION_KEY_PATH location
  3. Distribute the public key to verification tooling
  """

  use Mix.Task

  @shortdoc "Generate a new Ed25519 attestation keypair"

  @impl true
  def run(args) do
    {opts, _, _} = OptionParser.parse(args, strict: [output_dir: :string])
    output_dir = Keyword.get(opts, :output_dir, ".")

    File.mkdir_p!(output_dir)

    priv_path = Path.join(output_dir, "krait-attestation-ed25519.pem")
    pub_path = Path.join(output_dir, "krait-attestation-ed25519.pub")

    # Generate Ed25519 keypair via openssl
    case System.cmd("openssl", ["genpkey", "-algorithm", "ed25519", "-out", priv_path]) do
      {_, 0} ->
        # Set restrictive permissions on private key
        File.chmod!(priv_path, 0o600)

        # Extract public key
        case System.cmd("openssl", ["pkey", "-in", priv_path, "-pubout", "-out", pub_path]) do
          {_, 0} ->
            Mix.shell().info("""

            Attestation keypair generated:
              Private key: #{priv_path} (mode 600)
              Public key:  #{pub_path}

            Next steps:
              1. Deploy private key to KRAIT_ATTESTATION_KEY_PATH
              2. Distribute public key to verification tooling
              3. Update `mix krait.verify` with the new public key
            """)

          {err, code} ->
            Mix.raise("Failed to extract public key (exit #{code}): #{err}")
        end

      {err, code} ->
        Mix.raise("Failed to generate keypair (exit #{code}): #{err}")
    end
  end
end
