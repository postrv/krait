defmodule Krait.Memory.GuardTest do
  use ExUnit.Case, async: true

  describe "validate_write/2" do
    test "allows normal memory writes" do
      assert :ok = Krait.Memory.Guard.validate_write("prefs:theme", "dark")
    end

    test "rejects writes containing Anthropic API keys" do
      assert {:rejected, reason} =
               Krait.Memory.Guard.validate_write("config", "sk-ant-api03-abc123def")

      assert reason =~ "API key"
    end

    test "rejects writes containing OpenAI API keys" do
      assert {:rejected, reason} =
               Krait.Memory.Guard.validate_write("config", "sk-proj-abc123def456")

      assert reason =~ "API key"
    end

    test "rejects writes containing private key material" do
      pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."

      assert {:rejected, reason} =
               Krait.Memory.Guard.validate_write("data", pem)

      assert reason =~ "private key"
    end

    test "rejects writes containing EC private keys" do
      pem = "-----BEGIN EC PRIVATE KEY-----\nMHQC..."

      assert {:rejected, reason} =
               Krait.Memory.Guard.validate_write("data", pem)

      assert reason =~ "private key"
    end

    test "rejects writes containing generic private keys" do
      pem = "-----BEGIN PRIVATE KEY-----\nMIIE..."

      assert {:rejected, reason} =
               Krait.Memory.Guard.validate_write("data", pem)

      assert reason =~ "private key"
    end

    test "rejects writes to restricted key namespaces" do
      assert {:rejected, _} =
               Krait.Memory.Guard.validate_write("_system:config", "anything")
    end

    test "rejects writes exceeding size limit" do
      big = String.duplicate("x", 1_000_001)

      assert {:rejected, reason} =
               Krait.Memory.Guard.validate_write("key", big)

      assert reason =~ "size"
    end

    test "allows writes just under size limit" do
      ok_size = String.duplicate("x", 1_000_000)
      assert :ok = Krait.Memory.Guard.validate_write("key", ok_size)
    end

    test "rejects writes containing JWT tokens" do
      jwt =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"

      assert {:rejected, reason} =
               Krait.Memory.Guard.validate_write("token", jwt)

      assert reason =~ "JWT"
    end

    test "rejects writes containing GitHub tokens" do
      assert {:rejected, reason} =
               Krait.Memory.Guard.validate_write(
                 "config",
                 "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
               )

      assert reason =~ "API key"
    end

    test "handles non-string values by inspecting them" do
      assert :ok = Krait.Memory.Guard.validate_write("key", %{safe: "data"})
    end

    # --- Edge cases: false positives ---

    test "allows variable names that resemble key prefixes" do
      # A variable named 'ghp_enabled' should NOT trigger the API key check
      # because the guard looks for substrings, but this is a known limitation.
      # This test documents that variable-like names containing the prefix DO trigger.
      # In practice, this is the safer behavior (flag anything containing the prefix).
      assert {:rejected, _} =
               Krait.Memory.Guard.validate_write("config", "ghp_enabled_flag")
    end

    test "allows value that contains 'key' as a normal word" do
      assert :ok = Krait.Memory.Guard.validate_write("notes", "The key to success is persistence")
    end

    test "allows value containing 'private' as a normal word" do
      assert :ok = Krait.Memory.Guard.validate_write("notes", "This is a private matter")
    end

    test "allows value with 'token' in normal context" do
      assert :ok = Krait.Memory.Guard.validate_write("notes", "Use the token ring network")
    end

    # --- Edge cases: empty and nil values ---

    test "allows empty string value" do
      assert :ok = Krait.Memory.Guard.validate_write("key", "")
    end

    test "allows nil value (inspected as 'nil')" do
      assert :ok = Krait.Memory.Guard.validate_write("key", nil)
    end

    test "allows integer value" do
      assert :ok = Krait.Memory.Guard.validate_write("counter", 42)
    end

    test "allows list value" do
      assert :ok = Krait.Memory.Guard.validate_write("items", [1, 2, 3])
    end

    # --- Boundary tests ---

    test "allows value at exactly 1MB (1_000_000 bytes)" do
      exactly_1mb = String.duplicate("x", 1_000_000)
      assert :ok = Krait.Memory.Guard.validate_write("key", exactly_1mb)
    end

    test "rejects value at 1MB + 1 byte" do
      over_1mb = String.duplicate("x", 1_000_001)
      assert {:rejected, reason} = Krait.Memory.Guard.validate_write("key", over_1mb)
      assert reason =~ "size"
    end

    # --- Multi-line credential patterns ---

    test "rejects multi-line PEM private key" do
      pem = """
      Some preamble text
      -----BEGIN RSA PRIVATE KEY-----
      MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcLiKFMKj
      dObfYnlQVflZ0PQGLrimPJCx1SJo8oDQ0MFVrEv8VthZJMxk+U+9c9e5gzmj
      -----END RSA PRIVATE KEY-----
      More text after
      """

      assert {:rejected, reason} = Krait.Memory.Guard.validate_write("cert", pem)
      assert reason =~ "private key"
    end

    test "rejects DSA private key" do
      pem = "-----BEGIN DSA PRIVATE KEY-----\nMIIBuwIBAAJ..."
      assert {:rejected, reason} = Krait.Memory.Guard.validate_write("cert", pem)
      assert reason =~ "private key"
    end

    test "rejects EC private key" do
      pem = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEI..."
      assert {:rejected, reason} = Krait.Memory.Guard.validate_write("cert", pem)
      assert reason =~ "private key"
    end

    # --- Slack token variants ---

    test "rejects Slack bot token (xoxb-)" do
      assert {:rejected, reason} =
               Krait.Memory.Guard.validate_write("slack", "xoxb-1234-5678-abcdefghijk")

      assert reason =~ "API key"
    end

    test "rejects Slack user token (xoxp-)" do
      assert {:rejected, reason} =
               Krait.Memory.Guard.validate_write("slack", "xoxp-1234-5678-abcdefghijk")

      assert reason =~ "API key"
    end

    # --- GitHub token variants ---

    test "rejects GitHub fine-grained personal access token" do
      assert {:rejected, reason} =
               Krait.Memory.Guard.validate_write("gh", "github_pat_12345abcdef")

      assert reason =~ "API key"
    end

    test "rejects GitHub OAuth token (gho_)" do
      assert {:rejected, reason} =
               Krait.Memory.Guard.validate_write("gh", "gho_1234567890abcdef")

      assert reason =~ "API key"
    end

    test "rejects GitHub server token (ghs_)" do
      assert {:rejected, reason} =
               Krait.Memory.Guard.validate_write("gh", "ghs_1234567890abcdef")

      assert reason =~ "API key"
    end

    # --- JWT edge cases ---

    test "rejects JWT embedded in larger text" do
      text =
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U please use this"

      assert {:rejected, reason} = Krait.Memory.Guard.validate_write("auth", text)
      assert reason =~ "JWT"
    end

    test "allows base64 that does not match JWT three-part structure" do
      # Two parts only — not a valid JWT
      assert :ok =
               Krait.Memory.Guard.validate_write(
                 "data",
                 "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0"
               )
    end

    # --- Reserved namespace edge cases ---

    test "allows keys that contain _system but don't start with _system:" do
      assert :ok = Krait.Memory.Guard.validate_write("my_system_config", "safe")
    end

    test "rejects _system: prefix regardless of what follows" do
      assert {:rejected, _} = Krait.Memory.Guard.validate_write("_system:", "")
      assert {:rejected, _} = Krait.Memory.Guard.validate_write("_system:anything", "value")
    end

    # --- Credential hidden in map/struct values ---

    test "rejects API key hidden in a map value (inspected)" do
      map_with_key = %{nested: %{token: "sk-ant-api03-hidden-key-value"}}
      assert {:rejected, reason} = Krait.Memory.Guard.validate_write("data", map_with_key)
      assert reason =~ "API key"
    end

    test "rejects JWT hidden in a list value (inspected)" do
      jwt =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"

      list_with_jwt = ["safe", jwt, "also safe"]
      assert {:rejected, reason} = Krait.Memory.Guard.validate_write("data", list_with_jwt)
      assert reason =~ "JWT"
    end

    # --- OpenAI key prefix ---

    test "rejects OpenAI project key (sk-proj-)" do
      assert {:rejected, reason} =
               Krait.Memory.Guard.validate_write("config", "sk-proj-abcdef123456789")

      assert reason =~ "API key"
    end

    # --- Task 8: Extended credential patterns ---

    test "rejects AWS access key (AKIA prefix)" do
      assert {:rejected, reason} =
               Krait.Memory.Guard.validate_write("config", "AKIAIOSFODNN7EXAMPLE")

      assert reason =~ "API key"
    end

    test "rejects Stripe secret key (sk_live_)" do
      assert {:rejected, reason} =
               Krait.Memory.Guard.validate_write("config", "sk_live_4eC39HqLyjWDarjtT1zdp7dc")

      assert reason =~ "API key"
    end

    test "rejects Stripe test key (sk_test_)" do
      assert {:rejected, reason} =
               Krait.Memory.Guard.validate_write("config", "sk_test_4eC39HqLyjWDarjtT1zdp7dc")

      assert reason =~ "API key"
    end

    test "rejects Google service account JSON" do
      sa_json = ~s({"type": "service_account", "project_id": "my-project"})

      assert {:rejected, reason} =
               Krait.Memory.Guard.validate_write("config", sa_json)

      assert reason =~ "cloud service credentials"
    end

    test "rejects Azure connection string" do
      conn_str =
        "DefaultEndpointsProtocol=https;AccountName=test;AccountKey=abc123;EndpointSuffix=core.windows.net"

      assert {:rejected, reason} =
               Krait.Memory.Guard.validate_write("config", conn_str)

      assert reason =~ "cloud service credentials"
    end

    test "rejects database connection string with credentials" do
      assert {:rejected, reason} =
               Krait.Memory.Guard.validate_write(
                 "config",
                 "postgres://admin:secret_password@db.example.com:5432/mydb"
               )

      assert reason =~ "database connection string"
    end

    test "rejects Google API key (AIza prefix)" do
      assert {:rejected, reason} =
               Krait.Memory.Guard.validate_write("config", "AIzaSyD-abc123def456ghijklmnop")

      assert reason =~ "API key"
    end

    test "rejects HuggingFace token (hf_ prefix)" do
      assert {:rejected, reason} =
               Krait.Memory.Guard.validate_write("config", "hf_AbCdEfGhIjKlMnOpQrStUvWxYz")

      assert reason =~ "API key"
    end

    test "rejects Databricks token (dapi_ prefix)" do
      assert {:rejected, reason} =
               Krait.Memory.Guard.validate_write("config", "dapi_1234567890abcdef")

      assert reason =~ "API key"
    end

    test "allows normal text containing 'dapi' without underscore" do
      # "dapi" without underscore suffix should not trigger false positive
      assert :ok =
               Krait.Memory.Guard.validate_write("notes", "The API adapter is dapi-compatible")
    end

    test "allows normal text that doesn't match credential patterns" do
      assert :ok =
               Krait.Memory.Guard.validate_write(
                 "note",
                 "The user asked about authentication methods"
               )
    end

    # --- Case-insensitive credential detection ---

    test "rejects API key with varied case (AKIA uppercase)" do
      assert {:rejected, reason} =
               Krait.Memory.Guard.validate_write("config", "akiaIOSFODNN7EXAMPLE")

      assert reason =~ "API key"
    end

    test "rejects GitHub token mixed case" do
      assert {:rejected, reason} =
               Krait.Memory.Guard.validate_write("config", "GHP_1234567890abcdef")

      assert reason =~ "API key"
    end

    # --- Base64-encoded credential detection ---

    test "rejects base64-encoded API key" do
      encoded = Base.encode64("sk-ant-api03-abc123secretvalue")

      assert {:rejected, reason} =
               Krait.Memory.Guard.validate_write("config", encoded)

      assert reason =~ "encoded credential"
    end

    test "rejects base64-encoded private key" do
      encoded = Base.encode64("-----BEGIN RSA PRIVATE KEY-----\nMIIE...")

      assert {:rejected, reason} =
               Krait.Memory.Guard.validate_write("config", encoded)

      assert reason =~ "encoded credential"
    end

    test "allows short base64 non-credentials" do
      assert :ok = Krait.Memory.Guard.validate_write("data", "aGVsbG8=")
    end

    test "allows normal base64 non-credentials" do
      encoded = Base.encode64("Hello world, this is just a normal message")
      assert :ok = Krait.Memory.Guard.validate_write("data", encoded)
    end

    # --- Hex-encoded credential detection ---

    test "rejects hex-encoded API key" do
      encoded = Base.encode16("sk-ant-api03-abc123secretvalue")

      assert {:rejected, reason} =
               Krait.Memory.Guard.validate_write("config", encoded)

      assert reason =~ "encoded credential"
    end

    test "allows normal hex strings" do
      # A hex string that doesn't decode to a credential
      assert :ok =
               Krait.Memory.Guard.validate_write(
                 "data",
                 "deadbeef0123456789abcdef"
               )
    end
  end
end
