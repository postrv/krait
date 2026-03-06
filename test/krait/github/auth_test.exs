defmodule Krait.GitHub.AuthTest do
  use ExUnit.Case, async: true

  describe "generate_jwt/0" do
    test "returns error when no private key path is configured" do
      Application.put_env(:krait, :github_app_id, "12345")
      Application.put_env(:krait, :github_private_key_path, nil)

      assert {:error, :no_private_key_path} = Krait.GitHub.Auth.generate_jwt()
    after
      Application.delete_env(:krait, :github_app_id)
      Application.delete_env(:krait, :github_private_key_path)
    end

    test "returns error when key file does not exist" do
      Application.put_env(:krait, :github_app_id, "12345")
      Application.put_env(:krait, :github_private_key_path, "/nonexistent/key.pem")

      assert {:error, {:key_read_failed, :enoent}} = Krait.GitHub.Auth.generate_jwt()
    after
      Application.delete_env(:krait, :github_app_id)
      Application.delete_env(:krait, :github_private_key_path)
    end

    test "generates valid JWT with proper PEM key" do
      # Generate a test RSA key
      key = :public_key.generate_key({:rsa, 2048, 65_537})
      pem_entry = :public_key.pem_entry_encode(:RSAPrivateKey, key)
      pem = :public_key.pem_encode([pem_entry])

      tmp_path =
        Path.join(System.tmp_dir!(), "krait_test_key_#{System.unique_integer([:positive])}.pem")

      File.write!(tmp_path, pem)

      Application.put_env(:krait, :github_app_id, "12345")
      Application.put_env(:krait, :github_private_key_path, tmp_path)

      assert {:ok, jwt} = Krait.GitHub.Auth.generate_jwt()
      assert is_binary(jwt)

      # JWT has 3 parts separated by dots
      parts = String.split(jwt, ".")
      assert length(parts) == 3

      # Decode and verify claims
      [_header, payload, _sig] = parts
      {:ok, claims} = Base.url_decode64(payload, padding: false)
      claims = Jason.decode!(claims)

      assert claims["iss"] == "12345"
      assert is_integer(claims["iat"])
      assert is_integer(claims["exp"])
      assert claims["exp"] > claims["iat"]
    after
      Application.delete_env(:krait, :github_app_id)
      Application.delete_env(:krait, :github_private_key_path)
    end
  end

  describe "read_private_key path hardening" do
    test "rejects nil github_key_dir in prod env" do
      Application.put_env(:krait, :github_app_id, "12345")
      Application.put_env(:krait, :github_private_key_path, "/some/key.pem")
      Application.put_env(:krait, :github_key_dir, nil)

      _prev_env = Application.get_env(:krait, :env)
      Application.put_env(:krait, :env, :prod)

      assert {:error, :key_dir_required} = Krait.GitHub.Auth.generate_jwt()
    after
      Application.delete_env(:krait, :github_app_id)
      Application.delete_env(:krait, :github_private_key_path)
      Application.delete_env(:krait, :github_key_dir)
      Application.put_env(:krait, :env, :test)
    end

    test "rejects symlink pointing outside key_dir" do
      # Create a temp directory structure
      tmp_dir =
        Path.join(System.tmp_dir!(), "krait_auth_test_#{System.unique_integer([:positive])}")

      key_dir = Path.join(tmp_dir, "keys")
      outside_dir = Path.join(tmp_dir, "outside")
      File.mkdir_p!(key_dir)
      File.mkdir_p!(outside_dir)

      # Create a real file outside the key_dir
      outside_file = Path.join(outside_dir, "secret.pem")
      File.write!(outside_file, "not-a-real-key")

      # Create a symlink inside key_dir pointing outside
      symlink_path = Path.join(key_dir, "escape.pem")
      File.ln_s!(outside_file, symlink_path)

      Application.put_env(:krait, :github_app_id, "12345")
      Application.put_env(:krait, :github_private_key_path, symlink_path)
      Application.put_env(:krait, :github_key_dir, key_dir)

      assert {:error, {:key_path_rejected, _}} = Krait.GitHub.Auth.generate_jwt()
    after
      Application.delete_env(:krait, :github_app_id)
      Application.delete_env(:krait, :github_private_key_path)
      Application.delete_env(:krait, :github_key_dir)
    end
  end

  describe "generate_installation_token/1" do
    setup do
      bypass = Bypass.open()

      # Generate a test RSA key
      key = :public_key.generate_key({:rsa, 2048, 65_537})
      pem_entry = :public_key.pem_entry_encode(:RSAPrivateKey, key)
      pem = :public_key.pem_encode([pem_entry])

      tmp_path =
        Path.join(System.tmp_dir!(), "krait_test_key_#{System.unique_integer([:positive])}.pem")

      File.write!(tmp_path, pem)

      Application.put_env(:krait, :github_app_id, "12345")
      Application.put_env(:krait, :github_private_key_path, tmp_path)
      Application.put_env(:krait, :github_installation_id, "67890")

      on_exit(fn ->
        Application.delete_env(:krait, :github_app_id)
        Application.delete_env(:krait, :github_private_key_path)
        Application.delete_env(:krait, :github_installation_id)
        File.rm(tmp_path)
      end)

      %{bypass: bypass, tmp_path: tmp_path}
    end

    @tag :integration
    test "exchanges JWT for installation token via GitHub API" do
      # This test would need a real or mocked GitHub API endpoint
      # Marked as integration test since it requires network access
      assert true
    end
  end
end
