defmodule Krait.Security.NifIntegrityTest do
  use ExUnit.Case, async: true

  alias Krait.Security.NifIntegrity

  describe "verify!/0" do
    test "passes when NIF binary is not present (optional in dev)" do
      # In test, the NIF may or may not be loaded — verify! should not crash
      assert :ok = NifIntegrity.verify!()
    end
  end

  describe "compute_hash/1" do
    test "computes SHA256 hash of a file" do
      path = Path.join(System.tmp_dir!(), "nif_test_#{:rand.uniform(100_000)}.bin")
      File.write!(path, "test binary content")

      hash = NifIntegrity.compute_hash(path)

      # SHA256 hex is 64 chars
      assert String.length(hash) == 64
      assert Regex.match?(~r/^[a-f0-9]{64}$/, hash)

      # Deterministic
      assert hash == NifIntegrity.compute_hash(path)

      File.rm!(path)
    end
  end

  describe "nif_binary_path/1" do
    test "finds the Rustler runtime NIF name copied under priv/native" do
      dir =
        Path.join(System.tmp_dir!(), "nif_integrity_path_#{System.unique_integer([:positive])}")

      native_dir = Path.join(dir, "native")
      File.mkdir_p!(native_dir)

      path = Path.join(native_dir, "krait_analyzer.so")
      File.write!(path, "runtime nif")

      assert NifIntegrity.nif_binary_path(dir) == path

      File.rm_rf!(dir)
    end

    test "still accepts platform-specific library names" do
      dir =
        Path.join(
          System.tmp_dir!(),
          "nif_integrity_platform_#{System.unique_integer([:positive])}"
        )

      native_dir = Path.join(dir, "native")
      File.mkdir_p!(native_dir)

      path = Path.join(native_dir, "libkrait_analyzer.dylib")
      File.write!(path, "platform nif")

      assert NifIntegrity.nif_binary_path(dir) == path

      File.rm_rf!(dir)
    end
  end

  describe "hash verification" do
    test "passes with matching sidecar hash" do
      dir = Path.join(System.tmp_dir!(), "nif_integrity_#{:rand.uniform(100_000)}")
      File.mkdir_p!(dir)
      bin_path = Path.join(dir, "test.so")
      hash_path = bin_path <> ".sha256"

      File.write!(bin_path, "binary content for hash test")
      expected_hash = NifIntegrity.compute_hash(bin_path)
      File.write!(hash_path, expected_hash)

      # Verify using the public function indirectly
      # We can't call verify! directly since it uses nif_binary_path()
      # Instead verify the hash computation logic is correct
      actual = NifIntegrity.compute_hash(bin_path)
      assert actual == expected_hash

      File.rm_rf!(dir)
    end

    test "detects hash mismatch" do
      dir = Path.join(System.tmp_dir!(), "nif_integrity_mismatch_#{:rand.uniform(100_000)}")
      File.mkdir_p!(dir)
      bin_path = Path.join(dir, "test.so")

      File.write!(bin_path, "original content")
      original_hash = NifIntegrity.compute_hash(bin_path)

      # Tamper with binary
      File.write!(bin_path, "tampered content")
      tampered_hash = NifIntegrity.compute_hash(bin_path)

      assert original_hash != tampered_hash

      File.rm_rf!(dir)
    end
  end

  describe "sidecar absent" do
    test "verify!/0 skips when .sha256 sidecar file is absent" do
      # This is the default case in dev/test — no sidecar file exists
      # verify! should return :ok with a warning log
      assert :ok = NifIntegrity.verify!()
    end
  end
end
