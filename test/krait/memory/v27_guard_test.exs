defmodule Krait.Memory.V27GuardTest do
  @moduledoc "v27 M-5: Shannon entropy analysis for credential detection"
  use ExUnit.Case, async: true

  alias Krait.Memory.Guard

  describe "entropy-based credential detection" do
    test "rejects high-entropy strings >= 32 chars" do
      # Deterministic high-entropy string — all unique chars, no API key prefix matches
      # Entropy of this string is ~5.17 bits/char (well above 4.5 threshold)
      secret = "Qw3rTy7!Zx9@Lm4#Bn6$Vp2%Kj8^Fd1&Hs5*Gc0"
      assert {:rejected, msg} = Guard.validate_write("key", secret)
      assert msg =~ "high entropy"
    end

    test "allows normal text even if >= 32 chars" do
      # Normal English text has low entropy (~3.5-4.0 bits/char)
      text = "this is a perfectly normal sentence that is long enough to test"
      assert :ok = Guard.validate_write("key", text)
    end

    test "allows short high-entropy strings" do
      # Short strings are exempt (< 32 chars)
      assert :ok = Guard.validate_write("key", "abc123XYZ")
    end

    test "allows repeated character strings" do
      # Very low entropy (< 4.5)
      assert :ok = Guard.validate_write("key", String.duplicate("aaabbb", 10))
    end

    test "shannon_entropy calculates correctly" do
      # Single character repeated = 0 entropy
      assert Guard.shannon_entropy("aaaa") == 0.0

      # Two equally frequent chars = 1 bit
      assert_in_delta Guard.shannon_entropy("aabb"), 1.0, 0.01

      # Empty string = 0
      assert Guard.shannon_entropy("") == 0.0
    end

    test "allows base64-encoded non-credentials (checked by encoding detection instead)" do
      # Base64 is handled by check_encoded_credentials, not entropy
      # Pure base64 strings are exempt from entropy check to avoid false positives
      encoded = Base.encode64("Hello world, this is just a normal message")
      assert :ok = Guard.validate_write("key", encoded)
    end
  end
end
