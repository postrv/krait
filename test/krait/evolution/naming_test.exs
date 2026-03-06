defmodule Krait.Evolution.NamingTest do
  use ExUnit.Case, async: true

  alias Krait.Evolution.Naming

  describe "validate_skill_name/1" do
    test "accepts valid snake_case names" do
      assert {:ok, "greeting"} = Naming.validate_skill_name("greeting")
      assert {:ok, "web_fetch"} = Naming.validate_skill_name("web_fetch")
      assert {:ok, "bitcoin_price_v2"} = Naming.validate_skill_name("bitcoin_price_v2")
    end

    test "accepts single-character name" do
      assert {:ok, "a"} = Naming.validate_skill_name("a")
    end

    test "rejects path traversal attempts" do
      assert {:error, :invalid_skill_name} = Naming.validate_skill_name("../../config/runtime")
      assert {:error, :invalid_skill_name} = Naming.validate_skill_name("../hack")
      assert {:error, :invalid_skill_name} = Naming.validate_skill_name("foo/bar")
      assert {:error, :invalid_skill_name} = Naming.validate_skill_name("foo\\bar")
    end

    test "rejects names with dots" do
      assert {:error, :invalid_skill_name} = Naming.validate_skill_name("foo.bar")
      assert {:error, :invalid_skill_name} = Naming.validate_skill_name(".hidden")
    end

    test "rejects empty and whitespace" do
      assert {:error, :invalid_skill_name} = Naming.validate_skill_name("")
      assert {:error, :invalid_skill_name} = Naming.validate_skill_name("   ")
    end

    test "rejects names starting with numbers or underscores" do
      assert {:error, :invalid_skill_name} = Naming.validate_skill_name("2fast")
      assert {:error, :invalid_skill_name} = Naming.validate_skill_name("_private")
    end

    test "rejects uppercase" do
      assert {:error, :invalid_skill_name} = Naming.validate_skill_name("Hello")
      assert {:error, :invalid_skill_name} = Naming.validate_skill_name("camelCase")
    end

    test "rejects names over 64 characters" do
      long_name = String.duplicate("a", 65)
      assert {:error, :invalid_skill_name} = Naming.validate_skill_name(long_name)
    end

    test "accepts names at exactly 64 characters" do
      name = "a" <> String.duplicate("b", 63)
      assert {:ok, ^name} = Naming.validate_skill_name(name)
    end

    test "trims whitespace before validating" do
      assert {:ok, "greeting"} = Naming.validate_skill_name("  greeting  ")
    end

    test "rejects nil" do
      assert {:error, :invalid_skill_name} = Naming.validate_skill_name(nil)
    end

    test "rejects integers" do
      assert {:error, :invalid_skill_name} = Naming.validate_skill_name(42)
    end

    test "rejects shell metacharacters" do
      assert {:error, :invalid_skill_name} = Naming.validate_skill_name("foo;rm -rf /")
      assert {:error, :invalid_skill_name} = Naming.validate_skill_name("foo$(whoami)")
      assert {:error, :invalid_skill_name} = Naming.validate_skill_name("foo`id`")
    end
  end

  describe "to_module_name/1" do
    test "converts snake_case to PascalCase" do
      assert "BitcoinPrice" = Naming.to_module_name("bitcoin_price")
      assert "Greeting" = Naming.to_module_name("greeting")
      assert "WebFetchV2" = Naming.to_module_name("web_fetch_v2")
    end
  end
end
