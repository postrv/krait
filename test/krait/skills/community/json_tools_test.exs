defmodule Krait.Skills.Community.JsonToolsTest do
  use ExUnit.Case, async: true

  alias Krait.Skills.Community.JsonTools

  describe "behaviour compliance" do
    test "implements CapableSkill callbacks" do
      assert Code.ensure_loaded?(JsonTools)
      assert function_exported?(JsonTools, :name, 0)
      assert function_exported?(JsonTools, :description, 0)
      assert function_exported?(JsonTools, :required_capabilities, 0)
      assert function_exported?(JsonTools, :execute, 2)
    end

    test "name returns expected value" do
      assert JsonTools.name() == "json_tools"
    end

    test "requires no capabilities" do
      assert JsonTools.required_capabilities() == []
    end
  end

  describe "validate action" do
    test "validates correct JSON" do
      assert {:ok, %{valid: true}} =
               JsonTools.execute(%{"action" => "validate", "json" => ~s({"key": "value"})}, %{})
    end

    test "rejects invalid JSON" do
      assert {:ok, %{valid: false, error: _}} =
               JsonTools.execute(%{"action" => "validate", "json" => "not json"}, %{})
    end
  end

  describe "keys action" do
    test "extracts top-level keys" do
      json = Jason.encode!(%{"name" => "krait", "version" => "0.1.0"})

      assert {:ok, %{keys: keys}} =
               JsonTools.execute(%{"action" => "keys", "json" => json}, %{})

      assert Enum.sort(keys) == ["name", "version"]
    end

    test "returns error for non-object JSON" do
      assert {:error, _} =
               JsonTools.execute(%{"action" => "keys", "json" => "[1,2,3]"}, %{})
    end
  end

  describe "extract_path action" do
    test "extracts nested value by dot path" do
      json = Jason.encode!(%{"user" => %{"name" => "krait", "role" => "agent"}})

      assert {:ok, %{value: "krait"}} =
               JsonTools.execute(
                 %{"action" => "extract_path", "json" => json, "path" => "user.name"},
                 %{}
               )
    end

    test "returns nil for missing path" do
      json = Jason.encode!(%{"user" => %{"name" => "krait"}})

      assert {:ok, %{value: nil}} =
               JsonTools.execute(
                 %{"action" => "extract_path", "json" => json, "path" => "user.email"},
                 %{}
               )
    end

    test "handles array index access" do
      json = Jason.encode!(%{"items" => [%{"id" => 1}, %{"id" => 2}]})

      assert {:ok, %{value: [%{"id" => 1}, %{"id" => 2}]}} =
               JsonTools.execute(
                 %{"action" => "extract_path", "json" => json, "path" => "items"},
                 %{}
               )
    end
  end

  describe "pretty_print action" do
    test "formats compact JSON" do
      json = ~s({"a":1,"b":2})

      assert {:ok, %{result: formatted}} =
               JsonTools.execute(%{"action" => "pretty_print", "json" => json}, %{})

      assert formatted =~ "\n"
      assert formatted =~ "  "
    end
  end

  describe "flatten action" do
    test "flattens nested object" do
      json = Jason.encode!(%{"a" => %{"b" => %{"c" => 1}}, "d" => 2})

      assert {:ok, %{result: flat}} =
               JsonTools.execute(%{"action" => "flatten", "json" => json}, %{})

      assert flat["a.b.c"] == 1
      assert flat["d"] == 2
    end
  end

  describe "error cases" do
    test "returns error for unknown action" do
      assert {:error, _} =
               JsonTools.execute(%{"action" => "unknown", "json" => "{}"}, %{})
    end

    test "returns error for missing json param" do
      assert {:error, _} =
               JsonTools.execute(%{"action" => "validate"}, %{})
    end

    test "returns error for invalid JSON in non-validate actions" do
      assert {:error, _} =
               JsonTools.execute(%{"action" => "keys", "json" => "not json"}, %{})
    end
  end
end
