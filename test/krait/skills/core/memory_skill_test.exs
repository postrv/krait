defmodule Krait.Skills.Core.MemorySkillTest do
  use ExUnit.Case, async: false

  alias Krait.Skills.Core.MemorySkill

  setup do
    # Start a dedicated Hot memory instance for testing
    name = :"memory_skill_test_#{System.unique_integer([:positive])}"
    {:ok, _pid} = Krait.Memory.Hot.start_link(name: name)
    Application.put_env(:krait, :memory_hot_server, name)

    on_exit(fn ->
      Application.delete_env(:krait, :memory_hot_server)
    end)

    %{hot: name}
  end

  describe "name/0" do
    test "returns memory" do
      assert MemorySkill.name() == "memory"
    end
  end

  describe "description/0" do
    test "returns description" do
      assert MemorySkill.description() =~ "memories"
    end
  end

  describe "execute store action" do
    test "stores a value and returns key" do
      assert {:ok, %{stored: "test_key"}} =
               MemorySkill.execute(%{
                 "action" => "store",
                 "key" => "test_key",
                 "value" => "hello"
               })
    end

    test "actually persists in Hot memory", %{hot: hot} do
      MemorySkill.execute(%{"action" => "store", "key" => "persist_key", "value" => "world"})

      assert {:ok, "world"} = Krait.Memory.Hot.get(hot, "persist_key")
    end

    test "rejects credential values" do
      assert {:error, _} =
               MemorySkill.execute(%{
                 "action" => "store",
                 "key" => "secret",
                 "value" => "sk-ant-api03-abc123"
               })
    end

    test "rejects system namespace keys" do
      assert {:error, _} =
               MemorySkill.execute(%{
                 "action" => "store",
                 "key" => "_system:internal",
                 "value" => "hack"
               })
    end
  end

  describe "execute recall action" do
    test "recalls a stored value" do
      MemorySkill.execute(%{"action" => "store", "key" => "greeting", "value" => "hi"})

      assert {:ok, %{key: "greeting", value: "hi"}} =
               MemorySkill.execute(%{"action" => "recall", "key" => "greeting"})
    end

    test "returns nil for missing key" do
      assert {:ok, %{key: "nonexistent", value: nil}} =
               MemorySkill.execute(%{"action" => "recall", "key" => "nonexistent"})
    end
  end

  describe "execute list action" do
    test "lists all keys" do
      MemorySkill.execute(%{"action" => "store", "key" => "a", "value" => "1"})
      MemorySkill.execute(%{"action" => "store", "key" => "b", "value" => "2"})

      assert {:ok, %{memories: keys}} = MemorySkill.execute(%{"action" => "list"})
      assert "a" in keys
      assert "b" in keys
    end

    test "lists keys with prefix" do
      MemorySkill.execute(%{"action" => "store", "key" => "user:name", "value" => "alice"})
      MemorySkill.execute(%{"action" => "store", "key" => "user:age", "value" => "30"})
      MemorySkill.execute(%{"action" => "store", "key" => "system:foo", "value" => "bar"})

      assert {:ok, %{memories: keys}} =
               MemorySkill.execute(%{"action" => "list", "prefix" => "user:"})

      assert "user:name" in keys
      assert "user:age" in keys
      refute "system:foo" in keys
    end
  end

  describe "execute with atom keys" do
    test "converts atom keys to string keys" do
      assert {:ok, %{stored: "atom_key"}} =
               MemorySkill.execute(%{action: :store, key: "atom_key", value: "val"})
    end
  end

  describe "execute with missing action" do
    test "returns error" do
      assert {:error, _} = MemorySkill.execute(%{"key" => "test"})
    end
  end
end
