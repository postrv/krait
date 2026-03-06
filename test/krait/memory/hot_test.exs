defmodule Krait.Memory.HotTest do
  use ExUnit.Case, async: true

  setup do
    table_name = :"hot_test_#{System.unique_integer([:positive])}"
    {:ok, pid} = Krait.Memory.Hot.start_link(name: table_name)
    %{pid: pid, table: table_name}
  end

  describe "put/get" do
    test "stores and retrieves a value", %{pid: pid} do
      :ok = Krait.Memory.Hot.put(pid, "session:123", %{user: "alice"})
      assert {:ok, %{user: "alice"}} = Krait.Memory.Hot.get(pid, "session:123")
    end

    test "returns :not_found for missing keys", %{pid: pid} do
      assert :not_found = Krait.Memory.Hot.get(pid, "missing")
    end

    test "overwrites existing values", %{pid: pid} do
      :ok = Krait.Memory.Hot.put(pid, "key", "v1")
      :ok = Krait.Memory.Hot.put(pid, "key", "v2")
      assert {:ok, "v2"} = Krait.Memory.Hot.get(pid, "key")
    end
  end

  describe "delete" do
    test "removes a key", %{pid: pid} do
      :ok = Krait.Memory.Hot.put(pid, "key", "val")
      :ok = Krait.Memory.Hot.delete(pid, "key")
      assert :not_found = Krait.Memory.Hot.get(pid, "key")
    end
  end

  describe "list_keys" do
    test "returns all keys matching prefix", %{pid: pid} do
      :ok = Krait.Memory.Hot.put(pid, "session:1", "a")
      :ok = Krait.Memory.Hot.put(pid, "session:2", "b")
      :ok = Krait.Memory.Hot.put(pid, "other:1", "c")
      keys = Krait.Memory.Hot.list_keys(pid, "session:")
      assert Enum.sort(keys) == ["session:1", "session:2"]
    end
  end

  describe "ETS access control" do
    test "direct :ets.insert from non-owner process raises ArgumentError", %{table: table} do
      assert_raise ArgumentError, fn ->
        :ets.insert(table, {"rogue_key", "rogue_value", nil})
      end
    end

    test "put/3 still works via GenServer (owner process)", %{pid: pid} do
      :ok = Krait.Memory.Hot.put(pid, "via_genserver", "value")
      assert {:ok, "value"} = Krait.Memory.Hot.get(pid, "via_genserver")
    end

    test "get/2 still works from any process (read concurrency)", %{pid: pid} do
      :ok = Krait.Memory.Hot.put(pid, "readable", "data")

      # Read from a spawned process
      parent = self()

      spawn(fn ->
        result = Krait.Memory.Hot.get(pid, "readable")
        send(parent, {:read_result, result})
      end)

      assert_receive {:read_result, {:ok, "data"}}, 1000
    end
  end

  describe "ttl" do
    test "expires entries after ttl", %{pid: pid} do
      :ok = Krait.Memory.Hot.put(pid, "ephemeral", "val", ttl: 50)
      assert {:ok, "val"} = Krait.Memory.Hot.get(pid, "ephemeral")
      Process.sleep(100)
      assert :not_found = Krait.Memory.Hot.get(pid, "ephemeral")
    end
  end
end
