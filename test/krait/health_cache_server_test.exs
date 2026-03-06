defmodule Krait.HealthCacheServerTest do
  use ExUnit.Case, async: false

  setup do
    # Ensure the server is running
    case GenServer.whereis(Krait.HealthCacheServer) do
      nil -> Krait.HealthCacheServer.start_link([])
      pid -> if Process.alive?(pid), do: :ok, else: Krait.HealthCacheServer.start_link([])
    end

    :ok
  end

  describe "v22 SEC-08: HealthCacheServer" do
    test "write + read round-trip" do
      Krait.HealthCacheServer.write(:test_key, {true, 12_345})
      assert {:ok, {true, 12_345}} = Krait.HealthCacheServer.read(:test_key)
    end

    test "read returns :miss for unknown key" do
      assert :miss = Krait.HealthCacheServer.read(:nonexistent_key_abc)
    end

    test "delete removes the entry" do
      Krait.HealthCacheServer.write(:delete_me, "value")
      assert {:ok, "value"} = Krait.HealthCacheServer.read(:delete_me)

      Krait.HealthCacheServer.delete(:delete_me)
      assert :miss = Krait.HealthCacheServer.read(:delete_me)
    end

    test "table is :protected — direct ETS read succeeds from non-owner" do
      Krait.HealthCacheServer.write(:readable, "from_any_process")

      # Direct ETS read should work (protected allows reads)
      result = :ets.lookup(:krait_health_cache, :readable)
      assert [{:readable, "from_any_process"}] = result
    end

    test "table is :protected — direct ETS write from non-owner raises" do
      assert_raise ArgumentError, fn ->
        :ets.insert(:krait_health_cache, {:unauthorized_write, "bad"})
      end
    end
  end
end
