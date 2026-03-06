defmodule Krait.Brain.ReflectorTest do
  use ExUnit.Case, async: true

  alias Krait.Brain.Reflector

  setup do
    name = :"reflector_test_#{System.unique_integer([:positive])}"
    {:ok, _pid} = Krait.Memory.Hot.start_link(name: name)
    %{hot: name}
  end

  describe "reflect/2" do
    test "stores a success reflection", %{hot: hot} do
      context = %{action: "web_fetch", result: %{body: "data"}, success: true}
      assert :ok = Reflector.reflect(context, memory: hot)

      keys = Krait.Memory.Hot.list_keys(hot, "reflection:web_fetch:")
      assert length(keys) == 1
    end

    test "stores a failure reflection", %{hot: hot} do
      context = %{action: "evolve", result: "timeout", success: false}
      assert :ok = Reflector.reflect(context, memory: hot)

      keys = Krait.Memory.Hot.list_keys(hot, "reflection:evolve:")
      assert length(keys) == 1

      key = hd(keys)
      {:ok, insight} = Krait.Memory.Hot.get(hot, key)
      assert insight.outcome == :failure
    end

    test "stores with default action name", %{hot: hot} do
      context = %{result: "ok"}
      assert :ok = Reflector.reflect(context, memory: hot)

      keys = Krait.Memory.Hot.list_keys(hot, "reflection:unknown:")
      assert length(keys) == 1
    end
  end

  describe "recent_reflections/1" do
    test "lists reflection keys", %{hot: hot} do
      Reflector.reflect(%{action: "a", result: "1", success: true}, memory: hot)
      Reflector.reflect(%{action: "b", result: "2", success: true}, memory: hot)

      keys = Reflector.recent_reflections(memory: hot)
      assert length(keys) == 2
    end

    test "filters by prefix", %{hot: hot} do
      Reflector.reflect(%{action: "web_fetch", result: "1", success: true}, memory: hot)
      Reflector.reflect(%{action: "evolve", result: "2", success: true}, memory: hot)

      keys = Reflector.recent_reflections(memory: hot, prefix: "reflection:web_fetch:")
      assert length(keys) == 1
    end
  end
end
