defmodule Krait.Skills.CapableSkillTest do
  use ExUnit.Case, async: true

  alias Krait.Skills.CapabilityInjector
  alias Krait.Skills.CapableSkill

  # A test module implementing CapableSkill
  defmodule TestNetworkSkill do
    @behaviour CapableSkill

    @impl true
    def name, do: "test_network"

    @impl true
    def description, do: "A test skill that uses network"

    @impl true
    def required_capabilities, do: [:network]

    @impl true
    def execute(_params, capabilities) do
      {:ok, %{caps: Map.keys(capabilities)}}
    end
  end

  defmodule TestMultiCapSkill do
    @behaviour CapableSkill

    @impl true
    def name, do: "test_multi"

    @impl true
    def description, do: "A test skill with multiple capabilities"

    @impl true
    def required_capabilities, do: [:filesystem, :network, :memory]

    @impl true
    def execute(_params, capabilities) do
      {:ok, %{caps: Map.keys(capabilities) |> Enum.sort()}}
    end
  end

  defmodule TestNoCapSkill do
    @behaviour CapableSkill

    @impl true
    def name, do: "test_nocap"

    @impl true
    def description, do: "A test skill with no capabilities"

    @impl true
    def required_capabilities, do: []

    @impl true
    def execute(_params, capabilities) do
      {:ok, %{caps: Map.keys(capabilities)}}
    end
  end

  describe "CapableSkill behaviour" do
    test "module implementing CapableSkill has required callbacks" do
      assert function_exported?(TestNetworkSkill, :name, 0)
      assert function_exported?(TestNetworkSkill, :description, 0)
      assert function_exported?(TestNetworkSkill, :required_capabilities, 0)
      assert function_exported?(TestNetworkSkill, :execute, 2)
    end

    test "required_capabilities returns capability list" do
      assert TestNetworkSkill.required_capabilities() == [:network]
      assert TestMultiCapSkill.required_capabilities() == [:filesystem, :network, :memory]
      assert TestNoCapSkill.required_capabilities() == []
    end
  end

  describe "CapabilityInjector.build_capabilities/1" do
    test "builds map from capability names" do
      caps = CapabilityInjector.build_capabilities([:network])
      assert Map.has_key?(caps, :network)
      assert caps.network == Krait.Skills.Capabilities.NetworkCap
    end

    test "builds multi-capability map" do
      caps = CapabilityInjector.build_capabilities([:filesystem, :network, :memory])
      assert Map.has_key?(caps, :filesystem)
      assert Map.has_key?(caps, :network)
      assert Map.has_key?(caps, :memory)
      assert caps.filesystem == Krait.Skills.Capabilities.FilesystemCap
      assert caps.network == Krait.Skills.Capabilities.NetworkCap
      assert caps.memory == Krait.Skills.Capabilities.MemoryCap
    end

    test "empty requirements returns empty map" do
      caps = CapabilityInjector.build_capabilities([])
      assert caps == %{}
    end

    test "raises on unknown capability" do
      assert_raise ArgumentError, ~r/Unknown capability/, fn ->
        CapabilityInjector.build_capabilities([:unknown_cap])
      end
    end
  end

  describe "CapabilityInjector.execute_with_capabilities/2" do
    test "executes skill with injected capabilities" do
      assert {:ok, %{caps: [:network]}} =
               CapabilityInjector.execute_with_capabilities(TestNetworkSkill, %{})
    end

    test "executes skill with multiple capabilities" do
      assert {:ok, %{caps: caps}} =
               CapabilityInjector.execute_with_capabilities(TestMultiCapSkill, %{})

      assert Enum.sort(caps) == [:filesystem, :memory, :network]
    end

    test "executes skill with no capabilities" do
      assert {:ok, %{caps: []}} =
               CapabilityInjector.execute_with_capabilities(TestNoCapSkill, %{})
    end
  end
end
