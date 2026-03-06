defmodule Krait.Skills.CapabilityInjectorTest do
  use ExUnit.Case, async: true

  alias Krait.Skills.CapabilityInjector

  describe "build_capabilities/1" do
    test "filesystem maps to FilesystemCap" do
      caps = CapabilityInjector.build_capabilities([:filesystem])
      assert caps.filesystem == Krait.Skills.Capabilities.FilesystemCap
    end

    test "network maps to NetworkCap" do
      caps = CapabilityInjector.build_capabilities([:network])
      assert caps.network == Krait.Skills.Capabilities.NetworkCap
    end

    test "memory maps to MemoryCap" do
      caps = CapabilityInjector.build_capabilities([:memory])
      assert caps.memory == Krait.Skills.Capabilities.MemoryCap
    end

    test "only declared capabilities are included" do
      caps = CapabilityInjector.build_capabilities([:network])
      refute Map.has_key?(caps, :filesystem)
      refute Map.has_key?(caps, :memory)
    end

    test "all three capabilities can be requested" do
      caps = CapabilityInjector.build_capabilities([:filesystem, :network, :memory])
      assert map_size(caps) == 3
    end
  end
end
