defmodule Krait.Skills.RegistryTest do
  use ExUnit.Case, async: true

  setup do
    # MemorySkill now requires a Hot memory server
    name = :"registry_test_hot_#{System.unique_integer([:positive])}"
    {:ok, _pid} = Krait.Memory.Hot.start_link(name: name)
    Application.put_env(:krait, :memory_hot_server, name)

    on_exit(fn ->
      Application.delete_env(:krait, :memory_hot_server)
    end)

    :ok
  end

  describe "list_manifests/1" do
    test "returns registered skill manifests" do
      {:ok, pid} =
        Krait.Skills.Registry.start_link(
          skills: [Krait.Skills.Core.WebFetch, Krait.Skills.Core.Filesystem]
        )

      manifests = Krait.Skills.Registry.list_manifests(pid)
      names = Enum.map(manifests, & &1.name)
      assert "web_fetch" in names
      assert "filesystem" in names
    end
  end

  describe "get_skill/2" do
    test "returns full skill module for known skill" do
      {:ok, pid} = Krait.Skills.Registry.start_link(skills: [Krait.Skills.Core.WebFetch])
      assert {:ok, Krait.Skills.Core.WebFetch} = Krait.Skills.Registry.get_skill(pid, "web_fetch")
    end

    test "returns error for unknown skill" do
      {:ok, pid} = Krait.Skills.Registry.start_link(skills: [])
      assert {:error, :not_found} = Krait.Skills.Registry.get_skill(pid, "nonexistent")
    end
  end

  describe "execute_skill/3" do
    test "executes skill and returns result" do
      {:ok, pid} = Krait.Skills.Registry.start_link(skills: [Krait.Skills.Core.MemorySkill])
      assert {:ok, _} = Krait.Skills.Registry.execute_skill(pid, "memory", %{action: "list"})
    end

    test "returns :not_found for non-existent skill" do
      {:ok, pid} = Krait.Skills.Registry.start_link(skills: [])

      assert {:error, :not_found} =
               Krait.Skills.Registry.execute_skill(pid, "nonexistent", %{})
    end

    test "propagates skill execution errors" do
      {:ok, pid} = Krait.Skills.Registry.start_link(skills: [Krait.Skills.Core.MemorySkill])

      # MemorySkill.execute with missing action returns error
      assert {:error, _reason} =
               Krait.Skills.Registry.execute_skill(pid, "memory", %{})
    end

    test "propagates guard rejection from memory skill" do
      {:ok, pid} = Krait.Skills.Registry.start_link(skills: [Krait.Skills.Core.MemorySkill])

      # Try to store a value containing an API key — should be rejected by Guard
      assert {:error, reason} =
               Krait.Skills.Registry.execute_skill(pid, "memory", %{
                 "action" => "store",
                 "key" => "secret",
                 "value" => "sk-ant-api03-badkey123"
               })

      assert reason =~ "API key"
    end
  end

  describe "list_manifests/1 edge cases" do
    test "returns empty list when no skills registered" do
      {:ok, pid} = Krait.Skills.Registry.start_link(skills: [])

      assert [] = Krait.Skills.Registry.list_manifests(pid)
    end

    test "manifests contain name and description fields" do
      {:ok, pid} = Krait.Skills.Registry.start_link(skills: [Krait.Skills.Core.WebFetch])

      [manifest] = Krait.Skills.Registry.list_manifests(pid)
      assert Map.has_key?(manifest, :name)
      assert Map.has_key?(manifest, :description)
      assert manifest.name == "web_fetch"
      assert is_binary(manifest.description)
    end
  end

  describe "duplicate skill handling" do
    test "last skill with same name wins in registry" do
      # When two skills have the same name, Map.new takes the last one
      # Since we use Map.new(skills, fn mod -> {mod.name(), mod} end),
      # the iteration order determines which wins.
      # With a single module registered twice, it just overwrites itself.
      {:ok, pid} =
        Krait.Skills.Registry.start_link(
          skills: [Krait.Skills.Core.MemorySkill, Krait.Skills.Core.MemorySkill]
        )

      manifests = Krait.Skills.Registry.list_manifests(pid)
      # Duplicate collapsed — only one entry for "memory"
      memory_skills = Enum.filter(manifests, &(&1.name == "memory"))
      assert length(memory_skills) == 1
    end
  end
end
