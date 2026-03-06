defmodule KraitWeb.EvolutionLiveTest do
  use ExUnit.Case, async: false

  describe "mount/3 token comparison" do
    setup do
      original_env = Application.get_env(:krait, :env)
      original_token = Application.get_env(:krait, :api_auth_token)
      original_admin = Application.get_env(:krait, :admin_auth_token)

      on_exit(fn ->
        if original_env,
          do: Application.put_env(:krait, :env, original_env),
          else: Application.delete_env(:krait, :env)

        if original_token,
          do: Application.put_env(:krait, :api_auth_token, original_token),
          else: Application.delete_env(:krait, :api_auth_token)

        if original_admin,
          do: Application.put_env(:krait, :admin_auth_token, original_admin),
          else: Application.delete_env(:krait, :admin_auth_token)
      end)

      :ok
    end

    test "uses KraitWeb.Auth.verify_admin_session for session verification" do
      source = File.read!("lib/krait_web/live/evolution_live.ex")

      # v22 SEC-12: Now uses centralized verify_admin_session instead of inline comparison
      assert source =~ "KraitWeb.Auth.verify_admin_session",
             "mount must use KraitWeb.Auth.verify_admin_session"

      refute source =~ "token != expected",
             "token comparison must not use !="
    end

    test "uses shared KraitWeb.Auth module for session verification" do
      source = File.read!("lib/krait_web/live/evolution_live.ex")
      assert source =~ "KraitWeb.Auth.verify_admin_session"
      refute source =~ ~r/Application\.get_env\(:krait, :api_auth_token\)/
    end

    test "redirects to login on failed verification" do
      source = File.read!("lib/krait_web/live/evolution_live.ex")
      assert source =~ ~S[redirect(socket, to: "/admin/login")]
    end
  end

  describe "evolution trigger form" do
    test "render includes trigger form elements" do
      source = File.read!("lib/krait_web/live/evolution_live.ex")
      assert source =~ ~S[phx-submit="trigger_evolution"]
      assert source =~ ~S[name="skill_name"]
      assert source =~ ~S[name="description"]
      assert source =~ "Evolve"
    end

    test "render includes kill switch banner" do
      source = File.read!("lib/krait_web/live/evolution_live.ex")
      assert source =~ "kill_switch_active"
      assert source =~ "Kill switch is active"
    end

    test "handle_event uses Task.Supervisor for evolution" do
      source = File.read!("lib/krait_web/live/evolution_live.ex")
      assert source =~ "Task.Supervisor.start_child(Krait.TaskSupervisor"
    end

    test "handle_event uses EvolveCooldownServer for slot management" do
      source = File.read!("lib/krait_web/live/evolution_live.ex")
      assert source =~ "EvolveCooldownServer.try_acquire_slot"
      assert source =~ "EvolveCooldownServer.release_slot"
    end

    test "slot release is in after block (no leak on crash)" do
      source = File.read!("lib/krait_web/live/evolution_live.ex")
      assert source =~ "after\n            Krait.EvolveCooldownServer.release_slot"
    end

    test "subscribes to kill_switch PubSub topic" do
      source = File.read!("lib/krait_web/live/evolution_live.ex")
      assert source =~ ~S["kill_switch"]
    end
  end

  describe "validate_trigger_params/2 behavioral tests" do
    test "rejects empty skill name" do
      assert {:error, "Skill name is required"} =
               KraitWeb.EvolutionLive.validate_trigger_params("", "some description")
    end

    test "rejects invalid skill name characters" do
      assert {:error, msg} =
               KraitWeb.EvolutionLive.validate_trigger_params("Invalid-Name!", "desc")

      assert msg =~ "Invalid skill name"
    end

    test "rejects skill name starting with number" do
      assert {:error, msg} =
               KraitWeb.EvolutionLive.validate_trigger_params("1bad_name", "desc")

      assert msg =~ "Invalid skill name"
    end

    test "rejects empty description" do
      assert {:error, "Description is required"} =
               KraitWeb.EvolutionLive.validate_trigger_params("valid_name", "")
    end

    test "rejects oversized description" do
      long_desc = String.duplicate("a", 2001)

      assert {:error, msg} =
               KraitWeb.EvolutionLive.validate_trigger_params("valid_name", long_desc)

      assert msg =~ "too long"
    end

    test "rejects null bytes in description" do
      assert {:error, msg} =
               KraitWeb.EvolutionLive.validate_trigger_params("valid_name", "hello\0world")

      assert msg =~ "invalid characters"
    end

    test "accepts valid parameters" do
      assert :ok = KraitWeb.EvolutionLive.validate_trigger_params("greeting", "Say hello")
    end

    test "accepts underscored skill names" do
      assert :ok =
               KraitWeb.EvolutionLive.validate_trigger_params(
                 "my_cool_skill",
                 "Does something cool"
               )
    end

    test "rejects description at exactly max + 1 length" do
      desc = String.duplicate("x", 2001)

      assert {:error, _} =
               KraitWeb.EvolutionLive.validate_trigger_params("valid_name", desc)
    end

    test "accepts description at exactly max length" do
      desc = String.duplicate("x", 2000)
      assert :ok = KraitWeb.EvolutionLive.validate_trigger_params("valid_name", desc)
    end
  end
end
