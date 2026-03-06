defmodule Krait.ApplicationTest do
  use ExUnit.Case, async: false

  describe "validate_session_salts!/0" do
    test "raises in prod with default salts" do
      _original_env = Application.get_env(:krait, :env)
      original_config = Application.get_env(:krait, KraitWeb.Endpoint)

      Application.put_env(:krait, :env, :prod)

      Application.put_env(
        :krait,
        KraitWeb.Endpoint,
        Keyword.put(
          original_config || [],
          :session_options,
          signing_salt: "dev_default_session_salt",
          encryption_salt: "dev_default_encryption_salt"
        )
      )

      assert_raise RuntimeError, ~r/dev_default/, fn ->
        Krait.Application.validate_session_salts!()
      end
    after
      Application.put_env(:krait, :env, :test)
      Application.delete_env(:krait, KraitWeb.Endpoint)
    end

    test "passes in prod with custom salts" do
      _original_env = Application.get_env(:krait, :env)
      original_config = Application.get_env(:krait, KraitWeb.Endpoint)

      Application.put_env(:krait, :env, :prod)

      Application.put_env(
        :krait,
        KraitWeb.Endpoint,
        Keyword.put(
          original_config || [],
          :session_options,
          signing_salt: "prod_random_salt_abc123",
          encryption_salt: "prod_random_encryption_xyz789"
        )
      )

      # Should not raise
      Krait.Application.validate_session_salts!()
    after
      Application.put_env(:krait, :env, :test)
      Application.delete_env(:krait, KraitWeb.Endpoint)
    end

    test "passes in dev/test with default salts" do
      # In test env, validation should not raise
      # (validate_session_salts! is only called in prod path)
      Krait.Application.validate_session_salts!()
    end
  end

  describe "validate_live_view_salt!/0" do
    test "raises when live_view signing salt contains dev_default" do
      original_config = Application.get_env(:krait, KraitWeb.Endpoint)

      Application.put_env(
        :krait,
        KraitWeb.Endpoint,
        Keyword.put(
          original_config || [],
          :live_view,
          signing_salt: "dev_default_live_salt"
        )
      )

      assert_raise RuntimeError, ~r/dev_default/, fn ->
        Krait.Application.validate_live_view_salt!()
      end
    after
      Application.delete_env(:krait, KraitWeb.Endpoint)
    end

    test "passes with non-default salt" do
      original_config = Application.get_env(:krait, KraitWeb.Endpoint)

      Application.put_env(
        :krait,
        KraitWeb.Endpoint,
        Keyword.put(
          original_config || [],
          :live_view,
          signing_salt: "prod_random_live_salt_xyz789"
        )
      )

      # Should not raise
      Krait.Application.validate_live_view_salt!()
    after
      Application.delete_env(:krait, KraitWeb.Endpoint)
    end

    test "passes when live_view config absent" do
      original_config = Application.get_env(:krait, KraitWeb.Endpoint)

      Application.put_env(
        :krait,
        KraitWeb.Endpoint,
        Keyword.delete(original_config || [], :live_view)
      )

      # Should not raise
      Krait.Application.validate_live_view_salt!()
    after
      Application.delete_env(:krait, KraitWeb.Endpoint)
    end
  end

  describe "validate_admin_session_salt!/0" do
    test "passes when salt is a non-nil value" do
      # v20 M-1: No default check needed — only nil check remains
      prev = Application.get_env(:krait, :admin_session_salt)
      Application.put_env(:krait, :admin_session_salt, "any_salt_value")

      on_exit(fn ->
        if prev,
          do: Application.put_env(:krait, :admin_session_salt, prev),
          else: Application.delete_env(:krait, :admin_session_salt)
      end)

      assert :ok = Krait.Application.validate_admin_session_salt!()
    end

    test "raises when salt is nil" do
      prev = Application.get_env(:krait, :admin_session_salt)
      Application.delete_env(:krait, :admin_session_salt)

      on_exit(fn ->
        if prev,
          do: Application.put_env(:krait, :admin_session_salt, prev),
          else: Application.delete_env(:krait, :admin_session_salt)
      end)

      assert_raise RuntimeError, ~r/ADMIN_SESSION_SALT/i, fn ->
        Krait.Application.validate_admin_session_salt!()
      end
    end

    test "returns :ok for non-default value" do
      prev = Application.get_env(:krait, :admin_session_salt)
      Application.put_env(:krait, :admin_session_salt, "custom_production_salt_abc123")

      on_exit(fn ->
        if prev,
          do: Application.put_env(:krait, :admin_session_salt, prev),
          else: Application.delete_env(:krait, :admin_session_salt)
      end)

      assert :ok = Krait.Application.validate_admin_session_salt!()
    end
  end

  describe "validate_secret_key_base!/0" do
    test "raises when secret_key_base matches dev default" do
      prev = Application.get_env(:krait, KraitWeb.Endpoint)

      Application.put_env(
        :krait,
        KraitWeb.Endpoint,
        Keyword.put(
          prev || [],
          :secret_key_base,
          "MoCO2EgSPBi+j+Kqq1PBQof5lhiJIpr5i9YB+mw/9dqJmatGIrQRA/g/mtujgDEF"
        )
      )

      on_exit(fn ->
        if prev,
          do: Application.put_env(:krait, KraitWeb.Endpoint, prev),
          else: Application.delete_env(:krait, KraitWeb.Endpoint)
      end)

      assert_raise RuntimeError, ~r/dev\/test secret_key_base/, fn ->
        Krait.Application.validate_secret_key_base!()
      end
    end

    test "passes when secret_key_base is unique" do
      prev = Application.get_env(:krait, KraitWeb.Endpoint)

      Application.put_env(
        :krait,
        KraitWeb.Endpoint,
        Keyword.put(
          prev || [],
          :secret_key_base,
          "unique_production_secret_that_is_not_dev_default_abc123xyz"
        )
      )

      on_exit(fn ->
        if prev,
          do: Application.put_env(:krait, KraitWeb.Endpoint, prev),
          else: Application.delete_env(:krait, KraitWeb.Endpoint)
      end)

      assert :ok = Krait.Application.validate_secret_key_base!()
    end
  end

  describe "validate_admin_token!/0" do
    test "raises when admin_auth_token is nil in prod" do
      prev = Application.get_env(:krait, :admin_auth_token)
      Application.delete_env(:krait, :admin_auth_token)

      on_exit(fn ->
        if prev,
          do: Application.put_env(:krait, :admin_auth_token, prev),
          else: Application.delete_env(:krait, :admin_auth_token)
      end)

      assert_raise RuntimeError, ~r/KRAIT_ADMIN_TOKEN/, fn ->
        Krait.Application.validate_admin_token!()
      end
    end

    test "passes when admin_auth_token is set" do
      prev = Application.get_env(:krait, :admin_auth_token)
      Application.put_env(:krait, :admin_auth_token, "a-dedicated-admin-token")

      on_exit(fn ->
        if prev,
          do: Application.put_env(:krait, :admin_auth_token, prev),
          else: Application.delete_env(:krait, :admin_auth_token)
      end)

      assert :ok = Krait.Application.validate_admin_token!()
    end
  end

  describe "validate_token_complexity!/0" do
    setup do
      prev_api = Application.get_env(:krait, :api_auth_token)
      prev_admin = Application.get_env(:krait, :admin_auth_token)

      on_exit(fn ->
        if prev_api,
          do: Application.put_env(:krait, :api_auth_token, prev_api),
          else: Application.delete_env(:krait, :api_auth_token)

        if prev_admin,
          do: Application.put_env(:krait, :admin_auth_token, prev_admin),
          else: Application.delete_env(:krait, :admin_auth_token)
      end)

      :ok
    end

    test "raises when api_auth_token is shorter than 32 chars" do
      Application.put_env(:krait, :api_auth_token, "short")
      Application.put_env(:krait, :admin_auth_token, String.duplicate("a", 32))

      assert_raise RuntimeError, ~r/KRAIT_API_TOKEN.*32 characters/, fn ->
        Krait.Application.validate_token_complexity!()
      end
    end

    test "raises when admin_auth_token is shorter than 32 chars" do
      Application.put_env(:krait, :api_auth_token, String.duplicate("a", 32))
      Application.put_env(:krait, :admin_auth_token, "short")

      assert_raise RuntimeError, ~r/KRAIT_ADMIN_TOKEN.*32 characters/, fn ->
        Krait.Application.validate_token_complexity!()
      end
    end

    test "passes when both tokens are >= 32 chars" do
      Application.put_env(:krait, :api_auth_token, String.duplicate("a", 32))
      Application.put_env(:krait, :admin_auth_token, String.duplicate("b", 32))

      assert :ok = Krait.Application.validate_token_complexity!()
    end

    test "passes when tokens are nil (unconfigured)" do
      Application.delete_env(:krait, :api_auth_token)
      Application.delete_env(:krait, :admin_auth_token)

      assert :ok = Krait.Application.validate_token_complexity!()
    end
  end

  describe "validate_sandbox_config!/0" do
    test "raises when allow_local_execution is true" do
      prev = Application.get_env(:krait, :allow_local_execution)
      Application.put_env(:krait, :allow_local_execution, true)

      on_exit(fn ->
        if prev != nil,
          do: Application.put_env(:krait, :allow_local_execution, prev),
          else: Application.delete_env(:krait, :allow_local_execution)
      end)

      assert_raise RuntimeError, ~r/allow_local_execution/, fn ->
        Krait.Application.validate_sandbox_config!()
      end
    end

    test "passes when allow_local_execution is false" do
      prev = Application.get_env(:krait, :allow_local_execution)
      Application.put_env(:krait, :allow_local_execution, false)

      on_exit(fn ->
        if prev != nil,
          do: Application.put_env(:krait, :allow_local_execution, prev),
          else: Application.delete_env(:krait, :allow_local_execution)
      end)

      assert :ok = Krait.Application.validate_sandbox_config!()
    end

    test "passes when allow_local_execution is nil (default)" do
      prev = Application.get_env(:krait, :allow_local_execution)
      Application.delete_env(:krait, :allow_local_execution)

      on_exit(fn ->
        if prev != nil,
          do: Application.put_env(:krait, :allow_local_execution, prev),
          else: Application.delete_env(:krait, :allow_local_execution)
      end)

      assert :ok = Krait.Application.validate_sandbox_config!()
    end
  end

  describe "validate_filesystem_sandbox!/0" do
    test "raises in prod when not configured" do
      _original_root = Application.get_env(:krait, :filesystem_sandbox_root)
      Application.delete_env(:krait, :filesystem_sandbox_root)

      assert_raise RuntimeError, ~r/filesystem_sandbox_root/, fn ->
        Krait.Application.validate_filesystem_sandbox!()
      end
    after
      Application.delete_env(:krait, :filesystem_sandbox_root)
    end

    test "passes in prod when configured" do
      Application.put_env(:krait, :filesystem_sandbox_root, "/opt/krait/data")

      # Should not raise
      Krait.Application.validate_filesystem_sandbox!()
    after
      Application.delete_env(:krait, :filesystem_sandbox_root)
    end
  end

  describe "v22 SEC-03: dev sandbox warnings" do
    setup do
      prev_env = Application.get_env(:krait, :env)
      prev_local = Application.get_env(:krait, :allow_local_execution)
      prev_strict = Application.get_env(:krait, :strict_sandbox_mode)
      prev_deep = Application.get_env(:krait, :require_deep_scan)

      Application.put_env(:krait, :require_deep_scan, true)

      on_exit(fn ->
        if prev_env,
          do: Application.put_env(:krait, :env, prev_env),
          else: Application.delete_env(:krait, :env)

        if prev_local,
          do: Application.put_env(:krait, :allow_local_execution, prev_local),
          else: Application.delete_env(:krait, :allow_local_execution)

        if prev_strict,
          do: Application.put_env(:krait, :strict_sandbox_mode, prev_strict),
          else: Application.delete_env(:krait, :strict_sandbox_mode)

        if prev_deep,
          do: Application.put_env(:krait, :require_deep_scan, prev_deep),
          else: Application.delete_env(:krait, :require_deep_scan)
      end)

      :ok
    end

    test "logs warning when allow_local_execution=true in dev" do
      import ExUnit.CaptureLog

      Application.put_env(:krait, :env, :dev)
      Application.put_env(:krait, :allow_local_execution, true)

      log =
        capture_log(fn ->
          Krait.Application.log_security_warnings()
        end)

      assert log =~ "allow_local_execution=true"
      assert log =~ "not in Docker sandbox"
    end

    test "no warning when allow_local_execution=false in dev" do
      import ExUnit.CaptureLog

      Application.put_env(:krait, :env, :dev)
      Application.put_env(:krait, :allow_local_execution, false)

      log =
        capture_log(fn ->
          Krait.Application.log_security_warnings()
        end)

      refute log =~ "allow_local_execution=true"
    end
  end
end
