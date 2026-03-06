defmodule KraitWeb.Plugs.RequireAdminAuthTest do
  use KraitWeb.ConnCase, async: false

  alias KraitWeb.AdminSessionController

  setup do
    prev_token = Application.get_env(:krait, :api_auth_token)
    prev_admin = Application.get_env(:krait, :admin_auth_token)
    prev_disable = Application.get_env(:krait, :disable_auth)
    Application.put_env(:krait, :api_auth_token, "test-admin-token")
    # v23 H-4: Tests must use admin_auth_token directly (no fallback)
    Application.put_env(:krait, :admin_auth_token, "test-admin-token")
    Application.put_env(:krait, :disable_auth, false)

    on_exit(fn ->
      if prev_token,
        do: Application.put_env(:krait, :api_auth_token, prev_token),
        else: Application.delete_env(:krait, :api_auth_token)

      if prev_admin,
        do: Application.put_env(:krait, :admin_auth_token, prev_admin),
        else: Application.delete_env(:krait, :admin_auth_token)

      if prev_disable != nil,
        do: Application.put_env(:krait, :disable_auth, prev_disable),
        else: Application.delete_env(:krait, :disable_auth)
    end)
  end

  describe "call/2" do
    test "redirects to /admin/login when no session token", %{conn: conn} do
      conn =
        conn
        |> init_test_session(%{})
        |> KraitWeb.Plugs.RequireAdminAuth.call([])

      assert conn.halted
      assert redirected_to(conn) == "/admin/login"
    end

    test "redirects when session token hash is invalid", %{conn: conn} do
      conn =
        conn
        |> init_test_session(%{krait_admin_token: "bogus_hash_value"})
        |> KraitWeb.Plugs.RequireAdminAuth.call([])

      assert conn.halted
      assert redirected_to(conn) == "/admin/login"
    end

    test "passes through when session token hash is valid", %{conn: conn} do
      valid_hash = AdminSessionController.sign_session_token("test-admin-token")

      conn =
        conn
        |> init_test_session(%{krait_admin_token: valid_hash})
        |> KraitWeb.Plugs.RequireAdminAuth.call([])

      refute conn.halted
    end

    test "bypasses in test env when disable_auth is true", %{conn: conn} do
      Application.put_env(:krait, :disable_auth, true)

      conn =
        conn
        |> init_test_session(%{})
        |> KraitWeb.Plugs.RequireAdminAuth.call([])

      refute conn.halted
    end

    test "authenticates against admin_auth_token when set", %{conn: conn} do
      Application.put_env(:krait, :admin_auth_token, "separate-admin-token")
      on_exit(fn -> Application.delete_env(:krait, :admin_auth_token) end)

      valid_hash = AdminSessionController.sign_session_token("separate-admin-token")

      conn =
        conn
        |> init_test_session(%{krait_admin_token: valid_hash})
        |> KraitWeb.Plugs.RequireAdminAuth.call([])

      refute conn.halted
    end

    test "v23 H-4: redirects when admin_auth_token is nil (no fallback)", %{conn: conn} do
      Application.delete_env(:krait, :admin_auth_token)

      # Sign with the API token — but since there's no admin token, verify_admin_session returns :error
      valid_hash = AdminSessionController.sign_session_token("test-admin-token")

      conn =
        conn
        |> init_test_session(%{krait_admin_token: valid_hash})
        |> KraitWeb.Plugs.RequireAdminAuth.call([])

      assert conn.halted
      assert redirected_to(conn) == "/admin/login"
    end
  end
end
