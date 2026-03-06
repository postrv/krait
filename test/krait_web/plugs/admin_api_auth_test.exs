defmodule KraitWeb.Plugs.AdminApiAuthTest do
  use KraitWeb.ConnCase, async: false

  describe "AdminApiAuth plug" do
    test "accepts valid admin token", %{conn: conn} do
      Application.put_env(:krait, :admin_auth_token, "admin-token-abc")

      conn =
        conn
        |> put_req_header("authorization", "Bearer admin-token-abc")
        |> KraitWeb.Plugs.AdminApiAuth.call([])

      refute conn.halted
    after
      Application.delete_env(:krait, :admin_auth_token)
    end

    test "rejects wrong token with 401", %{conn: conn} do
      Application.put_env(:krait, :admin_auth_token, "admin-token-abc")

      conn =
        conn
        |> put_req_header("authorization", "Bearer wrong-token")
        |> KraitWeb.Plugs.AdminApiAuth.call([])

      assert conn.status == 401
      assert conn.halted
    after
      Application.delete_env(:krait, :admin_auth_token)
    end

    test "rejects regular API token (privilege separation)", %{conn: conn} do
      Application.put_env(:krait, :admin_auth_token, "admin-token-abc")
      Application.put_env(:krait, :api_auth_token, "api-token-xyz")

      conn =
        conn
        |> put_req_header("authorization", "Bearer api-token-xyz")
        |> KraitWeb.Plugs.AdminApiAuth.call([])

      assert conn.status == 401
      assert conn.halted
    after
      Application.delete_env(:krait, :admin_auth_token)
      Application.delete_env(:krait, :api_auth_token)
    end

    test "returns 503 when admin token not configured", %{conn: conn} do
      Application.delete_env(:krait, :admin_auth_token)
      _prev_disable = Application.get_env(:krait, :disable_auth)
      Application.put_env(:krait, :disable_auth, false)

      conn =
        conn
        |> put_req_header("authorization", "Bearer some-token")
        |> KraitWeb.Plugs.AdminApiAuth.call([])

      assert conn.status == 503
      assert conn.halted
    after
      Application.put_env(:krait, :disable_auth, true)
    end

    test "bypasses auth in test env with disable_auth", %{conn: conn} do
      Application.delete_env(:krait, :admin_auth_token)
      Application.put_env(:krait, :disable_auth, true)

      conn = KraitWeb.Plugs.AdminApiAuth.call(conn, [])

      refute conn.halted
    after
      Application.put_env(:krait, :disable_auth, true)
    end

    test "rejects missing authorization header", %{conn: conn} do
      Application.put_env(:krait, :admin_auth_token, "admin-token-abc")

      conn = KraitWeb.Plugs.AdminApiAuth.call(conn, [])

      assert conn.status == 401
      assert conn.halted
    after
      Application.delete_env(:krait, :admin_auth_token)
    end

    test "uses timing-safe comparison" do
      source = File.read!("lib/krait_web/plugs/admin_api_auth.ex")
      assert source =~ "Plug.Crypto.secure_compare"
    end
  end
end
