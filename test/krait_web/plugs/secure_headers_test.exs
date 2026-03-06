defmodule KraitWeb.Plugs.SecureHeadersTest do
  use KraitWeb.ConnCase, async: false

  setup do
    ensure_rate_limit_counter!()
    GenServer.call(KraitWeb.RateLimitCounter, {:sweep_all})
    :ok
  end

  describe "v22 SEC-16: security headers on browser routes" do
    test "GET /admin/login includes referrer-policy header", %{conn: conn} do
      conn = get(conn, "/admin/login")
      assert get_resp_header(conn, "referrer-policy") == ["strict-origin-when-cross-origin"]
    end

    test "GET /admin/login includes permissions-policy header", %{conn: conn} do
      conn = get(conn, "/admin/login")
      [policy] = get_resp_header(conn, "permissions-policy")
      assert policy =~ "camera=()"
      assert policy =~ "microphone=()"
      assert policy =~ "geolocation=()"
    end

    test "GET /admin/login includes content-security-policy header", %{conn: conn} do
      conn = get(conn, "/admin/login")
      [csp] = get_resp_header(conn, "content-security-policy")
      assert csp =~ "default-src 'self'"
      assert csp =~ "frame-ancestors 'none'"
    end

    test "GET /admin/login includes x-content-type-options header", %{conn: conn} do
      conn = get(conn, "/admin/login")
      assert get_resp_header(conn, "x-content-type-options") == ["nosniff"]
    end
  end

  describe "v22 SEC-16: security headers on authenticated routes" do
    test "both browser pipelines use shared @secure_headers" do
      source = File.read!("lib/krait_web/router.ex")
      assert source =~ ~s(plug :put_secure_browser_headers, @secure_headers)
      # Count occurrences — should appear in both :browser and :authenticated_browser
      occurrences =
        source
        |> String.split("plug :put_secure_browser_headers, @secure_headers")
        |> length()
        |> Kernel.-(1)

      assert occurrences == 2, "Expected @secure_headers in both browser pipelines"
    end
  end

  defp ensure_rate_limit_counter! do
    case GenServer.whereis(KraitWeb.RateLimitCounter) do
      nil -> KraitWeb.RateLimitCounter.start_link([])
      pid -> if Process.alive?(pid), do: :ok, else: KraitWeb.RateLimitCounter.start_link([])
    end
  end
end
