defmodule Krait.Skills.Core.WebFetchTest do
  use ExUnit.Case, async: true

  test "name returns web_fetch" do
    assert Krait.Skills.Core.WebFetch.name() == "web_fetch"
  end

  test "returns error for missing url" do
    assert {:error, _} = Krait.Skills.Core.WebFetch.execute(%{})
  end

  describe "domain allowlist enforcement" do
    test "allows requests to allowlisted domains" do
      bypass = Bypass.open()

      Bypass.expect_once(bypass, "GET", "/ok", fn conn ->
        Plug.Conn.resp(conn, 200, "hello")
      end)

      # localhost is always allowed in test (allow_local_network: true)
      assert {:ok, %{status: 200}} =
               Krait.Skills.Core.WebFetch.execute(%{
                 "url" => "http://localhost:#{bypass.port}/ok"
               })
    end

    test "rejects requests to non-allowlisted domains" do
      assert {:error, msg} =
               Krait.Skills.Core.WebFetch.execute(%{"url" => "https://evil.example.com/steal"})

      assert msg =~ "not in domain allowlist"
    end

    test "rejects IP address URLs" do
      assert {:error, msg} =
               Krait.Skills.Core.WebFetch.execute(%{"url" => "http://192.168.1.1/api"})

      assert msg =~ "not in domain allowlist"
    end
  end

  describe "SSRF protection" do
    setup do
      # Temporarily disable allow_local_network to test SSRF blocking
      original = Application.get_env(:krait, :allow_local_network)
      Application.put_env(:krait, :allow_local_network, false)
      # Also add the test host to allowlist so domain check passes
      original_allowlist = Application.get_env(:krait, :network_allowlist)

      on_exit(fn ->
        if original do
          Application.put_env(:krait, :allow_local_network, original)
        else
          Application.delete_env(:krait, :allow_local_network)
        end

        if original_allowlist do
          Application.put_env(:krait, :network_allowlist, original_allowlist)
        end
      end)

      :ok
    end

    test "blocks cloud metadata IP 169.254.169.254" do
      Application.put_env(:krait, :network_allowlist, ["169.254.169.254"])

      assert {:error, msg} =
               Krait.Skills.Core.WebFetch.execute(%{
                 "url" => "http://169.254.169.254/latest/meta-data/"
               })

      assert msg =~ "SSRF blocked"
    end

    test "blocks loopback IP 127.0.0.1" do
      Application.put_env(:krait, :network_allowlist, ["127.0.0.1"])

      assert {:error, msg} =
               Krait.Skills.Core.WebFetch.execute(%{
                 "url" => "http://127.0.0.1/admin"
               })

      assert msg =~ "SSRF blocked"
    end

    test "blocks RFC-1918 10.x.x.x" do
      Application.put_env(:krait, :network_allowlist, ["10.0.0.1"])

      assert {:error, msg} =
               Krait.Skills.Core.WebFetch.execute(%{
                 "url" => "http://10.0.0.1/internal"
               })

      assert msg =~ "SSRF blocked"
    end

    test "blocks RFC-1918 172.16.x.x" do
      Application.put_env(:krait, :network_allowlist, ["172.16.0.1"])

      assert {:error, msg} =
               Krait.Skills.Core.WebFetch.execute(%{
                 "url" => "http://172.16.0.1/internal"
               })

      assert msg =~ "SSRF blocked"
    end

    test "fail-closed on DNS resolution failure" do
      Application.put_env(:krait, :network_allowlist, [
        "definitely-unresolvable-host-krait-test.invalid"
      ])

      assert {:error, msg} =
               Krait.Skills.Core.WebFetch.execute(%{
                 "url" => "http://definitely-unresolvable-host-krait-test.invalid/secret"
               })

      assert msg =~ "DNS resolution failed"
    end
  end

  describe "redirect protection" do
    test "does not follow 302 redirect (could bypass SSRF)" do
      bypass = Bypass.open()

      Bypass.expect_once(bypass, "GET", "/redirect", fn conn ->
        conn
        |> Plug.Conn.put_resp_header("location", "http://169.254.169.254/latest/meta-data/")
        |> Plug.Conn.resp(302, "")
      end)

      assert {:error, msg} =
               Krait.Skills.Core.WebFetch.execute(%{
                 "url" => "http://localhost:#{bypass.port}/redirect"
               })

      assert msg =~ "HTTP 302"
    end

    test "does not follow 301 redirect" do
      bypass = Bypass.open()

      Bypass.expect_once(bypass, "GET", "/moved", fn conn ->
        conn
        |> Plug.Conn.put_resp_header("location", "https://evil.example.com/")
        |> Plug.Conn.resp(301, "")
      end)

      assert {:error, msg} =
               Krait.Skills.Core.WebFetch.execute(%{
                 "url" => "http://localhost:#{bypass.port}/moved"
               })

      assert msg =~ "HTTP 301"
    end
  end

  describe "IPv6 SSRF protection" do
    setup do
      original = Application.get_env(:krait, :allow_local_network)
      Application.put_env(:krait, :allow_local_network, false)
      original_allowlist = Application.get_env(:krait, :network_allowlist)

      on_exit(fn ->
        if original do
          Application.put_env(:krait, :allow_local_network, original)
        else
          Application.delete_env(:krait, :allow_local_network)
        end

        if original_allowlist do
          Application.put_env(:krait, :network_allowlist, original_allowlist)
        end
      end)

      :ok
    end

    test "blocks IPv6 link-local fe80::1" do
      Application.put_env(:krait, :network_allowlist, ["fe80::1"])

      assert {:error, msg} =
               Krait.Skills.Core.WebFetch.execute(%{"url" => "http://[fe80::1]/admin"})

      assert msg =~ "SSRF blocked"
    end

    test "blocks IPv6 unique-local fc00::1" do
      Application.put_env(:krait, :network_allowlist, ["fc00::1"])

      assert {:error, msg} =
               Krait.Skills.Core.WebFetch.execute(%{"url" => "http://[fc00::1]/admin"})

      assert msg =~ "SSRF blocked"
    end

    test "blocks IPv6 unique-local fd00::1" do
      Application.put_env(:krait, :network_allowlist, ["fd00::1"])

      assert {:error, msg} =
               Krait.Skills.Core.WebFetch.execute(%{"url" => "http://[fd00::1]/admin"})

      assert msg =~ "SSRF blocked"
    end

    test "blocks IPv4-mapped IPv6 ::ffff:10.0.0.1" do
      Application.put_env(:krait, :network_allowlist, ["::ffff:10.0.0.1"])

      assert {:error, msg} =
               Krait.Skills.Core.WebFetch.execute(%{
                 "url" => "http://[::ffff:10.0.0.1]/internal"
               })

      assert msg =~ "SSRF blocked"
    end

    test "blocks IPv4-mapped IPv6 ::ffff:192.168.1.1" do
      Application.put_env(:krait, :network_allowlist, ["::ffff:192.168.1.1"])

      assert {:error, msg} =
               Krait.Skills.Core.WebFetch.execute(%{
                 "url" => "http://[::ffff:192.168.1.1]/internal"
               })

      assert msg =~ "SSRF blocked"
    end

    test "blocks IPv4-mapped IPv6 ::ffff:169.254.169.254" do
      Application.put_env(:krait, :network_allowlist, ["::ffff:169.254.169.254"])

      assert {:error, msg} =
               Krait.Skills.Core.WebFetch.execute(%{
                 "url" => "http://[::ffff:169.254.169.254]/metadata"
               })

      assert msg =~ "SSRF blocked"
    end

    test "blocks Teredo IPv6 2001:0:4136:e378:8000:63bf:3fff:fdd2" do
      Application.put_env(:krait, :network_allowlist, [
        "2001:0:4136:e378:8000:63bf:3fff:fdd2"
      ])

      assert {:error, msg} =
               Krait.Skills.Core.WebFetch.execute(%{
                 "url" => "http://[2001:0:4136:e378:8000:63bf:3fff:fdd2]/admin"
               })

      assert msg =~ "SSRF blocked"
    end

    test "blocks 6to4 IPv6 2002:c0a8:1::1 (encodes 192.168.x.x)" do
      Application.put_env(:krait, :network_allowlist, ["2002:c0a8:1::1"])

      assert {:error, msg} =
               Krait.Skills.Core.WebFetch.execute(%{
                 "url" => "http://[2002:c0a8:1::1]/admin"
               })

      assert msg =~ "SSRF blocked"
    end

    test "blocks IPv4-compatible IPv6 ::192.168.1.1" do
      Application.put_env(:krait, :network_allowlist, ["::192.168.1.1"])

      assert {:error, msg} =
               Krait.Skills.Core.WebFetch.execute(%{
                 "url" => "http://[::192.168.1.1]/admin"
               })

      assert msg =~ "SSRF blocked"
    end

    test "blocks documentation IPv6 2001:db8::1" do
      Application.put_env(:krait, :network_allowlist, ["2001:db8::1"])

      assert {:error, msg} =
               Krait.Skills.Core.WebFetch.execute(%{
                 "url" => "http://[2001:db8::1]/test"
               })

      assert msg =~ "SSRF blocked"
    end

    test "blocks benchmarking IPv6 2001:2::1" do
      Application.put_env(:krait, :network_allowlist, ["2001:2::1"])

      assert {:error, msg} =
               Krait.Skills.Core.WebFetch.execute(%{
                 "url" => "http://[2001:2::1]/test"
               })

      assert msg =~ "SSRF blocked"
    end

    test "allows Global Unicast 2607:f8b0:4004:800::200e (not blocked by SSRF)" do
      # Global unicast should NOT be blocked by SSRF — it passes SSRF but
      # may fail for other reasons (transport error, domain allowlist, etc.)
      Application.put_env(:krait, :network_allowlist, [
        "2607:f8b0:4004:800::200e"
      ])

      assert {:error, msg} =
               Krait.Skills.Core.WebFetch.execute(%{
                 "url" => "http://[2607:f8b0:4004:800::200e]/test"
               })

      # Should NOT be an SSRF block — global unicast is allowed
      refute msg =~ "SSRF blocked"
    end
  end
end
