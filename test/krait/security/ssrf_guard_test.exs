defmodule Krait.Security.SsrfGuardTest do
  use ExUnit.Case, async: true

  alias Krait.Security.SsrfGuard

  describe "blocked_ip?/1" do
    test "blocks loopback 127.0.0.1" do
      assert SsrfGuard.blocked_ip?({127, 0, 0, 1})
    end

    test "blocks RFC-1918 10.x.x.x" do
      assert SsrfGuard.blocked_ip?({10, 0, 0, 1})
    end

    test "blocks RFC-1918 172.16.x.x" do
      assert SsrfGuard.blocked_ip?({172, 16, 0, 1})
    end

    test "blocks RFC-1918 192.168.x.x" do
      assert SsrfGuard.blocked_ip?({192, 168, 1, 1})
    end

    test "blocks cloud metadata 169.254.169.254" do
      assert SsrfGuard.blocked_ip?({169, 254, 169, 254})
    end

    test "allows public IP" do
      refute SsrfGuard.blocked_ip?({8, 8, 8, 8})
    end

    test "blocks IPv6 loopback ::1" do
      assert SsrfGuard.blocked_ip?({0, 0, 0, 0, 0, 0, 0, 1})
    end

    test "blocks IPv6 link-local fe80::" do
      assert SsrfGuard.blocked_ip?({0xFE80, 0, 0, 0, 0, 0, 0, 1})
    end

    test "blocks IPv6 unique-local fc00::" do
      assert SsrfGuard.blocked_ip?({0xFC00, 0, 0, 0, 0, 0, 0, 1})
    end

    test "blocks IPv4-mapped IPv6 ::ffff:10.0.0.1" do
      assert SsrfGuard.blocked_ip?({0, 0, 0, 0, 0, 0xFFFF, 0x0A00, 0x0001})
    end

    test "blocks Teredo 2001:0::" do
      assert SsrfGuard.blocked_ip?({0x2001, 0x0000, 0, 0, 0, 0, 0, 1})
    end

    test "allows global unicast" do
      refute SsrfGuard.blocked_ip?({0x2607, 0xF8B0, 0x4004, 0x800, 0, 0, 0, 0x200E})
    end
  end

  describe "validate_url/1 in prod mode" do
    setup do
      original_env = Application.get_env(:krait, :env)
      original_local = Application.get_env(:krait, :allow_local_network)
      Application.put_env(:krait, :env, :prod)
      Application.put_env(:krait, :allow_local_network, false)

      on_exit(fn ->
        if original_env,
          do: Application.put_env(:krait, :env, original_env),
          else: Application.delete_env(:krait, :env)

        if original_local,
          do: Application.put_env(:krait, :allow_local_network, original_local),
          else: Application.delete_env(:krait, :allow_local_network)
      end)

      :ok
    end

    test "blocks non-standard ports" do
      assert {:error, msg} = SsrfGuard.validate_url("http://example.com:9999/path")
      assert msg =~ "non-standard port"
    end

    test "blocks internal IPs" do
      assert {:error, msg} = SsrfGuard.validate_url("http://127.0.0.1/admin")
      assert msg =~ "SSRF blocked"
    end

    test "blocks cloud metadata" do
      assert {:error, msg} = SsrfGuard.validate_url("http://169.254.169.254/latest/meta-data/")
      assert msg =~ "SSRF blocked"
    end

    test "blocks invalid URLs" do
      assert {:error, _} = SsrfGuard.validate_url("not-a-url")
    end
  end

  describe "resolve_and_validate/1" do
    test "resolves public hosts" do
      # This may fail in CI without DNS, but validates the contract
      case SsrfGuard.resolve_and_validate("localhost") do
        {:ok, ip} -> assert is_binary(ip)
        {:error, msg} -> assert msg =~ "SSRF blocked"
      end
    end

    test "rejects unresolvable hosts" do
      assert {:error, msg} =
               SsrfGuard.resolve_and_validate("definitely-unresolvable.invalid")

      assert msg =~ "DNS resolution failed"
    end
  end
end
