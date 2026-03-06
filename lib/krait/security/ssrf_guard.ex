defmodule Krait.Security.SsrfGuard do
  @moduledoc """
  Shared SSRF protection: DNS resolution + internal/reserved IP blocking.

  v25 M-3: Extracted from WebFetch for reuse by Webhook and other HTTP-sending
  modules. Validates that a URL/host does not resolve to internal infrastructure.
  """

  import Bitwise

  # RFC-1918, loopback, link-local, cloud metadata
  @blocked_cidrs [
    {10, 0, 0, 0, 8},
    {172, 16, 0, 0, 12},
    {192, 168, 0, 0, 16},
    {127, 0, 0, 0, 8},
    {169, 254, 0, 0, 16},
    {0, 0, 0, 0, 8}
  ]

  @allowed_ports [80, 443, 8080, 8443]

  @doc """
  Validate that a URL does not target internal infrastructure.

  Parses the URL, checks the port is allowed, resolves DNS, and verifies
  the resolved IP is not in a blocked range. Returns `{:ok, resolved_ip_string}`
  on success or `{:error, reason}` if blocked.

  In test/dev with `allow_local_network: true`, SSRF checks are skipped
  (for Bypass test servers on random ports).
  """
  @spec validate_url(String.t()) :: {:ok, String.t()} | {:error, String.t()}
  def validate_url(url) when is_binary(url) do
    if allow_local?() do
      {:ok, "local"}
    else
      do_validate_url(url)
    end
  end

  defp do_validate_url(url) do
    case URI.parse(url) do
      %URI{host: host, port: port, scheme: scheme} when is_binary(host) ->
        default_port = if scheme == "https", do: 443, else: 80
        effective_port = port || default_port

        if effective_port in @allowed_ports do
          resolve_and_validate(host)
        else
          {:error, "SSRF blocked: non-standard port #{effective_port}"}
        end

      _ ->
        {:error, "SSRF blocked: invalid URL"}
    end
  end

  @doc """
  Resolve a hostname and validate the resolved IP is not internal.

  Returns `{:ok, ip_string}` or `{:error, reason}`.
  """
  @spec resolve_and_validate(String.t()) :: {:ok, String.t()} | {:error, String.t()}
  def resolve_and_validate(host) when is_binary(host) do
    case parse_ip(host) do
      {:ok, ip} ->
        if blocked_ip?(ip) do
          {:error, "SSRF blocked: #{host} resolves to internal IP"}
        else
          {:ok, format_ip(ip)}
        end

      :error ->
        case resolve_host(host) do
          {:ok, ip} ->
            if blocked_ip?(ip) do
              {:error, "SSRF blocked: #{host} resolves to internal IP"}
            else
              case check_ipv6_record(host) do
                :ok -> {:ok, format_ip(ip)}
                {:error, _} = err -> err
              end
            end

          {:error, _reason} ->
            {:error, "SSRF blocked: DNS resolution failed for #{host}"}
        end
    end
  end

  @doc "Check if an IP tuple is in a blocked/reserved range."
  @spec blocked_ip?(tuple()) :: boolean()
  # IPv4
  def blocked_ip?({a, b, c, d}) do
    Enum.any?(@blocked_cidrs, fn {na, nb, nc, nd, prefix_len} ->
      ip_int = a <<< 24 ||| b <<< 16 ||| c <<< 8 ||| d
      net_int = na <<< 24 ||| nb <<< 16 ||| nc <<< 8 ||| nd
      mask = Bitwise.bnot((1 <<< (32 - prefix_len)) - 1) &&& 0xFFFFFFFF
      (ip_int &&& mask) == (net_int &&& mask)
    end)
  end

  # IPv6 loopback ::1
  def blocked_ip?({0, 0, 0, 0, 0, 0, 0, 1}), do: true
  # NAT64 64:ff9b::/96
  def blocked_ip?({0x0064, 0xFF9B, 0, 0, 0, 0, hi16, lo16}) do
    blocked_ip?({hi16 >>> 8, hi16 &&& 0xFF, lo16 >>> 8, lo16 &&& 0xFF})
  end

  # IPv6 link-local fe80::/10
  def blocked_ip?({a, _, _, _, _, _, _, _}) when (a &&& 0xFFC0) == 0xFE80, do: true
  # IPv6 unique-local fc00::/7
  def blocked_ip?({a, _, _, _, _, _, _, _}) when (a &&& 0xFE00) == 0xFC00, do: true
  # IPv4-mapped IPv6 ::ffff:x.x.x.x
  def blocked_ip?({0, 0, 0, 0, 0, 0xFFFF, hi16, lo16}) do
    blocked_ip?({hi16 >>> 8, hi16 &&& 0xFF, lo16 >>> 8, lo16 &&& 0xFF})
  end

  # Teredo 2001:0000::/32
  def blocked_ip?({0x2001, 0x0000, _, _, _, _, _, _}), do: true
  # Documentation 2001:db8::/32
  def blocked_ip?({0x2001, 0x0DB8, _, _, _, _, _, _}), do: true
  # Benchmarking 2001:0002::/48
  def blocked_ip?({0x2001, 0x0002, _, _, _, _, _, _}), do: true
  # 6to4 2002::/16
  def blocked_ip?({0x2002, _, _, _, _, _, _, _}), do: true
  # IPv4-compatible ::x.x.x.x
  def blocked_ip?({0, 0, 0, 0, 0, 0, hi16, lo16}) do
    blocked_ip?({hi16 >>> 8, hi16 &&& 0xFF, lo16 >>> 8, lo16 &&& 0xFF})
  end

  # Global Unicast 2000::/3 — ALLOW
  def blocked_ip?({a, _, _, _, _, _, _, _}) when a >= 0x2000 and a <= 0x3FFF, do: false
  # Block everything else
  def blocked_ip?({_, _, _, _, _, _, _, _}), do: true

  # --- Private helpers ---

  defp parse_ip(host) do
    case :inet.parse_address(String.to_charlist(host)) do
      {:ok, ip} -> {:ok, ip}
      {:error, _} -> :error
    end
  end

  defp resolve_host(host) do
    case :inet.getaddr(String.to_charlist(host), :inet) do
      {:ok, ip} -> {:ok, ip}
      {:error, reason} -> {:error, reason}
    end
  end

  defp check_ipv6_record(host) do
    case :inet.getaddr(String.to_charlist(host), :inet6) do
      {:ok, ipv6} ->
        if blocked_ip?(ipv6) do
          {:error, "SSRF blocked: #{host} has internal IPv6 AAAA record"}
        else
          :ok
        end

      {:error, _} ->
        :ok
    end
  end

  defp format_ip(ip) when tuple_size(ip) == 4 do
    ip |> Tuple.to_list() |> Enum.join(".")
  end

  defp format_ip(ip) when tuple_size(ip) == 8 do
    ip |> Tuple.to_list() |> Enum.map_join(":", &Integer.to_string(&1, 16))
  end

  defp allow_local? do
    Application.get_env(:krait, :env, :dev) != :prod and
      Application.get_env(:krait, :allow_local_network, false)
  end
end
