defmodule Krait.Skills.Core.WebFetch do
  @moduledoc "Fetches web pages via HTTP GET with domain allowlist and SSRF protection"
  @behaviour Krait.Skills.Skill

  require Logger
  import Bitwise

  @default_allowlist ["api.anthropic.com", "api.github.com", "api.coingecko.com"]

  # RFC-1918, loopback, link-local, cloud metadata
  @blocked_cidrs [
    # 10.0.0.0/8
    {10, 0, 0, 0, 8},
    # 172.16.0.0/12
    {172, 16, 0, 0, 12},
    # 192.168.0.0/16
    {192, 168, 0, 0, 16},
    # Loopback 127.0.0.0/8
    {127, 0, 0, 0, 8},
    # Link-local 169.254.0.0/16 (includes cloud metadata 169.254.169.254)
    {169, 254, 0, 0, 16},
    # 0.0.0.0/8
    {0, 0, 0, 0, 8}
  ]

  @impl true
  def name, do: "web_fetch"

  @impl true
  def description, do: "Fetch the content of a URL via HTTP GET"

  @impl true
  def trigger_phrases, do: ["fetch", "get url", "web fetch"]

  @impl true
  @spec execute(map()) :: {:ok, term()} | {:error, term()}
  def execute(%{"url" => url}) do
    with :ok <- check_domain_allowlist(url),
         {:ok, resolved_ip} <- resolve_and_check_ssrf(url) do
      Logger.info("WebFetch request", url: url, domain: URI.parse(url).host)
      do_request(url, resolved_ip)
    end
  end

  def execute(%{url: url}), do: execute(%{"url" => url})
  def execute(_), do: {:error, "Missing required parameter: url"}

  # ---------------------------------------------------------------------------
  # Domain allowlist enforcement (KRAIT-004)
  # ---------------------------------------------------------------------------

  defp check_domain_allowlist(url) do
    case URI.parse(url) do
      %URI{host: host} when is_binary(host) ->
        allowlist = get_allowlist()

        if domain_allowed?(host, allowlist) do
          :ok
        else
          Logger.warning("Domain rejected by allowlist", domain: host, url: url)
          {:error, "Domain #{host} not in domain allowlist"}
        end

      _ ->
        {:error, "Invalid URL: not in domain allowlist"}
    end
  end

  defp domain_allowed?(host, allowlist) do
    if allow_local?() and host in ["localhost", "127.0.0.1"] do
      true
    else
      # v25 M-4: Exact match only — no subdomain inference.
      # Only explicitly listed domains are allowed.
      host in allowlist
    end
  end

  # ---------------------------------------------------------------------------
  # SSRF protection — resolve DNS once, validate, then pin
  # ---------------------------------------------------------------------------

  # v10: M8 — allowed ports for WebFetch
  @allowed_fetch_ports [80, 443, 8080, 8443]

  defp resolve_and_check_ssrf(url) do
    case URI.parse(url) do
      %URI{host: host, port: port, scheme: scheme} when is_binary(host) ->
        if allow_local?() do
          # In test/dev with allow_local, skip SSRF checks (for Bypass etc.)
          {:ok, nil}
        else
          default_port = if scheme == "https", do: 443, else: 80
          effective_port = port || default_port

          if effective_port in @allowed_fetch_ports do
            resolve_and_validate(host)
          else
            {:error, "SSRF blocked: non-standard port #{effective_port}"}
          end
        end

      _ ->
        {:error, "Invalid URL"}
    end
  end

  defp resolve_and_validate(host) do
    # Try parsing as IP directly first
    case parse_ip(host) do
      {:ok, ip} ->
        if blocked_ip?(ip) do
          {:error, "SSRF blocked: #{host} resolves to internal IP"}
        else
          {:ok, format_ip(ip)}
        end

      :error ->
        # It's a hostname — DNS resolve it (IPv4)
        case resolve_host(host) do
          {:ok, ip} ->
            if blocked_ip?(ip) do
              {:error, "SSRF blocked: #{host} resolves to internal IP"}
            else
              # v20 M-9: Defense-in-depth — also check AAAA record
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

  # v20 M-9: Check if host has an IPv6 AAAA record pointing to a blocked address
  defp check_ipv6_record(host) do
    case :inet.getaddr(String.to_charlist(host), :inet6) do
      {:ok, ipv6} ->
        if blocked_ip?(ipv6) do
          {:error, "SSRF blocked: #{host} has internal IPv6 AAAA record"}
        else
          :ok
        end

      {:error, _} ->
        # No AAAA record — fine
        :ok
    end
  end

  defp format_ip(ip) when tuple_size(ip) == 4 do
    ip |> Tuple.to_list() |> Enum.join(".")
  end

  defp format_ip(ip) when tuple_size(ip) == 8 do
    ip |> Tuple.to_list() |> Enum.map_join(":", &Integer.to_string(&1, 16))
  end

  # Execute the HTTP request, pinning to the resolved IP to prevent DNS rebinding
  defp do_request(url, nil) do
    # allow_local mode: no IP pinning (for Bypass tests)
    case Req.get(url, redirect: false) do
      {:ok, %{status: status, body: body}} when status in 200..299 ->
        {:ok, %{status: status, body: body}}

      {:ok, %{status: status}} ->
        {:error, "HTTP #{status}"}

      {:error, reason} ->
        {:error, inspect(reason)}
    end
  end

  defp do_request(url, resolved_ip) do
    uri = URI.parse(url)
    host = uri.host
    scheme = uri.scheme || "https"
    port = uri.port || if(scheme == "https", do: 443, else: 80)
    path = uri.path || "/"
    query = if uri.query, do: "?#{uri.query}", else: ""

    # Build the pinned URL using the resolved IP instead of hostname
    pinned_url = "#{scheme}://#{resolved_ip}:#{port}#{path}#{query}"

    # v25 H-6: Parse resolved IP to tuple for Mint transport_opts pinning
    # v27 H-1: Fail closed if IP can't be parsed — prevents DNS rebinding fallback
    case parse_ip_to_tuple(resolved_ip) do
      nil ->
        Logger.warning("IP parse failed for pinning, rejecting request",
          resolved_ip: resolved_ip,
          url: url
        )

        {:error, "SSRF protection: IP parse failed for pinning"}

      ip_tuple ->
        do_pinned_request(pinned_url, host, scheme, ip_tuple)
    end
  end

  # v27 H-1: Extracted from do_request to ensure ip_tuple is always present
  defp do_pinned_request(pinned_url, host, scheme, ip_tuple) do
    connect_opts =
      if scheme == "https" do
        [
          hostname: host,
          transport_opts: [
            server_name_indication: String.to_charlist(host),
            ip: ip_tuple
          ]
        ]
      else
        [transport_opts: [ip: ip_tuple]]
      end

    req_opts = [
      headers: [{"host", host}],
      redirect: false,
      connect_options: connect_opts
    ]

    case Req.get(pinned_url, req_opts) do
      {:ok, %{status: status, body: body}} when status in 200..299 ->
        {:ok, %{status: status, body: body}}

      {:ok, %{status: status}} ->
        {:error, "HTTP #{status}"}

      {:error, reason} ->
        {:error, inspect(reason)}
    end
  end

  defp parse_ip(host) do
    case :inet.parse_address(String.to_charlist(host)) do
      {:ok, ip} -> {:ok, ip}
      {:error, _} -> :error
    end
  end

  # v25 H-6: Parse IP string to tuple for Mint transport_opts pinning
  defp parse_ip_to_tuple(ip_string) when is_binary(ip_string) do
    case :inet.parse_address(String.to_charlist(ip_string)) do
      {:ok, ip_tuple} -> ip_tuple
      {:error, _} -> nil
    end
  end

  # v10: M2 — :inet.getaddr/2 with :inet resolves IPv4 only. IPv6-only DNS records
  # cause {:error, :nxdomain}, which triggers "SSRF blocked: DNS resolution failed" —
  # fail-closed by design. No dual-stack resolution needed.
  defp resolve_host(host) do
    case :inet.getaddr(String.to_charlist(host), :inet) do
      {:ok, ip} -> {:ok, ip}
      {:error, reason} -> {:error, reason}
    end
  end

  defp blocked_ip?({a, b, c, d}) do
    Enum.any?(@blocked_cidrs, fn {na, nb, nc, nd, prefix_len} ->
      ip_int = a <<< 24 ||| b <<< 16 ||| c <<< 8 ||| d
      net_int = na <<< 24 ||| nb <<< 16 ||| nc <<< 8 ||| nd
      mask = Bitwise.bnot((1 <<< (32 - prefix_len)) - 1) &&& 0xFFFFFFFF
      (ip_int &&& mask) == (net_int &&& mask)
    end)
  end

  # IPv6 — block loopback (::1)
  defp blocked_ip?({0, 0, 0, 0, 0, 0, 0, 1}), do: true
  # v10: M8 — NAT64 well-known prefix 64:ff9b::/96 — delegates to IPv4 check
  defp blocked_ip?({0x0064, 0xFF9B, 0, 0, 0, 0, hi16, lo16}) do
    blocked_ip?({hi16 >>> 8, hi16 &&& 0xFF, lo16 >>> 8, lo16 &&& 0xFF})
  end

  # IPv6 link-local fe80::/10
  defp blocked_ip?({a, _, _, _, _, _, _, _}) when (a &&& 0xFFC0) == 0xFE80, do: true
  # IPv6 unique-local fc00::/7 (covers fc00::/8 and fd00::/8)
  defp blocked_ip?({a, _, _, _, _, _, _, _}) when (a &&& 0xFE00) == 0xFC00, do: true
  # IPv4-mapped IPv6 ::ffff:x.x.x.x — delegate to IPv4 check
  defp blocked_ip?({0, 0, 0, 0, 0, 0xFFFF, hi16, lo16}) do
    blocked_ip?({hi16 >>> 8, hi16 &&& 0xFF, lo16 >>> 8, lo16 &&& 0xFF})
  end

  # Teredo 2001:0000::/32
  defp blocked_ip?({0x2001, 0x0000, _, _, _, _, _, _}), do: true
  # Documentation 2001:db8::/32
  defp blocked_ip?({0x2001, 0x0DB8, _, _, _, _, _, _}), do: true
  # Benchmarking 2001:0002::/48
  defp blocked_ip?({0x2001, 0x0002, _, _, _, _, _, _}), do: true
  # 6to4 2002::/16
  defp blocked_ip?({0x2002, _, _, _, _, _, _, _}), do: true
  # IPv4-compatible (deprecated) ::x.x.x.x — delegate to IPv4 check
  defp blocked_ip?({0, 0, 0, 0, 0, 0, hi16, lo16}) do
    blocked_ip?({hi16 >>> 8, hi16 &&& 0xFF, lo16 >>> 8, lo16 &&& 0xFF})
  end

  # Global Unicast 2000::/3 (0x2000-0x3FFF) — ALLOW (except Teredo/6to4 caught above)
  defp blocked_ip?({a, _, _, _, _, _, _, _}) when a >= 0x2000 and a <= 0x3FFF, do: false
  # Block everything else (multicast, documentation, reserved)
  defp blocked_ip?({_, _, _, _, _, _, _, _}), do: true

  # ---------------------------------------------------------------------------
  # Config helpers
  # ---------------------------------------------------------------------------

  defp get_allowlist do
    Application.get_env(:krait, :network_allowlist, @default_allowlist)
  end

  defp allow_local? do
    Application.get_env(:krait, :env, :dev) != :prod and
      Application.get_env(:krait, :allow_local_network, false)
  end
end
