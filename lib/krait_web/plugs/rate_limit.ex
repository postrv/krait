defmodule KraitWeb.Plugs.RateLimit do
  @moduledoc """
  ETS-backed rate limiter plug keyed by client IP.

  Limits requests per IP to `max_requests` within `window_ms`.

  The ETS table is created in `Krait.Application.start/2` at runtime.
  This plug does NOT create the table in `init/1` because `init/1` runs at
  compile time in Phoenix routers and that table wouldn't persist to runtime.

  ## Configuration

      plug KraitWeb.Plugs.RateLimit, max_requests: 10, window_ms: 60_000
  """

  import Plug.Conn
  require Logger

  @behaviour Plug

  @default_max_requests 10
  @default_window_ms 60_000
  @table :krait_rate_limit

  @impl true
  def init(opts) do
    %{
      max_requests: Keyword.get(opts, :max_requests, @default_max_requests),
      window_ms: Keyword.get(opts, :window_ms, @default_window_ms),
      response_format: Keyword.get(opts, :response_format, :json)
    }
  end

  @max_table_entries 100_000

  @impl true
  def call(conn, %{max_requests: max, window_ms: window} = opts) do
    ensure_table!()

    # Guard against unbounded table growth
    if :ets.info(@table, :size) > @max_table_entries do
      # v27 M-4: Force sweep when circuit breaker trips before rejecting
      sweep_stale(window)

      # v27 M-4: Admin token holders bypass the circuit breaker
      if admin_token_present?(conn) do
        do_rate_check(conn, max, window, Map.get(opts, :response_format, :json))
      else
        conn
        |> put_status(503)
        |> Phoenix.Controller.json(%{error: "service temporarily unavailable"})
        |> halt()
      end
    else
      do_rate_check(conn, max, window, Map.get(opts, :response_format, :json))
    end
  end

  defp do_rate_check(conn, max, window, response_format) do
    maybe_sweep(window)
    ip = client_ip(conn)
    now = System.monotonic_time(:millisecond)
    bucket = div(now, window)
    bucket_key = {ip, bucket}

    # v21 H-3: Route writes through RateLimitCounter GenServer (:protected table)
    ip_count = KraitWeb.RateLimitCounter.increment(bucket_key)

    # v25 L-5: Sliding window — also check previous bucket to smooth rate limiting
    # across bucket boundaries. Weight previous bucket by remaining fraction.
    prev_bucket_key = {ip, bucket - 1}
    prev_count = KraitWeb.RateLimitCounter.get_count(prev_bucket_key)
    elapsed_fraction = rem(now, window) / max(window, 1)
    weighted_count = round(prev_count * (1.0 - elapsed_fraction) + ip_count)

    # v24 F-08: Per-token secondary rate limit — prevents a single token from
    # consuming the entire IP-based quota (e.g., shared NAT/proxy)
    token_count = check_token_rate(conn, bucket)
    count = max(weighted_count, token_count)

    if count > max do
      Logger.warning("Rate limit exceeded", ip: ip, count: count)

      conn
      |> put_resp_header("retry-after", to_string(div(window, 1000)))
      |> send_rate_limit_response(response_format)
      |> halt()
    else
      conn
    end
  end

  # v24 F-08: Track per-token rate limit using hashed bearer token
  defp check_token_rate(conn, bucket) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> token] when byte_size(token) > 0 ->
        token_hash = :crypto.hash(:sha256, token) |> Base.encode16(case: :lower)
        # v27 L-4: 32 hex chars (128 bits) instead of 16 (64 bits) to prevent collisions
        token_key = {:token, binary_part(token_hash, 0, 32), bucket}
        KraitWeb.RateLimitCounter.increment(token_key)

      _ ->
        0
    end
  end

  defp send_rate_limit_response(conn, :html) do
    conn
    |> put_resp_content_type("text/html")
    |> send_resp(429, rate_limit_html())
  end

  defp send_rate_limit_response(conn, _json) do
    conn
    |> put_status(429)
    |> Phoenix.Controller.json(%{error: "rate limit exceeded"})
  end

  defp rate_limit_html do
    """
    <!DOCTYPE html>
    <html><head><title>Rate Limited</title></head>
    <body style="display:flex;justify-content:center;align-items:center;height:100vh;font-family:sans-serif">
    <div style="text-align:center">
    <h1>429 Too Many Requests</h1>
    <p>Rate limit exceeded. Please try again later.</p>
    </div>
    </body></html>
    """
  end

  defp client_ip(conn) do
    remote_str = normalize_ip(conn.remote_ip)
    trusted = Application.get_env(:krait, :trusted_proxies, [])

    if remote_str in trusted do
      extract_forwarded_ip(conn) || remote_str
    else
      remote_str
    end
  end

  # v25 M-9: Normalize IP addresses to canonical form for consistent rate limiting.
  # Prevents bypass via IPv6 representation variants (e.g., ::ffff:127.0.0.1 vs 127.0.0.1)
  defp normalize_ip(ip_tuple) when is_tuple(ip_tuple) do
    ip_tuple |> :inet.ntoa() |> to_string() |> normalize_ip_string()
  end

  defp normalize_ip_string(ip_str) do
    case :inet.parse_address(String.to_charlist(ip_str)) do
      {:ok, normalized} -> normalized |> :inet.ntoa() |> to_string()
      {:error, _} -> ip_str
    end
  end

  defp extract_forwarded_ip(conn) do
    trusted = Application.get_env(:krait, :trusted_proxies, [])

    case get_req_header(conn, "x-forwarded-for") do
      [value | _] ->
        value
        |> String.split(",")
        |> Enum.map(&String.trim/1)
        |> Enum.reverse()
        |> find_first_untrusted(trusted)

      [] ->
        nil
    end
  end

  defp find_first_untrusted([], _trusted), do: nil

  defp find_first_untrusted([ip | rest], trusted) do
    if valid_ip?(ip) and ip not in trusted do
      ip
    else
      find_first_untrusted(rest, trusted)
    end
  end

  defp valid_ip?(ip_str) do
    case :inet.parse_address(String.to_charlist(ip_str)) do
      {:ok, _} -> true
      {:error, _} -> false
    end
  end

  @doc """
  Remove stale bucket entries from the rate limit table.

  Buckets are keyed by `{ip, bucket_epoch}` where `bucket_epoch = div(now, window_ms)`.
  Entries from previous bucket epochs are stale and can be removed.

  Called probabilistically (~1% of requests) via `maybe_sweep/1`,
  or explicitly in tests.
  """
  @spec sweep_stale(non_neg_integer()) :: :ok
  def sweep_stale(window_ms) do
    # v21 H-3: Delegate sweep to GenServer (table is :protected)
    KraitWeb.RateLimitCounter.sweep_stale(window_ms)
  end

  @sweep_size_threshold 10_000

  # Sweep stale entries probabilistically (~1% of requests) or deterministically when table is large
  defp maybe_sweep(window_ms) do
    # v20 L-7: Force sweep when table exceeds size threshold
    if :ets.info(@table, :size) > @sweep_size_threshold or :rand.uniform(100) == 1 do
      sweep_stale(window_ms)
    end
  end

  # v27 M-4: Check if request carries a valid admin token (bypasses circuit breaker)
  defp admin_token_present?(conn) do
    case Application.get_env(:krait, :admin_auth_token) do
      nil ->
        false

      expected when is_binary(expected) ->
        case get_req_header(conn, "authorization") do
          ["Bearer " <> token] -> Plug.Crypto.secure_compare(token, expected)
          _ -> false
        end
    end
  end

  # v21 H-3: Table is now owned by RateLimitCounter GenServer.
  # This fallback starts the GenServer if it's not running (e.g. in tests).
  defp ensure_table! do
    case :ets.whereis(@table) do
      :undefined ->
        case KraitWeb.RateLimitCounter.start_link([]) do
          {:ok, _} -> :ok
          {:error, {:already_started, _}} -> :ok
        end

      _ ->
        :ok
    end
  end
end
