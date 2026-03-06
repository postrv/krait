defmodule Krait.Gateway.Channels.Webhook do
  @moduledoc "Generic webhook channel for Discord, Slack, or custom integrations"
  @behaviour Krait.Gateway.Channel

  use GenServer
  require Logger

  # v21 M-6: Cap stored messages to prevent memory exhaustion
  @max_messages 1000

  @impl Krait.Gateway.Channel
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  @impl Krait.Gateway.Channel
  def send_message(pid, recipient, message) do
    GenServer.call(pid, {:send_message, recipient, message})
  end

  @impl Krait.Gateway.Channel
  def channel_type, do: :webhook

  @doc "Process an incoming webhook payload"
  def process_incoming(pid, payload, signature \\ nil, raw_body \\ nil) do
    GenServer.call(pid, {:incoming, payload, signature, raw_body})
  end

  @impl GenServer
  def init(opts) do
    webhook_url = Keyword.get(opts, :webhook_url)
    secret = Keyword.get(opts, :secret)
    handler = Keyword.get(opts, :handler)

    {:ok,
     %{
       webhook_url: webhook_url,
       secret: secret,
       handler: handler,
       messages: []
     }}
  end

  @impl GenServer
  def handle_call({:send_message, recipient, message}, _from, state) do
    case state.webhook_url do
      nil ->
        # No webhook URL configured — store locally (dev/test mode)
        messages = Enum.take([{recipient, message} | state.messages], @max_messages)
        {:reply, :ok, %{state | messages: messages}}

      url ->
        # v25 M-3: SSRF validation on webhook URL before outgoing POST
        # v27 H-3: Pin resolved IP in outbound request to prevent DNS rebinding
        case Krait.Security.SsrfGuard.validate_url(url) do
          {:error, reason} ->
            Logger.warning("Webhook URL blocked by SSRF guard", url: url, reason: reason)
            {:reply, {:error, {:ssrf_blocked, reason}}, state}

          {:ok, resolved_ip} ->
            send_webhook_post(url, recipient, message, state, resolved_ip)
        end
    end
  end

  def handle_call({:incoming, payload, signature, raw_body}, _from, state) do
    # v22 SEC-18: Validate payload before processing
    with :ok <- validate_payload(payload),
         :ok <- verify_signature(payload, signature, state.secret, raw_body) do
      # v26 M-9: Sanitize known text fields before handler dispatch and storage
      sanitized_payload = sanitize_payload_text(payload)

      if state.handler do
        state.handler.(:webhook, sanitized_payload)
      end

      messages = Enum.take([sanitized_payload | state.messages], @max_messages)
      {:reply, {:ok, sanitized_payload}, %{state | messages: messages}}
    else
      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  # --- Private helpers ---

  # v27 H-3: Pin resolved IP in outbound POST to prevent DNS rebinding.
  # In allow_local mode (test/dev), resolved_ip is "local" — skip pinning.
  defp send_webhook_post(url, recipient, message, state, resolved_ip) do
    payload = %{recipient: recipient, message: message}

    headers =
      [{"host", URI.parse(url).host || ""}] ++
        if state.secret do
          sig = compute_signature(Jason.encode!(payload), state.secret)
          [{"x-krait-signature", sig}]
        else
          []
        end

    req_opts = build_pinned_req_opts(url, resolved_ip, headers)

    case Req.post(url, [json: payload] ++ req_opts) do
      {:ok, %{status: status}} when status in 200..299 ->
        {:reply, :ok, state}

      {:ok, %{status: status, body: body}} ->
        Logger.warning("Webhook POST failed", status: status)
        {:reply, {:error, {status, body}}, state}

      {:error, reason} ->
        Logger.warning("Webhook POST error", error: safe_error(reason))
        {:reply, {:error, reason}, state}
    end
  end

  # v27 H-3: Build Req options with IP pinning for DNS rebinding prevention
  defp build_pinned_req_opts(_url, "local", headers) do
    [headers: headers, redirect: false]
  end

  defp build_pinned_req_opts(url, resolved_ip, headers) do
    uri = URI.parse(url)
    host = uri.host || ""
    scheme = uri.scheme || "https"

    case parse_ip_to_tuple(resolved_ip) do
      nil ->
        Logger.warning("Webhook IP parse failed for pinning, using redirect: false only",
          resolved_ip: resolved_ip
        )

        [headers: headers, redirect: false]

      ip_tuple ->
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

        [headers: headers, redirect: false, connect_options: connect_opts]
    end
  end

  defp parse_ip_to_tuple(ip_string) when is_binary(ip_string) do
    case :inet.parse_address(String.to_charlist(ip_string)) do
      {:ok, ip_tuple} -> ip_tuple
      {:error, _} -> nil
    end
  end

  # v22 SEC-18: Validate payload format and size before signature verification
  @max_payload_size 65_536

  defp validate_payload(payload) when is_map(payload) do
    case Jason.encode(payload) do
      {:ok, encoded} when byte_size(encoded) <= @max_payload_size ->
        :ok

      {:ok, _} ->
        {:error, :payload_too_large}

      {:error, _} ->
        {:error, :invalid_payload_format}
    end
  end

  defp validate_payload(_), do: {:error, :invalid_payload_format}

  # No secret configured — behavior depends on environment and explicit opt-in
  defp verify_signature(_payload, _signature, nil, _raw_body) do
    cond do
      Application.get_env(:krait, :env, :dev) == :test and
          Application.get_env(:krait, :disable_webhook_auth, false) ->
        Logger.warning("[SECURITY] Webhook auth disabled (test env only)")
        :ok

      true ->
        Logger.warning("Webhook rejected: no signing secret configured",
          env: Application.get_env(:krait, :env, :dev)
        )

        {:error, :no_secret_configured}
    end
  end

  defp verify_signature(_payload, nil, _secret, _raw_body), do: {:error, :invalid_signature}

  defp verify_signature(_payload, signature, secret, raw_body) do
    if is_nil(raw_body) do
      Logger.warning("Webhook rejected: raw_body required for reliable HMAC verification")
      {:error, :raw_body_required}
    else
      expected = compute_signature(raw_body, secret)

      if Plug.Crypto.secure_compare(expected, signature) do
        :ok
      else
        {:error, :invalid_signature}
      end
    end
  end

  defp compute_signature(body, secret) do
    :crypto.mac(:hmac, :sha256, secret, body)
    |> Base.encode16(case: :lower)
  end

  # v27 M-3: Recursively sanitize ALL string values in webhook payloads.
  # Previous approach only sanitized named fields (@sanitize_fields), allowing
  # novel field names to bypass sanitization. Now every string value is sanitized.
  defp sanitize_payload_text(payload) when is_map(payload) do
    Map.new(payload, fn
      {key, value} when is_binary(value) ->
        {key, Krait.Security.PromptSanitizer.sanitize_strict(value)}

      {key, value} when is_map(value) ->
        {key, sanitize_payload_text(value)}

      {key, value} when is_list(value) ->
        {key, Enum.map(value, &sanitize_payload_text/1)}

      other ->
        other
    end)
  end

  defp sanitize_payload_text(value) when is_binary(value) do
    Krait.Security.PromptSanitizer.sanitize_strict(value)
  end

  defp sanitize_payload_text(other), do: other

  defp safe_error(%{__exception__: true} = e), do: Exception.message(e)
end
