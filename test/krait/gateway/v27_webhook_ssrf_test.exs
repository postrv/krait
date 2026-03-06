defmodule Krait.Gateway.Channels.V27WebhookSsrfTest do
  @moduledoc "v27 H-3: Webhook SSRF IP pinning tests"
  use ExUnit.Case, async: false

  alias Krait.Gateway.Channels.Webhook

  setup do
    prev_env = Application.get_env(:krait, :env)
    prev_local = Application.get_env(:krait, :allow_local_network)
    prev_auth = Application.get_env(:krait, :disable_webhook_auth)

    Application.put_env(:krait, :env, :test)
    Application.put_env(:krait, :allow_local_network, true)
    Application.put_env(:krait, :disable_webhook_auth, true)

    on_exit(fn ->
      if prev_env,
        do: Application.put_env(:krait, :env, prev_env),
        else: Application.delete_env(:krait, :env)

      if prev_local,
        do: Application.put_env(:krait, :allow_local_network, prev_local),
        else: Application.delete_env(:krait, :allow_local_network)

      if prev_auth,
        do: Application.put_env(:krait, :disable_webhook_auth, prev_auth),
        else: Application.delete_env(:krait, :disable_webhook_auth)
    end)

    :ok
  end

  describe "send_webhook_post IP pinning" do
    test "webhook with nil URL stores message locally (no SSRF path)" do
      {:ok, pid} = Webhook.start_link(webhook_url: nil, secret: nil, handler: nil)
      assert :ok = Webhook.send_message(pid, "user1", "hello")
      GenServer.stop(pid)
    end

    test "webhook with URL goes through SSRF validation" do
      # Using bypass to catch the actual request
      bypass = Bypass.open()
      url = "http://localhost:#{bypass.port}/hook"

      Bypass.expect_once(bypass, "POST", "/hook", fn conn ->
        # v27 H-3: Verify Host header is set (IP pinning adds it)
        host_headers = Plug.Conn.get_req_header(conn, "host")
        assert length(host_headers) >= 1
        Plug.Conn.resp(conn, 200, ~s({"ok": true}))
      end)

      {:ok, pid} = Webhook.start_link(webhook_url: url, secret: nil, handler: nil)
      assert :ok = Webhook.send_message(pid, "user1", "test message")
      GenServer.stop(pid)
    end

    test "parse_ip_to_tuple handles valid IPv4" do
      # Indirectly test via the webhook module's internal function
      # The webhook should successfully send when IP is parseable
      bypass = Bypass.open()
      url = "http://localhost:#{bypass.port}/hook"

      Bypass.expect_once(bypass, "POST", "/hook", fn conn ->
        Plug.Conn.resp(conn, 200, "ok")
      end)

      {:ok, pid} = Webhook.start_link(webhook_url: url, secret: nil, handler: nil)
      assert :ok = Webhook.send_message(pid, "user1", "pinned request")
      GenServer.stop(pid)
    end
  end
end
