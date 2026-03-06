defmodule Krait.Gateway.Channels.WebhookTest do
  use ExUnit.Case, async: false

  describe "channel_type/0" do
    test "returns :webhook" do
      assert :webhook = Krait.Gateway.Channels.Webhook.channel_type()
    end
  end

  describe "send_message/3 without webhook_url" do
    test "stores message locally" do
      {:ok, pid} = Krait.Gateway.Channels.Webhook.start_link([])
      assert :ok = Krait.Gateway.Channels.Webhook.send_message(pid, "chan1", "Hello")
    end
  end

  describe "send_message/3 with webhook_url" do
    setup do
      bypass = Bypass.open()
      {:ok, bypass: bypass, url: "http://localhost:#{bypass.port}/webhook"}
    end

    test "POSTs to configured webhook URL", %{bypass: bypass, url: url} do
      Bypass.expect_once(bypass, "POST", "/webhook", fn conn ->
        {:ok, body, conn} = Plug.Conn.read_body(conn)
        decoded = Jason.decode!(body)
        assert decoded["recipient"] == "chan1"
        assert decoded["message"] == "Hello webhook"

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(200, Jason.encode!(%{ok: true}))
      end)

      {:ok, pid} = Krait.Gateway.Channels.Webhook.start_link(webhook_url: url)
      assert :ok = Krait.Gateway.Channels.Webhook.send_message(pid, "chan1", "Hello webhook")
    end

    test "includes HMAC signature when secret is configured", %{bypass: bypass, url: url} do
      secret = "test_secret_key"

      Bypass.expect_once(bypass, "POST", "/webhook", fn conn ->
        sig =
          Enum.find_value(conn.req_headers, fn
            {"x-krait-signature", v} -> v
            _ -> nil
          end)

        assert sig != nil
        assert is_binary(sig)

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(200, Jason.encode!(%{ok: true}))
      end)

      {:ok, pid} = Krait.Gateway.Channels.Webhook.start_link(webhook_url: url, secret: secret)
      assert :ok = Krait.Gateway.Channels.Webhook.send_message(pid, "chan1", "Signed message")
    end

    test "returns error on HTTP failure", %{bypass: bypass, url: url} do
      Bypass.expect_once(bypass, "POST", "/webhook", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(500, Jason.encode!(%{error: "Internal Server Error"}))
      end)

      {:ok, pid} = Krait.Gateway.Channels.Webhook.start_link(webhook_url: url)
      assert {:error, _} = Krait.Gateway.Channels.Webhook.send_message(pid, "chan1", "Fail")
    end
  end

  describe "message cap (M-6)" do
    test "caps stored messages at 1000" do
      {:ok, pid} = Krait.Gateway.Channels.Webhook.start_link([])

      for i <- 1..1001 do
        Krait.Gateway.Channels.Webhook.send_message(pid, "chan1", "msg-#{i}")
      end

      state = :sys.get_state(pid)
      assert length(state.messages) == 1000
    end

    test "most recent message is preserved after cap" do
      {:ok, pid} = Krait.Gateway.Channels.Webhook.start_link([])

      for i <- 1..1001 do
        Krait.Gateway.Channels.Webhook.send_message(pid, "chan1", "msg-#{i}")
      end

      state = :sys.get_state(pid)
      # Newest-first: first element should be the most recent
      assert {"chan1", "msg-1001"} == hd(state.messages)
    end

    test "incoming webhook messages are also capped" do
      prev = Application.get_env(:krait, :disable_webhook_auth)
      Application.put_env(:krait, :disable_webhook_auth, true)

      on_exit(fn ->
        if prev,
          do: Application.put_env(:krait, :disable_webhook_auth, prev),
          else: Application.delete_env(:krait, :disable_webhook_auth)
      end)

      {:ok, pid} = Krait.Gateway.Channels.Webhook.start_link([])

      for i <- 1..1001 do
        Krait.Gateway.Channels.Webhook.process_incoming(pid, %{"i" => i})
      end

      state = :sys.get_state(pid)
      assert length(state.messages) == 1000
    end
  end

  describe "process_incoming/3" do
    setup do
      # Ensure webhook auth bypass is enabled for these tests (test env default)
      prev = Application.get_env(:krait, :disable_webhook_auth)
      Application.put_env(:krait, :disable_webhook_auth, true)

      on_exit(fn ->
        if prev,
          do: Application.put_env(:krait, :disable_webhook_auth, prev),
          else: Application.delete_env(:krait, :disable_webhook_auth)
      end)

      :ok
    end

    test "accepts payload without signature when no secret configured" do
      {:ok, pid} = Krait.Gateway.Channels.Webhook.start_link([])

      assert {:ok, payload} =
               Krait.Gateway.Channels.Webhook.process_incoming(pid, %{
                 "source" => "slack",
                 "text" => "Hello"
               })

      assert payload["source"] == "slack"
    end

    test "rejects payload without signature when secret is configured" do
      {:ok, pid} = Krait.Gateway.Channels.Webhook.start_link(secret: "my_secret")

      assert {:error, :invalid_signature} =
               Krait.Gateway.Channels.Webhook.process_incoming(pid, %{"text" => "sneaky"})
    end

    test "accepts payload with valid HMAC signature and raw_body" do
      secret = "my_secret"
      payload = %{"text" => "legit"}
      body = Jason.encode!(payload)

      sig =
        :crypto.mac(:hmac, :sha256, secret, body)
        |> Base.encode16(case: :lower)

      {:ok, pid} = Krait.Gateway.Channels.Webhook.start_link(secret: secret)

      assert {:ok, _} =
               Krait.Gateway.Channels.Webhook.process_incoming(pid, payload, sig, body)
    end

    test "calls handler on valid incoming message" do
      test_pid = self()

      handler = fn _channel_type, payload ->
        send(test_pid, {:webhook_received, payload})
      end

      {:ok, pid} = Krait.Gateway.Channels.Webhook.start_link(handler: handler)

      Krait.Gateway.Channels.Webhook.process_incoming(pid, %{"text" => "handler test"})

      assert_receive {:webhook_received, %{"text" => "handler test"}}
    end

    test "verifies HMAC over raw body bytes when provided" do
      secret = "my_secret"
      # Use specific key ordering that differs from what Jason.encode! produces
      raw_body = ~s|{"text":"legit","extra":"data"}|
      payload = Jason.decode!(raw_body)

      sig =
        :crypto.mac(:hmac, :sha256, secret, raw_body)
        |> Base.encode16(case: :lower)

      {:ok, pid} = Krait.Gateway.Channels.Webhook.start_link(secret: secret)

      assert {:ok, _} =
               Krait.Gateway.Channels.Webhook.process_incoming(pid, payload, sig, raw_body)
    end

    test "rejects invalid HMAC when raw body is provided" do
      secret = "my_secret"
      raw_body = ~s|{"text":"legit"}|
      payload = Jason.decode!(raw_body)

      # Sign with different body
      sig =
        :crypto.mac(:hmac, :sha256, secret, "tampered")
        |> Base.encode16(case: :lower)

      {:ok, pid} = Krait.Gateway.Channels.Webhook.start_link(secret: secret)

      assert {:error, :invalid_signature} =
               Krait.Gateway.Channels.Webhook.process_incoming(pid, payload, sig, raw_body)
    end

    test "3-arg process_incoming (no raw_body) returns error when secret is configured" do
      secret = "my_secret"
      payload = %{"text" => "legit"}
      body = Jason.encode!(payload)

      sig =
        :crypto.mac(:hmac, :sha256, secret, body)
        |> Base.encode16(case: :lower)

      {:ok, pid} = Krait.Gateway.Channels.Webhook.start_link(secret: secret)

      # Without raw_body, fail-closed even with valid signature
      assert {:error, :raw_body_required} =
               Krait.Gateway.Channels.Webhook.process_incoming(pid, payload, sig)
    end

    test "in prod, nil raw_body returns error (fail-closed)" do
      original_env = Application.get_env(:krait, :env)
      Application.put_env(:krait, :env, :prod)

      on_exit(fn ->
        if original_env do
          Application.put_env(:krait, :env, original_env)
        else
          Application.delete_env(:krait, :env)
        end
      end)

      secret = "my_secret"
      payload = %{"text" => "legit"}
      body = Jason.encode!(payload)

      sig =
        :crypto.mac(:hmac, :sha256, secret, body)
        |> Base.encode16(case: :lower)

      {:ok, pid} = Krait.Gateway.Channels.Webhook.start_link(secret: secret)

      # Pass signature but no raw_body — in prod this should fail-closed
      assert {:error, :raw_body_required} =
               Krait.Gateway.Channels.Webhook.process_incoming(pid, payload, sig)
    end

    test "in any env, nil raw_body returns error (no fallback to re-serialization)" do
      secret = "my_secret"
      payload = %{"text" => "legit"}
      body = Jason.encode!(payload)

      sig =
        :crypto.mac(:hmac, :sha256, secret, body)
        |> Base.encode16(case: :lower)

      {:ok, pid} = Krait.Gateway.Channels.Webhook.start_link(secret: secret)

      # Without raw_body — should fail-closed in ALL environments
      assert {:error, :raw_body_required} =
               Krait.Gateway.Channels.Webhook.process_incoming(pid, payload, sig)
    end

    test "rejects unsigned webhooks in prod mode when no secret configured" do
      original_env = Application.get_env(:krait, :env)
      Application.put_env(:krait, :env, :prod)

      on_exit(fn ->
        if original_env do
          Application.put_env(:krait, :env, original_env)
        else
          Application.delete_env(:krait, :env)
        end
      end)

      {:ok, pid} = Krait.Gateway.Channels.Webhook.start_link([])

      assert {:error, :no_secret_configured} =
               Krait.Gateway.Channels.Webhook.process_incoming(pid, %{"text" => "unsigned"})
    end
  end

  describe "v22 SEC-18: payload validation" do
    test "rejects non-map payloads (list)" do
      Application.put_env(:krait, :disable_webhook_auth, true)
      on_exit(fn -> Application.delete_env(:krait, :disable_webhook_auth) end)

      {:ok, pid} = Krait.Gateway.Channels.Webhook.start_link([])

      assert {:error, :invalid_payload_format} =
               Krait.Gateway.Channels.Webhook.process_incoming(pid, ["not", "a", "map"])
    end

    test "rejects non-map payloads (string)" do
      Application.put_env(:krait, :disable_webhook_auth, true)
      on_exit(fn -> Application.delete_env(:krait, :disable_webhook_auth) end)

      {:ok, pid} = Krait.Gateway.Channels.Webhook.start_link([])

      assert {:error, :invalid_payload_format} =
               Krait.Gateway.Channels.Webhook.process_incoming(pid, "just a string")
    end

    test "rejects non-map payloads (integer)" do
      Application.put_env(:krait, :disable_webhook_auth, true)
      on_exit(fn -> Application.delete_env(:krait, :disable_webhook_auth) end)

      {:ok, pid} = Krait.Gateway.Channels.Webhook.start_link([])

      assert {:error, :invalid_payload_format} =
               Krait.Gateway.Channels.Webhook.process_incoming(pid, 42)
    end

    test "rejects oversized payloads" do
      Application.put_env(:krait, :disable_webhook_auth, true)
      on_exit(fn -> Application.delete_env(:krait, :disable_webhook_auth) end)

      {:ok, pid} = Krait.Gateway.Channels.Webhook.start_link([])

      # Create a map payload that serializes to > 64KB
      large_value = String.duplicate("x", 70_000)
      large_payload = %{"data" => large_value}

      assert {:error, :payload_too_large} =
               Krait.Gateway.Channels.Webhook.process_incoming(pid, large_payload)
    end

    test "accepts valid map payload" do
      Application.put_env(:krait, :disable_webhook_auth, true)
      on_exit(fn -> Application.delete_env(:krait, :disable_webhook_auth) end)

      {:ok, pid} = Krait.Gateway.Channels.Webhook.start_link([])

      assert {:ok, %{"action" => "test"}} =
               Krait.Gateway.Channels.Webhook.process_incoming(pid, %{"action" => "test"})
    end
  end
end
