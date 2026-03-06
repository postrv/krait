defmodule Krait.Gateway.V25WebhookSsrfTest do
  use ExUnit.Case, async: false

  describe "v25 M-3: webhook SSRF protection" do
    setup do
      # Disable allow_local to test SSRF blocking
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

    test "blocks webhook URL pointing to internal IP" do
      {:ok, pid} =
        Krait.Gateway.Channels.Webhook.start_link(
          webhook_url: "http://169.254.169.254/latest/meta-data/"
        )

      assert {:error, {:ssrf_blocked, msg}} =
               Krait.Gateway.Channels.Webhook.send_message(pid, "chan1", "test")

      assert msg =~ "SSRF blocked"
    end

    test "blocks webhook URL with non-standard port" do
      {:ok, pid} =
        Krait.Gateway.Channels.Webhook.start_link(webhook_url: "http://example.com:9999/webhook")

      assert {:error, {:ssrf_blocked, msg}} =
               Krait.Gateway.Channels.Webhook.send_message(pid, "chan1", "test")

      assert msg =~ "non-standard port"
    end
  end
end
