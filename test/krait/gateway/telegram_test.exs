defmodule Krait.Gateway.Channels.TelegramTest do
  use ExUnit.Case, async: false

  alias Krait.Gateway.Channels.Telegram

  setup do
    bypass = Bypass.open()
    {:ok, bypass: bypass, base_url: "http://localhost:#{bypass.port}"}
  end

  test "sends a message via Telegram API", %{bypass: bypass, base_url: url} do
    Bypass.expect_once(bypass, "POST", "/botTEST_TOKEN/sendMessage", fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      decoded = Jason.decode!(body)
      assert decoded["chat_id"] == "123"
      assert decoded["text"] =~ "Hello"

      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.resp(200, Jason.encode!(%{ok: true, result: %{message_id: 1}}))
    end)

    {:ok, pid} =
      Telegram.start_link(
        token: "TEST_TOKEN",
        base_url: url
      )

    assert :ok = Telegram.send_message(pid, "123", "Hello from Krait!")
  end

  test "returns error when API fails", %{bypass: bypass, base_url: url} do
    Bypass.expect_once(bypass, "POST", "/botTEST_TOKEN/sendMessage", fn conn ->
      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.resp(400, Jason.encode!(%{ok: false, description: "Bad Request"}))
    end)

    {:ok, pid} =
      Telegram.start_link(
        token: "TEST_TOKEN",
        base_url: url
      )

    assert {:error, _} = Telegram.send_message(pid, "123", "Hello")
  end

  describe "v22 SEC-11: crash log redaction" do
    test "format_status redacts token from :sys.get_status output", %{base_url: url} do
      {:ok, pid} =
        Telegram.start_link(
          token: "SECRET_BOT_TOKEN_12345",
          base_url: url
        )

      {:status, _pid, _mod, [_pdict, _sysstate, _parent, _debug, misc]} = :sys.get_status(pid)
      status_str = inspect(misc)

      refute status_str =~ "SECRET_BOT_TOKEN_12345"
      # v24 F-17: Token is a closure — shows as #Function<...> in inspect
      assert status_str =~ "Function"
    end

    test "GenServer still works after format_status is defined", %{bypass: bypass, base_url: url} do
      Bypass.expect_once(bypass, "POST", "/botREDACT_TEST/sendMessage", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(200, Jason.encode!(%{ok: true, result: %{message_id: 1}}))
      end)

      {:ok, pid} =
        Telegram.start_link(
          token: "REDACT_TEST",
          base_url: url
        )

      assert :ok = Telegram.send_message(pid, "123", "test")
    end
  end

  describe "polling" do
    test "polls for updates and calls handler", %{bypass: bypass, base_url: url} do
      test_pid = self()

      Bypass.expect(bypass, "GET", "/botTEST_TOKEN/getUpdates", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(
          200,
          Jason.encode!(%{
            ok: true,
            result: [
              %{
                update_id: 100,
                message: %{
                  message_id: 1,
                  chat: %{id: 42, type: "private"},
                  text: "Hello bot"
                }
              }
            ]
          })
        )
      end)

      handler = fn channel_type, chat_id, text ->
        send(test_pid, {:received, channel_type, chat_id, text})
      end

      {:ok, pid} =
        Telegram.start_link(
          token: "TEST_TOKEN",
          base_url: url,
          handler: handler,
          poll_interval: 50
        )

      Telegram.start_polling(pid)

      assert_receive {:received, :telegram, "42", "Hello bot"}, 2_000

      Telegram.stop_polling(pid)
    end

    test "handles empty updates gracefully", %{bypass: bypass, base_url: url} do
      Bypass.expect(bypass, "GET", "/botTEST_TOKEN/getUpdates", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(200, Jason.encode!(%{ok: true, result: []}))
      end)

      {:ok, pid} =
        Telegram.start_link(
          token: "TEST_TOKEN",
          base_url: url,
          poll_interval: 50
        )

      Telegram.start_polling(pid)
      Process.sleep(200)
      Telegram.stop_polling(pid)

      # If we get here without crashing, the test passes
      assert Process.alive?(pid)
    end
  end
end
