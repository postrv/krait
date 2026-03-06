defmodule Krait.Gateway.V25TelegramTest do
  use ExUnit.Case, async: true

  alias Krait.Gateway.Channels.Telegram

  describe "v25 M-7: persistent_term token storage" do
    test "token is stored in persistent_term and accessible via closure" do
      {:ok, pid} = Telegram.start_link(token: "test_token_123", auto_poll: false)
      state = :sys.get_state(pid)

      # Token closure should return the token
      assert state.token.() == "test_token_123"

      # persistent_term key should be set
      pt_key = state.token_pt_key
      assert :persistent_term.get(pt_key) == "test_token_123"

      GenServer.stop(pid)
    end

    test "persistent_term is cleaned up on process stop" do
      {:ok, pid} = Telegram.start_link(token: "cleanup_test", auto_poll: false)
      state = :sys.get_state(pid)
      pt_key = state.token_pt_key

      # Key exists while process is alive
      assert :persistent_term.get(pt_key) == "cleanup_test"

      GenServer.stop(pid)

      # Key should be cleaned up after stop
      assert_raise ArgumentError, fn ->
        :persistent_term.get(pt_key)
      end
    end

    test "format_status redacts token in sys status" do
      {:ok, pid} = Telegram.start_link(token: "secret_token", auto_poll: false)
      {:status, _pid, _mod, status_data} = :sys.get_status(pid)

      # The status data is a list; the formatted state map is the last item
      # in the innermost list (format: [..., [header, data, state_map]])
      inner = List.last(status_data)
      formatted_state = Enum.find(inner, &is_map/1)
      assert formatted_state != nil
      # format_status replaces the real token closure with a redacted one
      assert formatted_state.token.() == "**redacted**"

      GenServer.stop(pid)
    end
  end
end
