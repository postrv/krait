defmodule Krait.Gateway.ConsoleChannelTest do
  use ExUnit.Case, async: false

  alias Krait.Gateway.Channels.Console

  import Mox

  setup :set_mox_from_context
  setup :verify_on_exit!

  test "receives message and routes to brain, returns response" do
    Krait.LLM.Mock
    |> expect(:complete_with_tools, fn _msgs, _tools, _opts ->
      {:ok, %{text: "I'm Krait!", tool_calls: []}}
    end)

    {:ok, channel} =
      Console.start_link(brain_opts: [llm: Krait.LLM.Mock, session_id: "console-test-1"])

    assert {:ok, "I'm Krait!"} =
             Console.send_user_message(channel, "Who are you?")
  end

  test "handles multiple sequential messages" do
    Krait.LLM.Mock
    |> expect(:complete_with_tools, fn msgs, _tools, _opts ->
      user_msg = List.last(msgs)
      assert user_msg["content"] =~ "first"
      {:ok, %{text: "Got first!", tool_calls: []}}
    end)
    |> expect(:complete_with_tools, fn msgs, _tools, _opts ->
      user_msg = List.last(msgs)
      assert user_msg["content"] =~ "second"
      {:ok, %{text: "Got second!", tool_calls: []}}
    end)

    {:ok, channel} =
      Console.start_link(brain_opts: [llm: Krait.LLM.Mock, session_id: "console-test-2"])

    assert {:ok, "Got first!"} =
             Console.send_user_message(channel, "first")

    assert {:ok, "Got second!"} =
             Console.send_user_message(channel, "second")
  end

  test "returns error when brain errors" do
    Krait.LLM.Mock
    |> expect(:complete_with_tools, fn _msgs, _tools, _opts ->
      {:error, :api_down}
    end)

    {:ok, channel} =
      Console.start_link(brain_opts: [llm: Krait.LLM.Mock, session_id: "console-test-3"])

    assert {:error, :api_down} = Console.send_user_message(channel, "Hi")
  end
end
