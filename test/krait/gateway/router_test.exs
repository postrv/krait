defmodule Krait.Gateway.RouterTest do
  use ExUnit.Case, async: false

  import Mox

  setup :set_mox_from_context
  setup :verify_on_exit!

  setup do
    # Configure LLM mock for Brain instances created by the router
    Krait.LLM.Mock
    |> stub(:complete_with_tools, fn _messages, _tools, _opts ->
      {:ok, %{text: "Hello from brain!", tool_calls: []}}
    end)

    {:ok, router} =
      Krait.Gateway.Router.start_link(
        name: :"router_test_#{System.unique_integer([:positive])}",
        brain_opts: [llm: Krait.LLM.Mock, skills: []]
      )

    %{router: router}
  end

  describe "route_message/4" do
    test "creates a Brain instance for new conversations", %{router: router} do
      assert {:ok, response} =
               Krait.Gateway.Router.route_message(router, :telegram, "chat_123", "hello")

      assert is_binary(response)
    end

    test "reuses Brain for same conversation", %{router: router} do
      {:ok, _} = Krait.Gateway.Router.route_message(router, :telegram, "chat_123", "first")
      {:ok, _} = Krait.Gateway.Router.route_message(router, :telegram, "chat_123", "second")

      convos = Krait.Gateway.Router.list_conversations(router)
      telegram_convos = Enum.filter(convos, &(&1.channel == :telegram))
      assert length(telegram_convos) == 1
    end

    test "creates separate Brains for different conversations", %{router: router} do
      {:ok, _} = Krait.Gateway.Router.route_message(router, :telegram, "chat_1", "hi")
      {:ok, _} = Krait.Gateway.Router.route_message(router, :telegram, "chat_2", "hi")

      convos = Krait.Gateway.Router.list_conversations(router)
      assert length(convos) == 2
    end

    test "creates separate Brains for different channels", %{router: router} do
      {:ok, _} = Krait.Gateway.Router.route_message(router, :telegram, "123", "hi")
      {:ok, _} = Krait.Gateway.Router.route_message(router, :webhook, "123", "hi")

      convos = Krait.Gateway.Router.list_conversations(router)
      assert length(convos) == 2
    end
  end

  describe "register_channel/3" do
    test "registers a channel", %{router: router} do
      assert :ok = Krait.Gateway.Router.register_channel(router, :telegram, self())
    end
  end

  describe "list_conversations/1" do
    test "returns empty list initially", %{router: router} do
      assert [] = Krait.Gateway.Router.list_conversations(router)
    end

    test "returns conversation info after routing", %{router: router} do
      {:ok, _} = Krait.Gateway.Router.route_message(router, :telegram, "chat_42", "hi")

      convos = Krait.Gateway.Router.list_conversations(router)
      assert length(convos) == 1
      assert hd(convos).channel == :telegram
      assert hd(convos).conversation_id == "chat_42"
      assert is_pid(hd(convos).brain_pid)
    end
  end

  describe "conversation sweeping" do
    test "dead process removed on sweep" do
      # The router links to brain processes via start_link. When a brain
      # is killed, the router also dies unless it traps exits. Instead of
      # killing the brain, we'll start a separate process and inject it
      # into the conversation map to simulate a dead process.

      {:ok, router} =
        Krait.Gateway.Router.start_link(
          name: :"router_sweep_test_#{System.unique_integer([:positive])}",
          brain_opts: [llm: Krait.LLM.Mock, skills: []],
          sweep_interval: 0
        )

      # Start a standalone process that will die on its own
      {:ok, dead_pid} = Task.start(fn -> :ok end)
      # Wait for it to finish
      Process.sleep(50)
      refute Process.alive?(dead_pid)

      # Manually inject the dead pid into the router's conversation state
      :sys.replace_state(router, fn state ->
        %{
          state
          | conversations: Map.put(state.conversations, {:telegram, "dead_chat"}, dead_pid),
            last_activity:
              Map.put(
                state.last_activity,
                {:telegram, "dead_chat"},
                System.monotonic_time(:millisecond)
              )
        }
      end)

      # Verify it's in the conversation list
      assert length(Krait.Gateway.Router.list_conversations(router)) == 1

      # Trigger sweep
      send(router, :sweep_conversations)
      Process.sleep(50)

      convos = Krait.Gateway.Router.list_conversations(router)
      assert convos == []
    end

    test "active conversation preserved on sweep" do
      {:ok, router} =
        Krait.Gateway.Router.start_link(
          name: :"router_active_test_#{System.unique_integer([:positive])}",
          brain_opts: [llm: Krait.LLM.Mock, skills: []],
          sweep_interval: 0
        )

      {:ok, _} = Krait.Gateway.Router.route_message(router, :telegram, "active_chat", "hi")

      # Trigger sweep — conversation should still be there
      send(router, :sweep_conversations)
      Process.sleep(50)

      convos = Krait.Gateway.Router.list_conversations(router)
      assert length(convos) == 1
    end
  end
end
