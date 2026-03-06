defmodule Krait.LLM.ClaudeTest do
  use ExUnit.Case, async: true

  setup do
    bypass = Bypass.open()
    {:ok, bypass: bypass, base_url: "http://localhost:#{bypass.port}"}
  end

  describe "complete/2" do
    test "sends messages and returns response", %{bypass: bypass, base_url: url} do
      Bypass.expect_once(bypass, "POST", "/v1/messages", fn conn ->
        {:ok, body, conn} = Plug.Conn.read_body(conn)
        decoded = Jason.decode!(body)

        assert decoded["model"] =~ "claude"
        assert length(decoded["messages"]) > 0

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(
          200,
          Jason.encode!(%{
            "id" => "msg_123",
            "type" => "message",
            "role" => "assistant",
            "content" => [%{"type" => "text", "text" => "Hello!"}],
            "stop_reason" => "end_turn"
          })
        )
      end)

      assert {:ok, "Hello!"} =
               Krait.LLM.Claude.complete(
                 [%{role: "user", content: "Hi"}],
                 api_key: "test-key",
                 base_url: url
               )
    end

    test "returns error on HTTP failure", %{bypass: bypass, base_url: url} do
      Bypass.expect_once(bypass, "POST", "/v1/messages", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(500, Jason.encode!(%{"error" => %{"message" => "Internal error"}}))
      end)

      assert {:error, _} =
               Krait.LLM.Claude.complete(
                 [%{role: "user", content: "Hi"}],
                 api_key: "test-key",
                 base_url: url
               )
    end

    test "returns error tuple with status code on 401 unauthorized", %{
      bypass: bypass,
      base_url: url
    } do
      Bypass.expect_once(bypass, "POST", "/v1/messages", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(
          401,
          Jason.encode!(%{
            "error" => %{"type" => "authentication_error", "message" => "Invalid API key"}
          })
        )
      end)

      assert {:error, {401, body}} =
               Krait.LLM.Claude.complete(
                 [%{role: "user", content: "Hi"}],
                 api_key: "bad-key",
                 base_url: url
               )

      assert body["error"]["type"] == "authentication_error"
    end

    test "returns error tuple with status code on 429 rate limit", %{
      bypass: bypass,
      base_url: url
    } do
      Bypass.expect_once(bypass, "POST", "/v1/messages", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(
          429,
          Jason.encode!(%{
            "error" => %{"type" => "rate_limit_error", "message" => "Rate limit exceeded"}
          })
        )
      end)

      assert {:error, {429, body}} =
               Krait.LLM.Claude.complete(
                 [%{role: "user", content: "Hi"}],
                 api_key: "test-key",
                 base_url: url
               )

      assert body["error"]["type"] == "rate_limit_error"
    end

    test "returns empty string when response has no text content blocks", %{
      bypass: bypass,
      base_url: url
    } do
      Bypass.expect_once(bypass, "POST", "/v1/messages", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(
          200,
          Jason.encode!(%{
            "id" => "msg_empty",
            "type" => "message",
            "role" => "assistant",
            "content" => [],
            "stop_reason" => "end_turn"
          })
        )
      end)

      assert {:ok, ""} =
               Krait.LLM.Claude.complete(
                 [%{role: "user", content: "Hi"}],
                 api_key: "test-key",
                 base_url: url
               )
    end

    test "returns error when connection is refused", %{bypass: bypass, base_url: url} do
      Bypass.down(bypass)

      assert {:error, _reason} =
               Krait.LLM.Claude.complete(
                 [%{role: "user", content: "Hi"}],
                 api_key: "test-key",
                 base_url: url
               )
    end

    test "raises KeyError when api_key is missing" do
      assert_raise KeyError, ~r/api_key/, fn ->
        Krait.LLM.Claude.complete([%{role: "user", content: "Hi"}], [])
      end
    end
  end

  describe "complete_with_tools/3" do
    test "handles tool_use response", %{bypass: bypass, base_url: url} do
      Bypass.expect_once(bypass, "POST", "/v1/messages", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(
          200,
          Jason.encode!(%{
            "id" => "msg_456",
            "type" => "message",
            "role" => "assistant",
            "content" => [
              %{"type" => "text", "text" => "I'll check that for you."},
              %{
                "type" => "tool_use",
                "id" => "tool_1",
                "name" => "web_fetch",
                "input" => %{"url" => "https://example.com"}
              }
            ],
            "stop_reason" => "tool_use"
          })
        )
      end)

      assert {:ok, result} =
               Krait.LLM.Claude.complete_with_tools(
                 [%{role: "user", content: "fetch example.com"}],
                 [%{name: "web_fetch", description: "Fetch URL", input_schema: %{}}],
                 api_key: "test-key",
                 base_url: url
               )

      assert result.text == "I'll check that for you."
      assert [%{name: "web_fetch", id: "tool_1"}] = result.tool_calls
    end

    test "handles response with no tool calls", %{bypass: bypass, base_url: url} do
      Bypass.expect_once(bypass, "POST", "/v1/messages", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(
          200,
          Jason.encode!(%{
            "id" => "msg_789",
            "type" => "message",
            "role" => "assistant",
            "content" => [%{"type" => "text", "text" => "Just text."}],
            "stop_reason" => "end_turn"
          })
        )
      end)

      assert {:ok, result} =
               Krait.LLM.Claude.complete_with_tools(
                 [%{role: "user", content: "hello"}],
                 [],
                 api_key: "test-key",
                 base_url: url
               )

      assert result.text == "Just text."
      assert result.tool_calls == []
    end

    test "parses multiple tool calls in a single response", %{bypass: bypass, base_url: url} do
      Bypass.expect_once(bypass, "POST", "/v1/messages", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(
          200,
          Jason.encode!(%{
            "id" => "msg_multi",
            "type" => "message",
            "role" => "assistant",
            "content" => [
              %{"type" => "text", "text" => "I'll do both."},
              %{
                "type" => "tool_use",
                "id" => "t1",
                "name" => "read_file",
                "input" => %{"path" => "/a"}
              },
              %{
                "type" => "tool_use",
                "id" => "t2",
                "name" => "write_file",
                "input" => %{"path" => "/b", "content" => "x"}
              }
            ],
            "stop_reason" => "tool_use"
          })
        )
      end)

      assert {:ok, result} =
               Krait.LLM.Claude.complete_with_tools(
                 [%{role: "user", content: "read and write"}],
                 [%{name: "read_file"}, %{name: "write_file"}],
                 api_key: "test-key",
                 base_url: url
               )

      assert result.text == "I'll do both."
      assert length(result.tool_calls) == 2
      assert Enum.map(result.tool_calls, & &1.name) == ["read_file", "write_file"]
      assert Enum.map(result.tool_calls, & &1.id) == ["t1", "t2"]
    end

    test "handles tool_use response with no text blocks", %{bypass: bypass, base_url: url} do
      Bypass.expect_once(bypass, "POST", "/v1/messages", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(
          200,
          Jason.encode!(%{
            "id" => "msg_notxt",
            "type" => "message",
            "role" => "assistant",
            "content" => [
              %{
                "type" => "tool_use",
                "id" => "t1",
                "name" => "echo",
                "input" => %{"text" => "hi"}
              }
            ],
            "stop_reason" => "tool_use"
          })
        )
      end)

      assert {:ok, result} =
               Krait.LLM.Claude.complete_with_tools(
                 [%{role: "user", content: "echo hi"}],
                 [%{name: "echo"}],
                 api_key: "test-key",
                 base_url: url
               )

      assert result.text == ""
      assert length(result.tool_calls) == 1
    end

    test "returns error on 401 unauthorized", %{bypass: bypass, base_url: url} do
      Bypass.expect_once(bypass, "POST", "/v1/messages", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(401, Jason.encode!(%{"error" => %{"type" => "authentication_error"}}))
      end)

      assert {:error, {401, _body}} =
               Krait.LLM.Claude.complete_with_tools(
                 [%{role: "user", content: "Hi"}],
                 [],
                 api_key: "bad-key",
                 base_url: url
               )
    end

    test "returns error when connection is refused", %{bypass: bypass, base_url: url} do
      Bypass.down(bypass)

      assert {:error, _reason} =
               Krait.LLM.Claude.complete_with_tools(
                 [%{role: "user", content: "Hi"}],
                 [],
                 api_key: "test-key",
                 base_url: url
               )
    end

    test "handles response with null content gracefully", %{bypass: bypass, base_url: url} do
      Bypass.expect_once(bypass, "POST", "/v1/messages", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(
          200,
          Jason.encode!(%{
            "id" => "msg_null",
            "type" => "message",
            "role" => "assistant",
            "content" => nil,
            "stop_reason" => "end_turn"
          })
        )
      end)

      assert {:ok, result} =
               Krait.LLM.Claude.complete_with_tools(
                 [%{role: "user", content: "hi"}],
                 [],
                 api_key: "test-key",
                 base_url: url
               )

      assert result.text == ""
      assert result.tool_calls == []
    end

    test "preserves tool input data in parsed tool calls", %{bypass: bypass, base_url: url} do
      Bypass.expect_once(bypass, "POST", "/v1/messages", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(
          200,
          Jason.encode!(%{
            "id" => "msg_input",
            "type" => "message",
            "role" => "assistant",
            "content" => [
              %{
                "type" => "tool_use",
                "id" => "tc_1",
                "name" => "search",
                "input" => %{"query" => "elixir", "limit" => 10, "nested" => %{"key" => "val"}}
              }
            ],
            "stop_reason" => "tool_use"
          })
        )
      end)

      assert {:ok, result} =
               Krait.LLM.Claude.complete_with_tools(
                 [%{role: "user", content: "search for elixir"}],
                 [%{name: "search"}],
                 api_key: "test-key",
                 base_url: url
               )

      [tool_call] = result.tool_calls

      assert tool_call.input == %{
               "query" => "elixir",
               "limit" => 10,
               "nested" => %{"key" => "val"}
             }
    end
  end

  describe "stream/2" do
    test "returns :not_implemented error" do
      assert {:error, :not_implemented} =
               Krait.LLM.Claude.stream([%{role: "user", content: "Hi"}], api_key: "key")
    end
  end
end
