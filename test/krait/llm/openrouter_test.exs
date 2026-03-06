defmodule Krait.LLM.OpenRouterTest do
  use ExUnit.Case, async: true

  alias Krait.LLM.OpenRouter

  setup do
    bypass = Bypass.open()
    base_url = "http://localhost:#{bypass.port}"
    {:ok, bypass: bypass, base_url: base_url, opts: [api_key: "test-key", base_url: base_url]}
  end

  describe "complete/2" do
    test "sends correct request and parses text response", %{bypass: bypass, opts: opts} do
      Bypass.expect_once(bypass, "POST", "/chat/completions", fn conn ->
        {:ok, body, conn} = Plug.Conn.read_body(conn)
        decoded = Jason.decode!(body)

        assert Plug.Conn.get_req_header(conn, "authorization") == ["Bearer test-key"]
        assert decoded["model"] == "anthropic/claude-sonnet-4.5"
        assert is_list(decoded["messages"])

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(
          200,
          Jason.encode!(%{
            "choices" => [
              %{
                "index" => 0,
                "message" => %{"role" => "assistant", "content" => "Hello!"},
                "finish_reason" => "stop"
              }
            ],
            "usage" => %{"prompt_tokens" => 10, "completion_tokens" => 5, "cost" => 0.00015}
          })
        )
      end)

      assert {:ok, "Hello!"} =
               OpenRouter.complete([%{"role" => "user", "content" => "Hi"}], opts)
    end

    test "returns error on 401 unauthorized", %{bypass: bypass, opts: opts} do
      Bypass.expect_once(bypass, "POST", "/chat/completions", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(
          401,
          Jason.encode!(%{"error" => %{"message" => "Invalid API key"}})
        )
      end)

      assert {:error, {:openrouter_error, 401, _}} =
               OpenRouter.complete([%{"role" => "user", "content" => "Hi"}], opts)
    end

    test "returns insufficient_credits on 402", %{bypass: bypass, opts: opts} do
      Bypass.expect_once(bypass, "POST", "/chat/completions", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(
          402,
          Jason.encode!(%{"error" => %{"message" => "Insufficient credits"}})
        )
      end)

      assert {:error, {:insufficient_credits, _}} =
               OpenRouter.complete([%{"role" => "user", "content" => "Hi"}], opts)
    end

    test "returns error on 500", %{bypass: bypass, opts: opts} do
      Bypass.expect_once(bypass, "POST", "/chat/completions", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(500, Jason.encode!(%{"error" => "Internal error"}))
      end)

      assert {:error, {:openrouter_error, 500, _}} =
               OpenRouter.complete([%{"role" => "user", "content" => "Hi"}], opts)
    end

    test "returns error when connection is refused", %{bypass: bypass, opts: opts} do
      Bypass.down(bypass)

      assert {:error, _} =
               OpenRouter.complete([%{"role" => "user", "content" => "Hi"}], opts)
    end

    test "raises KeyError when api_key is missing" do
      assert_raise KeyError, ~r/api_key/, fn ->
        OpenRouter.complete([%{"role" => "user", "content" => "Hi"}], [])
      end
    end
  end

  describe "complete_with_tools/3" do
    test "transforms tools to OpenAI format and parses tool_calls response", %{
      bypass: bypass,
      opts: opts
    } do
      Bypass.expect_once(bypass, "POST", "/chat/completions", fn conn ->
        {:ok, body, conn} = Plug.Conn.read_body(conn)
        decoded = Jason.decode!(body)

        # Verify tool format is OpenAI-compatible
        [tool] = decoded["tools"]
        assert tool["type"] == "function"
        assert tool["function"]["name"] == "get_weather"
        assert tool["function"]["parameters"]["type"] == "object"

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(
          200,
          Jason.encode!(%{
            "choices" => [
              %{
                "index" => 0,
                "message" => %{
                  "role" => "assistant",
                  "content" => "",
                  "tool_calls" => [
                    %{
                      "id" => "call_123",
                      "type" => "function",
                      "function" => %{
                        "name" => "get_weather",
                        "arguments" => ~S|{"location": "London"}|
                      }
                    }
                  ]
                },
                "finish_reason" => "tool_calls"
              }
            ],
            "usage" => %{"prompt_tokens" => 20, "completion_tokens" => 10, "cost" => 0.0003}
          })
        )
      end)

      tools = [
        %{
          "name" => "get_weather",
          "description" => "Get weather for a location",
          "input_schema" => %{
            "type" => "object",
            "properties" => %{"location" => %{"type" => "string"}}
          }
        }
      ]

      assert {:ok, result} =
               OpenRouter.complete_with_tools(
                 [%{"role" => "user", "content" => "Weather in London?"}],
                 tools,
                 opts
               )

      assert result.text == ""
      assert [tool_call] = result.tool_calls
      assert tool_call.id == "call_123"
      assert tool_call.name == "get_weather"
      assert tool_call.input == %{"location" => "London"}
      assert result.cost == 0.0003
    end

    test "handles tool_call with already-parsed map arguments", %{bypass: bypass, opts: opts} do
      Bypass.expect_once(bypass, "POST", "/chat/completions", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(
          200,
          Jason.encode!(%{
            "choices" => [
              %{
                "message" => %{
                  "role" => "assistant",
                  "content" => "Using tool",
                  "tool_calls" => [
                    %{
                      "id" => "call_456",
                      "type" => "function",
                      "function" => %{"name" => "calc", "arguments" => %{"x" => 42}}
                    }
                  ]
                }
              }
            ]
          })
        )
      end)

      assert {:ok, result} =
               OpenRouter.complete_with_tools(
                 [%{"role" => "user", "content" => "Calculate"}],
                 [%{"name" => "calc", "description" => "calc", "input_schema" => %{}}],
                 opts
               )

      assert result.tool_calls |> hd() |> Map.get(:input) == %{"x" => 42}
    end

    test "handles response with no tool calls", %{bypass: bypass, opts: opts} do
      Bypass.expect_once(bypass, "POST", "/chat/completions", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(
          200,
          Jason.encode!(%{
            "choices" => [
              %{"message" => %{"role" => "assistant", "content" => "Just text."}}
            ]
          })
        )
      end)

      assert {:ok, result} =
               OpenRouter.complete_with_tools(
                 [%{"role" => "user", "content" => "hello"}],
                 [],
                 opts
               )

      assert result.text == "Just text."
      assert result.tool_calls == []
    end
  end

  describe "model fallback" do
    test "sends models list and route: fallback in body", %{bypass: bypass, opts: opts} do
      Bypass.expect_once(bypass, "POST", "/chat/completions", fn conn ->
        {:ok, body, conn} = Plug.Conn.read_body(conn)
        decoded = Jason.decode!(body)

        assert decoded["models"] == ["anthropic/claude-sonnet-4.5", "openai/gpt-4o"]
        assert decoded["route"] == "fallback"

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(
          200,
          Jason.encode!(%{
            "choices" => [%{"message" => %{"content" => "ok"}}]
          })
        )
      end)

      assert {:ok, "ok"} =
               OpenRouter.complete(
                 [%{"role" => "user", "content" => "test"}],
                 opts ++ [models: ["anthropic/claude-sonnet-4.5", "openai/gpt-4o"]]
               )
    end
  end

  describe "provider preferences" do
    test "sends provider preferences in body", %{bypass: bypass, opts: opts} do
      Bypass.expect_once(bypass, "POST", "/chat/completions", fn conn ->
        {:ok, body, conn} = Plug.Conn.read_body(conn)
        decoded = Jason.decode!(body)

        assert decoded["provider"]["order"] == ["anthropic", "google"]
        assert decoded["provider"]["data_collection"] == "deny"

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(
          200,
          Jason.encode!(%{
            "choices" => [%{"message" => %{"content" => "ok"}}]
          })
        )
      end)

      assert {:ok, "ok"} =
               OpenRouter.complete(
                 [%{"role" => "user", "content" => "test"}],
                 opts ++
                   [
                     provider: %{order: ["anthropic", "google"]},
                     default_provider: %{data_collection: "deny"}
                   ]
               )
    end
  end

  describe "cost tracking" do
    test "parses cost from usage in response", %{bypass: bypass, opts: opts} do
      Bypass.expect_once(bypass, "POST", "/chat/completions", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(
          200,
          Jason.encode!(%{
            "choices" => [
              %{"message" => %{"role" => "assistant", "content" => "answer"}}
            ],
            "usage" => %{
              "prompt_tokens" => 100,
              "completion_tokens" => 50,
              "total_tokens" => 150,
              "cost" => 0.0025
            }
          })
        )
      end)

      assert {:ok, result} =
               OpenRouter.complete_with_tools(
                 [%{"role" => "user", "content" => "test"}],
                 [],
                 opts
               )

      assert result.cost == 0.0025
    end
  end

  describe "check_credits/1" do
    test "returns balance info", %{bypass: bypass, opts: opts} do
      Bypass.expect_once(bypass, "GET", "/key", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(
          200,
          Jason.encode!(%{
            "data" => %{
              "balance" => 10.50,
              "limit" => 100.0,
              "usage" => 89.50,
              "limit_remaining" => 10.50
            }
          })
        )
      end)

      assert {:ok, credits} = OpenRouter.check_credits(opts)
      assert credits.balance == 10.50
      assert credits.limit == 100.0
      assert credits.usage == 89.50
      assert credits.limit_remaining == 10.50
    end

    test "returns error on failure", %{bypass: bypass, opts: opts} do
      Bypass.expect_once(bypass, "GET", "/key", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(401, Jason.encode!(%{"error" => "invalid key"}))
      end)

      assert {:error, {401, _}} = OpenRouter.check_credits(opts)
    end
  end

  describe "message normalization" do
    test "passes through simple string messages", %{bypass: bypass, opts: opts} do
      Bypass.expect_once(bypass, "POST", "/chat/completions", fn conn ->
        {:ok, body, conn} = Plug.Conn.read_body(conn)
        decoded = Jason.decode!(body)

        assert [%{"role" => "user", "content" => "hello"}] = decoded["messages"]

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(
          200,
          Jason.encode!(%{"choices" => [%{"message" => %{"content" => "hi"}}]})
        )
      end)

      assert {:ok, "hi"} =
               OpenRouter.complete([%{"role" => "user", "content" => "hello"}], opts)
    end

    test "converts Anthropic tool_use content blocks to OpenAI tool_calls", %{
      bypass: bypass,
      opts: opts
    } do
      Bypass.expect_once(bypass, "POST", "/chat/completions", fn conn ->
        {:ok, body, conn} = Plug.Conn.read_body(conn)
        decoded = Jason.decode!(body)

        [assistant_msg] = decoded["messages"]
        assert assistant_msg["role"] == "assistant"
        assert [tc] = assistant_msg["tool_calls"]
        assert tc["type"] == "function"
        assert tc["function"]["name"] == "get_data"
        assert tc["function"]["arguments"] == ~S|{"key":"val"}|

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(
          200,
          Jason.encode!(%{"choices" => [%{"message" => %{"content" => "done"}}]})
        )
      end)

      messages = [
        %{
          "role" => "assistant",
          "content" => [
            %{"type" => "text", "text" => "Let me check"},
            %{
              "type" => "tool_use",
              "id" => "tu_1",
              "name" => "get_data",
              "input" => %{"key" => "val"}
            }
          ]
        }
      ]

      assert {:ok, "done"} = OpenRouter.complete(messages, opts)
    end

    test "converts Anthropic tool_result blocks to OpenAI tool role messages", %{
      bypass: bypass,
      opts: opts
    } do
      Bypass.expect_once(bypass, "POST", "/chat/completions", fn conn ->
        {:ok, body, conn} = Plug.Conn.read_body(conn)
        decoded = Jason.decode!(body)

        [tool_msg] = decoded["messages"]
        assert tool_msg["role"] == "tool"
        assert tool_msg["tool_call_id"] == "tu_1"
        assert tool_msg["content"] == "result data"

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(
          200,
          Jason.encode!(%{"choices" => [%{"message" => %{"content" => "ok"}}]})
        )
      end)

      messages = [
        %{
          "role" => "user",
          "content" => [
            %{"type" => "tool_result", "tool_use_id" => "tu_1", "content" => "result data"}
          ]
        }
      ]

      assert {:ok, "ok"} = OpenRouter.complete(messages, opts)
    end
  end

  describe "headers" do
    test "includes X-Title header", %{bypass: bypass, opts: opts} do
      Bypass.expect_once(bypass, "POST", "/chat/completions", fn conn ->
        assert Plug.Conn.get_req_header(conn, "x-title") == ["Krait"]
        assert Plug.Conn.get_req_header(conn, "authorization") == ["Bearer test-key"]

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(
          200,
          Jason.encode!(%{"choices" => [%{"message" => %{"content" => "ok"}}]})
        )
      end)

      assert {:ok, _} =
               OpenRouter.complete([%{"role" => "user", "content" => "test"}], opts)
    end

    test "includes HTTP-Referer when site_url is set", %{bypass: bypass, opts: opts} do
      Bypass.expect_once(bypass, "POST", "/chat/completions", fn conn ->
        assert Plug.Conn.get_req_header(conn, "http-referer") == ["https://krait.dev"]

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(
          200,
          Jason.encode!(%{"choices" => [%{"message" => %{"content" => "ok"}}]})
        )
      end)

      assert {:ok, _} =
               OpenRouter.complete(
                 [%{"role" => "user", "content" => "test"}],
                 opts ++ [site_url: "https://krait.dev"]
               )
    end
  end

  describe "stream/2" do
    test "returns :not_implemented error" do
      assert {:error, :not_implemented} =
               OpenRouter.stream([%{role: "user", content: "Hi"}], api_key: "key")
    end
  end
end
