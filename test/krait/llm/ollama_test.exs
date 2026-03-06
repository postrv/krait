defmodule Krait.LLM.OllamaTest do
  use ExUnit.Case, async: true

  describe "complete/2" do
    setup do
      bypass = Bypass.open()
      {:ok, bypass: bypass, base_url: "http://localhost:#{bypass.port}"}
    end

    test "sends messages and returns text response", %{bypass: bypass, base_url: url} do
      Bypass.expect_once(bypass, "POST", "/api/chat", fn conn ->
        {:ok, body, conn} = Plug.Conn.read_body(conn)
        decoded = Jason.decode!(body)

        assert decoded["model"] == "qwen2.5-coder:14b"
        assert decoded["stream"] == false
        assert length(decoded["messages"]) == 1
        assert hd(decoded["messages"])["content"] == "Hello"

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(
          200,
          Jason.encode!(%{
            "message" => %{"role" => "assistant", "content" => "Hi there!"},
            "done" => true
          })
        )
      end)

      assert {:ok, "Hi there!"} =
               Krait.LLM.Ollama.complete(
                 [%{"role" => "user", "content" => "Hello"}],
                 base_url: url
               )
    end

    test "returns error when Ollama is unreachable" do
      assert {:error, :ollama_unavailable} =
               Krait.LLM.Ollama.complete(
                 [%{"role" => "user", "content" => "Hello"}],
                 base_url: "http://localhost:1"
               )
    end

    test "returns error on non-200 status", %{bypass: bypass, base_url: url} do
      Bypass.expect_once(bypass, "POST", "/api/chat", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(500, Jason.encode!(%{"error" => "model not found"}))
      end)

      assert {:error, {:ollama_error, 500, _}} =
               Krait.LLM.Ollama.complete(
                 [%{"role" => "user", "content" => "Hello"}],
                 base_url: url
               )
    end
  end

  describe "complete_with_tools/3" do
    setup do
      bypass = Bypass.open()
      {:ok, bypass: bypass, base_url: "http://localhost:#{bypass.port}"}
    end

    test "sends tools in OpenAI format and parses tool_calls response",
         %{bypass: bypass, base_url: url} do
      Bypass.expect_once(bypass, "POST", "/api/chat", fn conn ->
        {:ok, body, conn} = Plug.Conn.read_body(conn)
        decoded = Jason.decode!(body)

        # Verify tools were translated to OpenAI function format
        assert [tool] = decoded["tools"]
        assert tool["type"] == "function"
        assert tool["function"]["name"] == "web_fetch"

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(
          200,
          Jason.encode!(%{
            "message" => %{
              "role" => "assistant",
              "content" => "I'll fetch that for you.",
              "tool_calls" => [
                %{
                  "id" => "call_001",
                  "type" => "function",
                  "function" => %{
                    "name" => "web_fetch",
                    "arguments" => %{"url" => "https://example.com"}
                  }
                }
              ]
            },
            "done" => true
          })
        )
      end)

      tools = [
        %{
          "name" => "web_fetch",
          "description" => "Fetch a URL",
          "input_schema" => %{
            "type" => "object",
            "properties" => %{"url" => %{"type" => "string"}}
          }
        }
      ]

      assert {:ok, result} =
               Krait.LLM.Ollama.complete_with_tools(
                 [%{"role" => "user", "content" => "fetch example.com"}],
                 tools,
                 base_url: url
               )

      assert result.text == "I'll fetch that for you."
      assert [tool_call] = result.tool_calls
      assert tool_call.name == "web_fetch"
      assert tool_call.input == %{"url" => "https://example.com"}
      assert tool_call.id == "call_001"
    end

    test "handles response with no tool calls", %{bypass: bypass, base_url: url} do
      Bypass.expect_once(bypass, "POST", "/api/chat", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(
          200,
          Jason.encode!(%{
            "message" => %{"role" => "assistant", "content" => "No tools needed."},
            "done" => true
          })
        )
      end)

      assert {:ok, result} =
               Krait.LLM.Ollama.complete_with_tools(
                 [%{"role" => "user", "content" => "hello"}],
                 [],
                 base_url: url
               )

      assert result.text == "No tools needed."
      assert result.tool_calls == []
    end

    test "handles string arguments from Ollama (not pre-parsed)",
         %{bypass: bypass, base_url: url} do
      Bypass.expect_once(bypass, "POST", "/api/chat", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(
          200,
          Jason.encode!(%{
            "message" => %{
              "role" => "assistant",
              "content" => "",
              "tool_calls" => [
                %{
                  "type" => "function",
                  "function" => %{
                    "name" => "calc",
                    # Some Ollama models return arguments as a JSON string
                    "arguments" => Jason.encode!(%{"expression" => "2+2"})
                  }
                }
              ]
            },
            "done" => true
          })
        )
      end)

      assert {:ok, result} =
               Krait.LLM.Ollama.complete_with_tools(
                 [%{"role" => "user", "content" => "calc 2+2"}],
                 [%{"name" => "calc", "description" => "Calculate"}],
                 base_url: url
               )

      assert [tc] = result.tool_calls
      assert tc.input == %{"expression" => "2+2"}
    end
  end

  describe "redirect protection" do
    setup do
      bypass = Bypass.open()
      {:ok, bypass: bypass, base_url: "http://localhost:#{bypass.port}"}
    end

    test "does not follow 302 redirects", %{bypass: bypass, base_url: url} do
      Bypass.expect_once(bypass, "POST", "/api/chat", fn conn ->
        conn
        |> Plug.Conn.put_resp_header("location", "http://169.254.169.254/latest/meta-data/")
        |> Plug.Conn.resp(302, "")
      end)

      assert {:error, {:ollama_error, 302, _}} =
               Krait.LLM.Ollama.complete(
                 [%{"role" => "user", "content" => "Hello"}],
                 base_url: url
               )
    end
  end

  describe "SSRF protection in do_chat" do
    setup do
      bypass = Bypass.open()
      {:ok, bypass: bypass, base_url: "http://localhost:#{bypass.port}"}
    end

    test "rejects non-local base_url (always-on, not just prod)" do
      assert {:error, :invalid_ollama_url} =
               Krait.LLM.Ollama.complete(
                 [%{"role" => "user", "content" => "Hello"}],
                 base_url: "http://evil.com:11434"
               )
    end

    test "rejects metadata endpoint" do
      assert {:error, :invalid_ollama_url} =
               Krait.LLM.Ollama.complete(
                 [%{"role" => "user", "content" => "Hello"}],
                 base_url: "http://169.254.169.254"
               )
    end

    test "allows localhost", %{bypass: bypass, base_url: url} do
      Bypass.expect_once(bypass, "POST", "/api/chat", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(
          200,
          Jason.encode!(%{
            "message" => %{"role" => "assistant", "content" => "Hi!"},
            "done" => true
          })
        )
      end)

      assert {:ok, "Hi!"} =
               Krait.LLM.Ollama.complete(
                 [%{"role" => "user", "content" => "Hello"}],
                 base_url: url
               )
    end

    test "allows 127.0.0.1" do
      bypass = Bypass.open()

      Bypass.expect_once(bypass, "POST", "/api/chat", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(
          200,
          Jason.encode!(%{
            "message" => %{"role" => "assistant", "content" => "Hi!"},
            "done" => true
          })
        )
      end)

      assert {:ok, "Hi!"} =
               Krait.LLM.Ollama.complete(
                 [%{"role" => "user", "content" => "Hello"}],
                 base_url: "http://127.0.0.1:#{bypass.port}"
               )
    end
  end

  describe "message normalization" do
    setup do
      bypass = Bypass.open()
      {:ok, bypass: bypass, base_url: "http://localhost:#{bypass.port}"}
    end

    test "normalizes Claude-style tool_use + tool_result messages",
         %{bypass: bypass, base_url: url} do
      Bypass.expect_once(bypass, "POST", "/api/chat", fn conn ->
        {:ok, body, conn} = Plug.Conn.read_body(conn)
        decoded = Jason.decode!(body)
        messages = decoded["messages"]

        # First message: user text
        assert Enum.at(messages, 0)["role"] == "user"
        assert Enum.at(messages, 0)["content"] == "fetch example.com"

        # Second message: assistant with tool_calls
        assistant = Enum.at(messages, 1)
        assert assistant["role"] == "assistant"
        assert [tc] = assistant["tool_calls"]
        assert tc["function"]["name"] == "web_fetch"

        # Third message: tool result
        tool_result = Enum.at(messages, 2)
        assert tool_result["role"] == "tool"
        assert tool_result["content"] =~ "page content"

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.resp(
          200,
          Jason.encode!(%{
            "message" => %{"role" => "assistant", "content" => "Done!"},
            "done" => true
          })
        )
      end)

      # These are Claude-format messages as produced by Brain's ReAct loop
      messages = [
        %{"role" => "user", "content" => "fetch example.com"},
        %{
          "role" => "assistant",
          "content" => [
            %{"type" => "text", "text" => "Let me fetch that."},
            %{
              "type" => "tool_use",
              "id" => "t1",
              "name" => "web_fetch",
              "input" => %{"url" => "https://example.com"}
            }
          ]
        },
        %{
          "role" => "user",
          "content" => [
            %{
              "type" => "tool_result",
              "tool_use_id" => "t1",
              "content" => "page content here"
            }
          ]
        }
      ]

      assert {:ok, _} =
               Krait.LLM.Ollama.complete_with_tools(messages, [], base_url: url)
    end
  end
end
