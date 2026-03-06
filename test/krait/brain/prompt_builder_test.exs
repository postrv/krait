defmodule Krait.Brain.PromptBuilderTest do
  use ExUnit.Case, async: true

  describe "build_system_prompt/1" do
    test "includes agent identity" do
      prompt = Krait.Brain.PromptBuilder.build_system_prompt(%{})
      assert prompt =~ "Krait"
      assert prompt =~ "self-evolving agent"
    end

    test "includes skill manifests in progressive disclosure format" do
      skills = [
        %{name: "web_fetch", description: "Fetch web pages", triggers: ["fetch", "get url"]},
        %{name: "bitcoin", description: "Check BTC prices", triggers: ["bitcoin", "btc"]}
      ]

      prompt = Krait.Brain.PromptBuilder.build_system_prompt(%{skills: skills})
      assert prompt =~ "web_fetch"
      assert prompt =~ "bitcoin"
      refute prompt =~ "defmodule"
    end

    test "includes relevant memories" do
      memories = ["User prefers concise responses", "User timezone is UTC+0"]
      prompt = Krait.Brain.PromptBuilder.build_system_prompt(%{memories: memories})
      assert prompt =~ "concise"
      assert prompt =~ "UTC+0"
    end

    test "handles empty context" do
      prompt = Krait.Brain.PromptBuilder.build_system_prompt(%{})
      assert is_binary(prompt)
      assert String.length(prompt) > 0
    end
  end

  describe "build_tool_definitions/1" do
    test "formats skills as Claude tool_use schema" do
      skills = [%{name: "web_fetch", description: "Fetch a URL", params: %{url: :string}}]
      tools = Krait.Brain.PromptBuilder.build_tool_definitions(skills)
      assert is_list(tools)
      tool = hd(tools)
      assert tool["name"] == "web_fetch"
      assert tool["description"] == "Fetch a URL"
      assert tool["input_schema"]["properties"]["url"]
    end

    test "returns empty list for no skills" do
      assert [] = Krait.Brain.PromptBuilder.build_tool_definitions([])
    end

    test "handles skills with multiple params" do
      skills = [
        %{
          name: "search",
          description: "Search the web",
          params: %{query: :string, limit: :integer}
        }
      ]

      tools = Krait.Brain.PromptBuilder.build_tool_definitions(skills)
      tool = hd(tools)
      assert tool["input_schema"]["properties"]["query"]["type"] == "string"
      assert tool["input_schema"]["properties"]["limit"]["type"] == "integer"
    end
  end
end
