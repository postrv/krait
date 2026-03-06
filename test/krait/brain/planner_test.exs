defmodule Krait.Brain.PlannerTest do
  use ExUnit.Case, async: true

  import Mox

  setup :verify_on_exit!

  describe "decompose/2" do
    test "decomposes a request into steps" do
      Krait.LLM.Mock
      |> expect(:complete, fn _messages, _opts ->
        {:ok,
         Jason.encode!([
           %{
             "step" => 1,
             "action" => "skill_call",
             "skill" => "web_fetch",
             "params" => %{"url" => "https://example.com"},
             "description" => "Fetch data"
           },
           %{
             "step" => 2,
             "action" => "respond",
             "skill" => nil,
             "params" => %{},
             "description" => "Summarize results"
           }
         ])}
      end)

      assert {:ok, steps} =
               Krait.Brain.Planner.decompose("fetch and summarize example.com",
                 llm: Krait.LLM.Mock
               )

      assert length(steps) == 2
      assert hd(steps).action == :skill_call
      assert hd(steps).skill == "web_fetch"
    end

    test "returns error on LLM failure" do
      Krait.LLM.Mock
      |> expect(:complete, fn _messages, _opts ->
        {:error, :api_error}
      end)

      assert {:error, :api_error} =
               Krait.Brain.Planner.decompose("do something", llm: Krait.LLM.Mock)
    end

    test "returns error on invalid response" do
      Krait.LLM.Mock
      |> expect(:complete, fn _messages, _opts ->
        {:ok, "not json at all"}
      end)

      assert {:error, :invalid_response} =
               Krait.Brain.Planner.decompose("do something", llm: Krait.LLM.Mock)
    end
  end
end
