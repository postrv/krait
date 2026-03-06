defmodule Krait.ReleaseSeedTest do
  use Krait.DataCase, async: false

  alias Krait.Evolution.{EventSchema, Feed}

  setup do
    # Clean up any existing events to test seed from empty state
    Repo.delete_all(EventSchema)
    :ok
  end

  describe "seed_evolution_events/0" do
    test "creates 5 demo events when table is empty" do
      assert {:ok, 5} = Krait.Release.seed_evolution_events()

      events = Feed.list(limit: 100)
      assert length(events) == 5

      skill_names = Enum.map(events, & &1.skill_name) |> Enum.sort()

      assert skill_names == [
               "code_metrics",
               "date_helper",
               "json_tools",
               "math_utils",
               "text_transform"
             ]
    end

    test "is idempotent — skips if events already exist" do
      assert {:ok, 5} = Krait.Release.seed_evolution_events()
      assert {:ok, 0} = Krait.Release.seed_evolution_events()

      events = Feed.list(limit: 100)
      assert length(events) == 5
    end

    test "seeded events have expected fields" do
      {:ok, 5} = Krait.Release.seed_evolution_events()

      events = Feed.list(limit: 100)

      for event <- events do
        assert is_binary(event.skill_name)
        assert is_binary(event.description)
        assert is_boolean(event.draft)
        assert is_integer(event.complexity)
        assert is_binary(event.ast_hash)
        assert event.security_findings == 0
        assert event.taint_flows == 0
      end
    end

    test "code_metrics event is a draft with reasoning" do
      {:ok, 5} = Krait.Release.seed_evolution_events()

      code_metrics = Repo.get_by(EventSchema, skill_name: "code_metrics")

      assert code_metrics.draft == true
      assert code_metrics.attempts == 2
      assert is_binary(code_metrics.reasoning)
    end
  end
end
