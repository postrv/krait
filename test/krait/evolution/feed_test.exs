defmodule Krait.Evolution.FeedTest do
  use Krait.DataCase, async: true

  alias Krait.Evolution.Feed

  test "records evolution event and persists to database" do
    event = %{
      skill_name: "bitcoin",
      description: "Check Bitcoin prices",
      pr_url: "https://github.com/org/krait/pull/42",
      pr_number: 42,
      attempts: 1,
      draft: false,
      ast_hash: "abc123",
      complexity: 12,
      complexity_delta: 12,
      security_findings: 0,
      taint_flows: 0,
      test_count: 4,
      reasoning: "I chose CoinGecko because..."
    }

    {:ok, recorded} = Feed.record(event)
    assert recorded.id
    assert recorded.skill_name == "bitcoin"

    events = Feed.list(limit: 10)
    assert Enum.any?(events, &(&1.id == recorded.id))
  end

  test "generates shareable markdown for evolution event" do
    {:ok, event} =
      Feed.record(%{
        skill_name: "bitcoin",
        description: "User asked about Bitcoin prices",
        pr_url: "https://github.com/org/krait/pull/42",
        security_findings: 0,
        taint_flows: 0,
        complexity_delta: 12,
        test_count: 4,
        attempts: 1,
        ast_hash: "abc123def456"
      })

    markdown = Feed.to_markdown(event)
    assert markdown =~ "Evolution"
    assert markdown =~ "bitcoin"
    assert markdown =~ "0 findings"
    assert markdown =~ "abc123def456"
    assert markdown =~ "pull/42"
  end

  test "list returns events in reverse chronological order" do
    {:ok, _} = Feed.record(%{skill_name: "first", description: "first"})
    Process.sleep(10)
    {:ok, _} = Feed.record(%{skill_name: "second", description: "second"})

    [latest | _] = Feed.list()
    assert latest.skill_name == "second"
  end

  describe "safe_pr_link URL restriction (M-13)" do
    test "github.com PR URL produces markdown link" do
      {:ok, event} =
        Feed.record(%{
          skill_name: "url_test",
          description: "test",
          pr_url: "https://github.com/org/repo/pull/1"
        })

      markdown = Feed.to_markdown(event)
      assert markdown =~ "[View PR](https://github.com/org/repo/pull/1)"
    end

    test "non-github https URL produces no link" do
      {:ok, event} =
        Feed.record(%{
          skill_name: "url_test2",
          description: "test",
          pr_url: "https://evil.com/steal"
        })

      markdown = Feed.to_markdown(event)
      refute markdown =~ "[View PR]"
    end

    test "attacker URL produces no link" do
      {:ok, event} =
        Feed.record(%{
          skill_name: "url_test3",
          description: "test",
          pr_url: "https://attacker.com"
        })

      markdown = Feed.to_markdown(event)
      refute markdown =~ "[View PR]"
    end
  end

  test "broadcasts PubSub event on record" do
    Phoenix.PubSub.subscribe(Krait.PubSub, "evolution:feed")
    Feed.record(%{skill_name: "broadcast_test", description: "test"})
    assert_receive {:evolution_event, %{skill_name: "broadcast_test"}}, 1000
  end
end
