defmodule Mix.Tasks.Krait.SeedFeed do
  @moduledoc "Seeds the evolution feed with sample events for development"
  use Mix.Task

  @shortdoc "Seed evolution feed with sample events"

  def run(_args) do
    Mix.Task.run("app.start")

    events = [
      %{
        skill_name: "greeting",
        description: "Personalized greeting skill",
        attempts: 1,
        draft: false,
        pr_url: "https://github.com/org/krait/pull/1",
        complexity: 8,
        security_findings: 0,
        taint_flows: 0,
        test_count: 3,
        ast_hash: "a1b2c3d4e5f6"
      },
      %{
        skill_name: "weather",
        description: "Weather lookup via wttr.in",
        attempts: 2,
        draft: true,
        complexity: 15,
        security_findings: 0,
        taint_flows: 0,
        test_count: 2,
        ast_hash: "f6e5d4c3b2a1"
      },
      %{
        skill_name: "calculator",
        description: "Basic arithmetic skill",
        attempts: 1,
        draft: false,
        pr_url: "https://github.com/org/krait/pull/3",
        complexity: 12,
        security_findings: 0,
        taint_flows: 0,
        test_count: 5,
        ast_hash: "1a2b3c4d5e6f"
      }
    ]

    for event <- events do
      case Krait.Evolution.Feed.record(event) do
        {:ok, e} -> Mix.shell().info("Seeded: #{e.skill_name} (id=#{e.id})")
        {:error, cs} -> Mix.shell().error("Failed: #{inspect(cs)}")
      end
    end

    Mix.shell().info("Seeded #{length(events)} evolution events")
  end
end
