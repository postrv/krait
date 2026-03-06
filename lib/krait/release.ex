defmodule Krait.Release do
  @moduledoc """
  Release-time helpers invoked via `bin/krait eval`.

  Used by:
  - Docker HEALTHCHECK: `bin/krait eval "Krait.Release.health_check()"`
  - Migrations: `bin/krait eval "Krait.Release.migrate()"`
  """

  @app :krait

  @doc "Run all pending Ecto migrations."
  def migrate do
    load_app()

    for repo <- repos() do
      {:ok, _, _} = Ecto.Migrator.with_repo(repo, &Ecto.Migrator.run(&1, :up, all: true))
    end
  end

  @doc "Rollback the last migration."
  def rollback(repo, version) do
    load_app()
    {:ok, _, _} = Ecto.Migrator.with_repo(repo, &Ecto.Migrator.run(&1, :down, to: version))
  end

  @doc "Health check for Docker HEALTHCHECK — exits 0 if the app is running."
  def health_check do
    load_app()

    case Ecto.Adapters.SQL.query(Krait.Repo, "SELECT 1") do
      {:ok, _} -> :ok
      {:error, _} -> System.halt(1)
    end
  end

  @doc """
  Seed the database with demo evolution events.
  Idempotent — skips if events already exist.
  """
  def seed do
    load_app()

    for repo <- repos() do
      {:ok, _, _} = Ecto.Migrator.with_repo(repo, fn _repo -> seed_evolution_events() end)
    end
  end

  @doc false
  def seed_evolution_events do
    alias Krait.Evolution.EventSchema
    alias Krait.Repo

    count = Repo.aggregate(EventSchema, :count)

    if count == 0 do
      now = DateTime.utc_now() |> DateTime.truncate(:microsecond)

      events = [
        %{
          skill_name: "text_transform",
          description: "Text transformation utilities — uppercase, lowercase, slug, snake_case",
          draft: false,
          complexity: 12,
          complexity_delta: 0,
          security_findings: 0,
          taint_flows: 0,
          test_count: 15,
          attempts: 1,
          ast_hash: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
          inserted_at: DateTime.add(now, -7200, :second),
          updated_at: DateTime.add(now, -7200, :second)
        },
        %{
          skill_name: "json_tools",
          description: "JSON manipulation — validate, extract paths, flatten nested objects",
          draft: false,
          complexity: 15,
          complexity_delta: 0,
          security_findings: 0,
          taint_flows: 0,
          test_count: 12,
          attempts: 1,
          ast_hash: "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3",
          inserted_at: DateTime.add(now, -5400, :second),
          updated_at: DateTime.add(now, -5400, :second)
        },
        %{
          skill_name: "math_utils",
          description: "Mathematical utilities — statistics, number theory, sequences",
          draft: false,
          complexity: 18,
          complexity_delta: 0,
          security_findings: 0,
          taint_flows: 0,
          test_count: 18,
          attempts: 1,
          ast_hash: "c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4",
          inserted_at: DateTime.add(now, -3600, :second),
          updated_at: DateTime.add(now, -3600, :second)
        },
        %{
          skill_name: "date_helper",
          description: "Date/time helpers — relative time, formatting, arithmetic",
          draft: false,
          complexity: 10,
          complexity_delta: 0,
          security_findings: 0,
          taint_flows: 0,
          test_count: 10,
          attempts: 1,
          ast_hash: "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5",
          inserted_at: DateTime.add(now, -1800, :second),
          updated_at: DateTime.add(now, -1800, :second)
        },
        %{
          skill_name: "code_metrics",
          description: "Elixir code analysis — line count, function count, comment ratio",
          draft: true,
          complexity: 8,
          complexity_delta: 0,
          security_findings: 0,
          taint_flows: 0,
          test_count: 8,
          attempts: 2,
          reasoning:
            "Second attempt needed: initial version used File.read! instead of capability injection",
          ast_hash: "e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6",
          inserted_at: now,
          updated_at: now
        }
      ]

      for event_attrs <- events do
        %EventSchema{}
        |> Ecto.Changeset.cast(event_attrs, [
          :skill_name,
          :description,
          :draft,
          :complexity,
          :complexity_delta,
          :security_findings,
          :taint_flows,
          :test_count,
          :attempts,
          :ast_hash,
          :reasoning,
          :inserted_at,
          :updated_at
        ])
        |> Repo.insert!()
      end

      {:ok, 5}
    else
      {:ok, 0}
    end
  end

  defp repos do
    Application.fetch_env!(@app, :ecto_repos)
  end

  defp load_app do
    Application.ensure_all_started(:ssl)
    Application.load(@app)
  end
end
