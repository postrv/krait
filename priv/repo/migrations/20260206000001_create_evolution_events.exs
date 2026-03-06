defmodule Krait.Repo.Migrations.CreateEvolutionEvents do
  use Ecto.Migration

  def change do
    create table(:evolution_events, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :skill_name, :string, null: false
      add :description, :text
      add :pr_url, :string
      add :pr_number, :integer
      add :attempts, :integer, default: 1
      add :draft, :boolean, default: true
      add :ast_hash, :string
      add :complexity, :integer
      add :complexity_delta, :integer
      add :security_findings, :integer, default: 0
      add :taint_flows, :integer, default: 0
      add :test_count, :integer, default: 0
      add :reasoning, :text
      timestamps(type: :utc_datetime_usec)
    end

    create index(:evolution_events, [:skill_name])
    create index(:evolution_events, [:inserted_at])
  end
end
