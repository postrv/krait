defmodule Krait.Repo.Migrations.CreateKillSwitchState do
  use Ecto.Migration

  def change do
    create table(:kill_switch_state, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :halted, :boolean, null: false, default: false
      add :halted_at, :utc_datetime_usec
      add :halted_by, :string
      add :consecutive_failures, :integer, null: false, default: 0

      timestamps(type: :utc_datetime_usec)
    end
  end
end
