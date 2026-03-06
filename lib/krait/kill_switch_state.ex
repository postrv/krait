defmodule Krait.KillSwitchState do
  @moduledoc "Ecto schema for persisted kill switch state (survives node restarts)"

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}

  schema "kill_switch_state" do
    field(:halted, :boolean, default: false)
    field(:halted_at, :utc_datetime_usec)
    field(:halted_by, :string)
    field(:consecutive_failures, :integer, default: 0)

    timestamps(type: :utc_datetime_usec)
  end

  def changeset(state, attrs) do
    state
    |> cast(attrs, [:halted, :halted_at, :halted_by, :consecutive_failures])
    |> validate_required([:halted, :consecutive_failures])
  end
end
