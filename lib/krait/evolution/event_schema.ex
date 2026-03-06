defmodule Krait.Evolution.EventSchema do
  @moduledoc "Ecto schema for persisted evolution events"

  use Ecto.Schema
  import Ecto.Changeset

  @type t :: %__MODULE__{}

  @primary_key {:id, :binary_id, autogenerate: true}

  schema "evolution_events" do
    field(:skill_name, :string)
    field(:description, :string)
    field(:pr_url, :string)
    field(:pr_number, :integer)
    field(:attempts, :integer, default: 1)
    field(:draft, :boolean, default: true)
    field(:ast_hash, :string)
    field(:complexity, :integer)
    field(:complexity_delta, :integer)
    field(:security_findings, :integer, default: 0)
    field(:taint_flows, :integer, default: 0)
    field(:test_count, :integer, default: 0)
    field(:reasoning, :string)
    timestamps(type: :utc_datetime_usec)
  end

  @required_fields [:skill_name]
  @optional_fields [
    :description,
    :pr_url,
    :pr_number,
    :attempts,
    :draft,
    :ast_hash,
    :complexity,
    :complexity_delta,
    :security_findings,
    :taint_flows,
    :test_count,
    :reasoning
  ]

  def changeset(event, attrs) do
    event
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
  end
end
