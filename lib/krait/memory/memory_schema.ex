defmodule Krait.Memory.MemorySchema do
  @moduledoc false
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}

  schema "memories" do
    field(:content, :string)
    field(:category, :string, default: "fact")
    field(:embedding, Pgvector.Ecto.Vector)
    field(:metadata, :map, default: %{})

    timestamps(type: :utc_datetime)
  end

  def changeset(memory, attrs) do
    memory
    |> cast(attrs, [:content, :category, :embedding, :metadata])
    |> validate_required([:content, :category])
  end
end
