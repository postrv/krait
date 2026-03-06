defmodule Krait.Repo.Migrations.CreateMemories do
  use Ecto.Migration

  def up do
    # pgvector is optional — skip if extension not available
    case repo().query("SELECT 1 FROM pg_available_extensions WHERE name = 'vector'") do
      {:ok, %{num_rows: 1}} ->
        execute("CREATE EXTENSION IF NOT EXISTS vector")

        create table(:memories, primary_key: false) do
          add :id, :binary_id, primary_key: true
          add :content, :text, null: false
          add :category, :string, null: false, default: "fact"
          add :embedding, :vector, size: 384
          add :metadata, :map, default: %{}

          timestamps(type: :utc_datetime)
        end

        execute(
          "CREATE INDEX memories_embedding_idx ON memories USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100)"
        )

      _ ->
        # Create memories table without vector column when pgvector is unavailable
        create table(:memories, primary_key: false) do
          add :id, :binary_id, primary_key: true
          add :content, :text, null: false
          add :category, :string, null: false, default: "fact"
          add :metadata, :map, default: %{}

          timestamps(type: :utc_datetime)
        end
    end
  end

  def down do
    drop_if_exists(table(:memories))

    case repo().query("SELECT 1 FROM pg_available_extensions WHERE name = 'vector'") do
      {:ok, %{num_rows: 1}} -> execute("DROP EXTENSION IF EXISTS vector")
      _ -> :ok
    end
  end
end
