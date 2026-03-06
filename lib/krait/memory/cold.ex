defmodule Krait.Memory.Cold do
  @moduledoc "Long-term memory backed by pgvector for similarity search"

  import Ecto.Query
  alias Krait.Memory.{Guard, MemorySchema}
  alias Krait.Repo

  @spec store(term(), term(), keyword()) ::
          {:ok, Ecto.Schema.t()}
          | {:error, Ecto.Changeset.t()}
          | {:error, {:guard_rejected, String.t()}}
  def store(content, category, opts \\ []) do
    embedding = Keyword.get(opts, :embedding)
    metadata = Keyword.get(opts, :metadata, %{})

    value_to_check = inspect(%{content: content, metadata: metadata})

    case Guard.validate_write("memory:#{category}", value_to_check) do
      :ok ->
        attrs = %{
          content: content,
          category: to_string(category),
          embedding: embedding,
          metadata: metadata
        }

        %MemorySchema{}
        |> MemorySchema.changeset(attrs)
        |> Repo.insert()

      {:rejected, reason} ->
        {:error, {:guard_rejected, reason}}
    end
  end

  # v25 L-10: Expected embedding dimension (matches pgvector column config)
  @expected_dimension Application.compile_env(:krait, :embedding_dimension, 1536)

  @spec recall(keyword()) :: [Ecto.Schema.t()] | {:error, :dimension_mismatch}
  def recall(opts \\ []) do
    embedding = Keyword.fetch!(opts, :embedding)
    limit = Keyword.get(opts, :limit, 5)

    if length(embedding) != @expected_dimension do
      {:error, :dimension_mismatch}
    else
      query =
        from(m in MemorySchema,
          order_by: fragment("embedding <=> ?::vector", ^Pgvector.new(embedding)),
          limit: ^limit
        )

      Repo.all(query)
    end
  end

  @spec forget(term()) :: :ok | {:error, :not_found}
  def forget(id) do
    case Repo.get(MemorySchema, id) do
      nil ->
        {:error, :not_found}

      memory ->
        Repo.delete(memory)
        :ok
    end
  end
end
