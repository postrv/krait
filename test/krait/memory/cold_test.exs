defmodule Krait.Memory.ColdTest do
  use Krait.DataCase, async: false

  @moduletag :pgvector_required

  describe "store/3 and recall/2" do
    test "stores and recalls a memory" do
      embedding = for _ <- 1..384, do: :rand.uniform()

      assert {:ok, memory} =
               Krait.Memory.Cold.store("user likes hiking", :fact, embedding: embedding)

      assert memory.id
      assert memory.content == "user likes hiking"
    end

    test "recall returns stored memories" do
      embedding1 = for _ <- 1..384, do: :rand.uniform()
      embedding2 = for _ <- 1..384, do: :rand.uniform()

      {:ok, _} = Krait.Memory.Cold.store("user likes hiking", :fact, embedding: embedding1)
      {:ok, _} = Krait.Memory.Cold.store("user works at Acme", :fact, embedding: embedding2)

      results = Krait.Memory.Cold.recall(embedding: embedding1, limit: 10)
      assert length(results) >= 1
    end
  end

  describe "forget/1" do
    test "removes a specific memory" do
      embedding = for _ <- 1..384, do: :rand.uniform()

      {:ok, memory} = Krait.Memory.Cold.store("temporary", :fact, embedding: embedding)
      assert :ok = Krait.Memory.Cold.forget(memory.id)

      results = Krait.Memory.Cold.recall(embedding: embedding, limit: 10)
      refute Enum.any?(results, &(&1.id == memory.id))
    end
  end
end
