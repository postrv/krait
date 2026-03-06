defmodule Krait.DataCase do
  @moduledoc "Test case for tests requiring database access"

  use ExUnit.CaseTemplate

  using do
    quote do
      alias Krait.Repo

      import Ecto
      import Ecto.Changeset
      import Ecto.Query
      import Krait.DataCase
    end
  end

  setup tags do
    Krait.DataCase.setup_sandbox(tags)
    :ok
  end

  def setup_sandbox(tags) do
    pid = Ecto.Adapters.SQL.Sandbox.start_owner!(Krait.Repo, shared: not tags[:async])
    on_exit(fn -> Ecto.Adapters.SQL.Sandbox.stop_owner(pid) end)
  end
end
