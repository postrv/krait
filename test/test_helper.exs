{:ok, _, _} = Ecto.Migrator.with_repo(Krait.Repo, &Ecto.Migrator.run(&1, :up, all: true))

# v21 H-3: Start RateLimitCounter GenServer for tests that need rate limiting
# This creates the :krait_rate_limit ETS table with :protected access.
case GenServer.whereis(KraitWeb.RateLimitCounter) do
  nil -> KraitWeb.RateLimitCounter.start_link([])
  _pid -> :ok
end

ExUnit.start(exclude: [:integration, :narsil_required, :docker_required, :pgvector_required])
