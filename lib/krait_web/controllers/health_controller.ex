defmodule KraitWeb.HealthController do
  @moduledoc """
  Health check endpoints for operational readiness.

  These endpoints are unauthenticated by design:
  - `GET /health` — liveness probe (always 200 if the BEAM is up)
  - `GET /health/ready` — readiness probe (checks DB, ETS, NIF)
  - `GET /health/evolution` — evolution subsystem status (kill switch state)

  The readiness check intentionally does NOT include the kill switch.
  When the kill switch is engaged, the system is still "ready" (healthy) —
  it has simply chosen to pause evolution. Orchestrators should not restart
  a pod just because evolution is paused.
  """

  use KraitWeb, :controller

  def check(conn, _params) do
    conn |> put_status(200) |> json(%{status: "alive"})
  end

  def ready(conn, _params) do
    checks = %{
      database: check_repo(),
      cooldown_server: check_cooldown_server(),
      nif: check_nif()
    }

    status = if Enum.all?(Map.values(checks), &(&1 == :ok)), do: 200, else: 503

    conn
    |> put_status(status)
    |> json(%{status: status_label(status), checks: serialize_checks(checks)})
  end

  def evolution(conn, _params) do
    kill_switch = Krait.KillSwitch.status()

    conn
    |> put_status(200)
    |> json(%{
      kill_switch: serialize_kill_switch(kill_switch),
      evolution_enabled: not kill_switch.halted
    })
  end

  defp check_repo do
    Krait.Repo.query("SELECT 1")
    :ok
  rescue
    DBConnection.ConnectionError -> :error
    Postgrex.Error -> :error
    Ecto.QueryError -> :error
    DBConnection.OwnershipError -> :error
  end

  defp check_cooldown_server do
    # Verify the EvolveCooldownServer is responsive by doing a lookup
    Krait.EvolveCooldownServer.lookup(:active_evolutions)
    :ok
  rescue
    ArgumentError -> :error
  end

  defp check_nif do
    if Code.ensure_loaded?(Krait.Analyzer.Nif), do: :ok, else: :unavailable
  end

  defp status_label(200), do: "ready"
  defp status_label(_), do: "not_ready"

  defp serialize_checks(checks) do
    Map.new(checks, fn {k, v} -> {k, Atom.to_string(v)} end)
  end

  # v25 L-1: Reduced data — halted_by and consecutive_failures are internal details
  # that should not be exposed on an unauthenticated endpoint
  defp serialize_kill_switch(status) do
    %{
      halted: status.halted,
      halted_at: if(status.halted_at, do: DateTime.to_iso8601(status.halted_at), else: nil)
    }
  end
end
