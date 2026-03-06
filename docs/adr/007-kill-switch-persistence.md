# ADR-007: Kill Switch State Persisted to Database

## Status

Accepted

## Context

The kill switch (`Krait.KillSwitch`) is a GenServer that provides immediate
halt/resume control over the entire evolution system -- the "K" in KRAIT. When
halted, all evolution entry points are blocked: `Krait.Evolution.evolve/1`
checks `KillSwitch.halted?/0` before proceeding, and `Krait.Skills.Core.Evolve`
checks it again before acquiring a slot.

The kill switch can be engaged manually (`KillSwitchController`), by auto-trip
after consecutive validation failures (default threshold: 5), or during graceful
shutdown (`Application.prep_stop/1`). The question is where to persist state.

ETS provides fast reads (sub-microsecond) but is ephemeral -- the table is
destroyed when the owning process terminates or the node restarts. If the kill
switch is engaged due to a security incident (e.g., the LLM producing
suspicious code that triggers auto-trip), a node restart would silently clear
the halted state and re-enable evolution.

This is a critical safety gap. The scenarios where the kill switch is most
needed (security incidents, validation pipeline failures) are also scenarios
where nodes are likely to restart (crash loops, operator-initiated restarts
for diagnosis, deployment of fixes).

## Decision

Kill switch state is persisted to both ETS and PostgreSQL:

- **ETS** (`@table :krait_kill_switch`): Used for fast reads via
  `KillSwitch.halted?/0`. This is the hot path checked on every evolution
  request. The table is `:protected` (only the owning GenServer can write).

- **PostgreSQL** (`kill_switch_state` table via `Krait.KillSwitchState` Ecto
  schema): Persists `halted`, `halted_at`, `halted_by`, and
  `consecutive_failures`. Written on every state change via `persist_to_db/1`.

On init, `restore_from_db/1` queries the table. If a halted record exists, ETS
is populated and a warning is logged. The operator must explicitly call
`KillSwitch.resume!/0` (30-second cooldown) to re-enable evolution.

DB errors during persistence are logged but do not block the halt. ETS is
always updated first; DB persistence is best-effort. A halt is never delayed by
a slow database. Migration:
`priv/repo/migrations/20260212000001_create_kill_switch_state.exs`.

## Consequences

**Positive:**

- A security halt survives node restarts. If auto-trip fires due to 5
  consecutive validation failures, the system remains halted until an operator
  explicitly resumes. This prevents restart-based bypass of the safety mechanism.
- ETS provides sub-microsecond reads on the hot path. The database is only
  accessed on state changes (halt, resume, failure/success recording), not on
  every `halted?/0` check.
- The 30-second resume cooldown (`kill_switch_resume_cooldown` config) prevents
  automated scripts from rapidly toggling the switch.
- Full state is available for dashboards via `KillSwitch.status/0` without
  querying the database.

**Negative:**

- Database unavailability during init means the kill switch starts non-halted.
  Specific exceptions (`DBConnection.ConnectionError`, `Postgrex.Error`,
  `Ecto.QueryError`) are caught and logged at warning level for monitoring.
- The GenServer must start after `Krait.Repo` and `Phoenix.PubSub` in the
  supervisor tree. This ordering is enforced in `Krait.Application.children/0`.
- A single DB row is updated on every state change. The failure threshold (5)
  and resume cooldown (30s) bound write frequency in practice.
