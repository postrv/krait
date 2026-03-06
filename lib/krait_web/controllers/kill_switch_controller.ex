defmodule KraitWeb.KillSwitchController do
  @moduledoc "Admin API for the kill switch — halt/resume/status"

  use KraitWeb, :controller

  # v25 M-6: Validate reason — max 200 chars, printable UTF-8, strip control chars
  @max_reason_length 200

  def halt(conn, params) do
    reason =
      Map.get(params, "reason", "admin_halt")
      |> sanitize_reason()

    :ok = Krait.KillSwitch.halt!(reason)
    json(conn, %{status: "halted", reason: reason})
  end

  defp sanitize_reason(reason) when is_binary(reason) do
    reason
    |> String.replace(~r/[\x00-\x1F\x7F]/, "")
    |> String.slice(0, @max_reason_length)
  end

  defp sanitize_reason(_), do: "admin_halt"

  def resume(conn, _params) do
    case Krait.KillSwitch.resume!() do
      :ok ->
        json(conn, %{status: "resumed"})

      {:error, :resume_cooldown, seconds_remaining} ->
        conn
        |> put_status(429)
        |> json(%{
          error: "resume_cooldown",
          message: "Resume cooldown active. Try again in #{seconds_remaining} seconds."
        })
    end
  end

  def status(conn, _params) do
    status = Krait.KillSwitch.status()

    json(conn, %{
      halted: status.halted,
      halted_at: if(status.halted_at, do: DateTime.to_iso8601(status.halted_at), else: nil),
      halted_by: status.halted_by,
      consecutive_failures: status.consecutive_failures
    })
  end
end
