defmodule Krait.Skills.Community.DateHelper do
  @moduledoc "Date/time utilities — relative time, formatting, arithmetic, day-of-week"
  @behaviour Krait.Skills.CapableSkill

  @impl true
  def name, do: "date_helper"

  @impl true
  def description,
    do: "Date helpers: relative_time, add_days, format, day_of_week, days_between, is_weekend"

  @impl true
  def required_capabilities, do: []

  @impl true
  def execute(%{"action" => "relative_time", "datetime" => dt_string}, _caps)
      when is_binary(dt_string) do
    case DateTime.from_iso8601(dt_string) do
      {:ok, dt, _offset} ->
        {:ok, %{result: relative_time(dt)}}

      {:error, _} ->
        {:error, "Invalid ISO 8601 datetime"}
    end
  end

  def execute(%{"action" => "add_days", "date" => date_string, "days" => days}, _caps)
      when is_binary(date_string) and is_integer(days) do
    case Date.from_iso8601(date_string) do
      {:ok, date} ->
        result = Date.add(date, days)
        {:ok, %{result: Date.to_iso8601(result)}}

      {:error, _} ->
        {:error, "Invalid date format (expected YYYY-MM-DD)"}
    end
  end

  def execute(%{"action" => "format", "date" => date_string} = params, _caps)
      when is_binary(date_string) do
    format = Map.get(params, "format", "%Y-%m-%d")

    cond do
      String.length(format) > 100 ->
        {:error, "Format string too long (max 100 characters)"}

      String.contains?(format, "%{") ->
        {:error, "Invalid format directive"}

      true ->
        case Date.from_iso8601(date_string) do
          {:ok, date} ->
            {:ok, %{result: Calendar.strftime(date, format)}}

          {:error, _} ->
            {:error, "Invalid date format (expected YYYY-MM-DD)"}
        end
    end
  end

  def execute(%{"action" => "day_of_week", "date" => date_string}, _caps)
      when is_binary(date_string) do
    case Date.from_iso8601(date_string) do
      {:ok, date} ->
        day_name = day_name(Date.day_of_week(date))
        {:ok, %{result: day_name}}

      {:error, _} ->
        {:error, "Invalid date format (expected YYYY-MM-DD)"}
    end
  end

  def execute(%{"action" => "days_between", "from" => from_str, "to" => to_str}, _caps)
      when is_binary(from_str) and is_binary(to_str) do
    with {:ok, from_date} <- Date.from_iso8601(from_str),
         {:ok, to_date} <- Date.from_iso8601(to_str) do
      {:ok, %{result: Date.diff(to_date, from_date)}}
    else
      {:error, _} -> {:error, "Invalid date format (expected YYYY-MM-DD)"}
    end
  end

  def execute(%{"action" => "is_weekend", "date" => date_string}, _caps)
      when is_binary(date_string) do
    case Date.from_iso8601(date_string) do
      {:ok, date} ->
        dow = Date.day_of_week(date)
        {:ok, %{result: dow in [6, 7]}}

      {:error, _} ->
        {:error, "Invalid date format (expected YYYY-MM-DD)"}
    end
  end

  def execute(%{"action" => _}, _caps), do: {:error, "Unknown action or missing parameters"}
  def execute(_params, _caps), do: {:error, "Missing required parameter: action"}

  defp relative_time(dt) do
    now = DateTime.utc_now()
    diff = DateTime.diff(now, dt, :second)

    cond do
      diff < 0 -> "in the future"
      diff < 60 -> "#{diff} second#{plural(diff)} ago"
      diff < 3600 -> "#{div(diff, 60)} minute#{plural(div(diff, 60))} ago"
      diff < 86_400 -> "#{div(diff, 3600)} hour#{plural(div(diff, 3600))} ago"
      diff < 2_592_000 -> "#{div(diff, 86_400)} day#{plural(div(diff, 86_400))} ago"
      true -> "#{div(diff, 2_592_000)} month#{plural(div(diff, 2_592_000))} ago"
    end
  end

  defp plural(1), do: ""
  defp plural(_), do: "s"

  defp day_name(1), do: "Monday"
  defp day_name(2), do: "Tuesday"
  defp day_name(3), do: "Wednesday"
  defp day_name(4), do: "Thursday"
  defp day_name(5), do: "Friday"
  defp day_name(6), do: "Saturday"
  defp day_name(7), do: "Sunday"
end
