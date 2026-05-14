defmodule Krait.Skills.Community.DateHelperTest do
  use ExUnit.Case, async: true

  alias Krait.Skills.Community.DateHelper

  describe "behaviour compliance" do
    test "implements CapableSkill callbacks" do
      assert Code.ensure_loaded?(DateHelper)
      assert function_exported?(DateHelper, :name, 0)
      assert function_exported?(DateHelper, :description, 0)
      assert function_exported?(DateHelper, :required_capabilities, 0)
      assert function_exported?(DateHelper, :execute, 2)
    end

    test "name returns expected value" do
      assert DateHelper.name() == "date_helper"
    end

    test "requires no capabilities" do
      assert DateHelper.required_capabilities() == []
    end
  end

  describe "relative_time action" do
    test "formats past datetime as relative string" do
      past = DateTime.utc_now() |> DateTime.add(-3600, :second) |> DateTime.to_iso8601()

      assert {:ok, %{result: result}} =
               DateHelper.execute(%{"action" => "relative_time", "datetime" => past}, %{})

      assert result =~ "hour"
    end

    test "formats recent datetime" do
      recent = DateTime.utc_now() |> DateTime.add(-30, :second) |> DateTime.to_iso8601()

      assert {:ok, %{result: result}} =
               DateHelper.execute(%{"action" => "relative_time", "datetime" => recent}, %{})

      assert result =~ "second"
    end
  end

  describe "add_days action" do
    test "adds days to a date" do
      assert {:ok, %{result: "2024-01-11"}} =
               DateHelper.execute(
                 %{"action" => "add_days", "date" => "2024-01-01", "days" => 10},
                 %{}
               )
    end

    test "subtracts days with negative value" do
      assert {:ok, %{result: "2023-12-22"}} =
               DateHelper.execute(
                 %{"action" => "add_days", "date" => "2024-01-01", "days" => -10},
                 %{}
               )
    end

    test "returns error for invalid date" do
      assert {:error, _} =
               DateHelper.execute(
                 %{"action" => "add_days", "date" => "not-a-date", "days" => 1},
                 %{}
               )
    end
  end

  describe "format action" do
    test "formats date with custom format" do
      assert {:ok, %{result: "January 15, 2024"}} =
               DateHelper.execute(
                 %{"action" => "format", "date" => "2024-01-15", "format" => "%B %d, %Y"},
                 %{}
               )
    end

    test "uses default format without format param" do
      assert {:ok, %{result: "2024-01-15"}} =
               DateHelper.execute(
                 %{"action" => "format", "date" => "2024-01-15"},
                 %{}
               )
    end
  end

  describe "day_of_week action" do
    test "returns day name" do
      # 2024-01-15 is a Monday
      assert {:ok, %{result: "Monday"}} =
               DateHelper.execute(
                 %{"action" => "day_of_week", "date" => "2024-01-15"},
                 %{}
               )
    end
  end

  describe "days_between action" do
    test "calculates days between two dates" do
      assert {:ok, %{result: 31}} =
               DateHelper.execute(
                 %{"action" => "days_between", "from" => "2024-01-01", "to" => "2024-02-01"},
                 %{}
               )
    end

    test "returns negative for reversed dates" do
      assert {:ok, %{result: -31}} =
               DateHelper.execute(
                 %{"action" => "days_between", "from" => "2024-02-01", "to" => "2024-01-01"},
                 %{}
               )
    end
  end

  describe "is_weekend action" do
    test "identifies Saturday as weekend" do
      # 2024-01-13 is a Saturday
      assert {:ok, %{result: true}} =
               DateHelper.execute(
                 %{"action" => "is_weekend", "date" => "2024-01-13"},
                 %{}
               )
    end

    test "identifies Monday as weekday" do
      # 2024-01-15 is a Monday
      assert {:ok, %{result: false}} =
               DateHelper.execute(
                 %{"action" => "is_weekend", "date" => "2024-01-15"},
                 %{}
               )
    end
  end

  describe "error cases" do
    test "returns error for unknown action" do
      assert {:error, _} =
               DateHelper.execute(%{"action" => "unknown"}, %{})
    end

    test "returns error for missing action" do
      assert {:error, _} =
               DateHelper.execute(%{"date" => "2024-01-01"}, %{})
    end
  end
end
