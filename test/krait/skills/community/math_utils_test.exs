defmodule Krait.Skills.Community.MathUtilsTest do
  use ExUnit.Case, async: true

  alias Krait.Skills.Community.MathUtils

  describe "behaviour compliance" do
    test "implements CapableSkill callbacks" do
      assert function_exported?(MathUtils, :name, 0)
      assert function_exported?(MathUtils, :description, 0)
      assert function_exported?(MathUtils, :required_capabilities, 0)
      assert function_exported?(MathUtils, :execute, 2)
    end

    test "name returns expected value" do
      assert MathUtils.name() == "math_utils"
    end

    test "requires no capabilities" do
      assert MathUtils.required_capabilities() == []
    end
  end

  describe "mean action" do
    test "calculates arithmetic mean" do
      assert {:ok, %{result: 3.0}} =
               MathUtils.execute(%{"action" => "mean", "numbers" => [1, 2, 3, 4, 5]}, %{})
    end

    test "returns error for empty list" do
      assert {:error, _} =
               MathUtils.execute(%{"action" => "mean", "numbers" => []}, %{})
    end
  end

  describe "median action" do
    test "calculates median for odd count" do
      assert {:ok, %{result: 3}} =
               MathUtils.execute(%{"action" => "median", "numbers" => [1, 3, 5, 2, 4]}, %{})
    end

    test "calculates median for even count" do
      assert {:ok, %{result: 2.5}} =
               MathUtils.execute(%{"action" => "median", "numbers" => [1, 2, 3, 4]}, %{})
    end
  end

  describe "mode action" do
    test "finds most frequent value" do
      assert {:ok, %{result: [2]}} =
               MathUtils.execute(%{"action" => "mode", "numbers" => [1, 2, 2, 3]}, %{})
    end

    test "returns multiple modes" do
      assert {:ok, %{result: modes}} =
               MathUtils.execute(%{"action" => "mode", "numbers" => [1, 1, 2, 2, 3]}, %{})

      assert Enum.sort(modes) == [1, 2]
    end
  end

  describe "stddev action" do
    test "calculates population standard deviation" do
      assert {:ok, %{result: stddev}} =
               MathUtils.execute(
                 %{"action" => "stddev", "numbers" => [2, 4, 4, 4, 5, 5, 7, 9]},
                 %{}
               )

      assert_in_delta stddev, 2.0, 0.01
    end
  end

  describe "percentile action" do
    test "calculates nth percentile" do
      assert {:ok, %{result: _}} =
               MathUtils.execute(
                 %{
                   "action" => "percentile",
                   "numbers" => [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                   "p" => 50
                 },
                 %{}
               )
    end

    test "returns error for invalid percentile" do
      assert {:error, _} =
               MathUtils.execute(
                 %{"action" => "percentile", "numbers" => [1, 2, 3], "p" => 101},
                 %{}
               )
    end
  end

  describe "factorial action" do
    test "computes factorial" do
      assert {:ok, %{result: 120}} =
               MathUtils.execute(%{"action" => "factorial", "n" => 5}, %{})
    end

    test "factorial of 0 is 1" do
      assert {:ok, %{result: 1}} =
               MathUtils.execute(%{"action" => "factorial", "n" => 0}, %{})
    end

    test "rejects negative input" do
      assert {:error, _} =
               MathUtils.execute(%{"action" => "factorial", "n" => -1}, %{})
    end

    test "rejects very large input" do
      assert {:error, _} =
               MathUtils.execute(%{"action" => "factorial", "n" => 1001}, %{})
    end
  end

  describe "gcd action" do
    test "computes greatest common divisor" do
      assert {:ok, %{result: 6}} =
               MathUtils.execute(%{"action" => "gcd", "a" => 12, "b" => 18}, %{})
    end

    test "gcd with zero" do
      assert {:ok, %{result: 5}} =
               MathUtils.execute(%{"action" => "gcd", "a" => 5, "b" => 0}, %{})
    end
  end

  describe "fibonacci action" do
    test "computes nth fibonacci number" do
      assert {:ok, %{result: 55}} =
               MathUtils.execute(%{"action" => "fibonacci", "n" => 10}, %{})
    end

    test "fibonacci of 0 is 0" do
      assert {:ok, %{result: 0}} =
               MathUtils.execute(%{"action" => "fibonacci", "n" => 0}, %{})
    end

    test "fibonacci of 1 is 1" do
      assert {:ok, %{result: 1}} =
               MathUtils.execute(%{"action" => "fibonacci", "n" => 1}, %{})
    end

    test "rejects very large input" do
      assert {:error, _} =
               MathUtils.execute(%{"action" => "fibonacci", "n" => 1001}, %{})
    end
  end

  describe "error cases" do
    test "returns error for unknown action" do
      assert {:error, _} =
               MathUtils.execute(%{"action" => "unknown"}, %{})
    end

    test "returns error for missing action" do
      assert {:error, _} =
               MathUtils.execute(%{"numbers" => [1, 2, 3]}, %{})
    end
  end
end
