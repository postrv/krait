defmodule Krait.Skills.Community.CodeMetricsTest do
  use ExUnit.Case, async: true

  alias Krait.Skills.Community.CodeMetrics

  describe "behaviour compliance" do
    test "implements CapableSkill callbacks" do
      assert function_exported?(CodeMetrics, :name, 0)
      assert function_exported?(CodeMetrics, :description, 0)
      assert function_exported?(CodeMetrics, :required_capabilities, 0)
      assert function_exported?(CodeMetrics, :execute, 2)
    end

    test "name returns expected value" do
      assert CodeMetrics.name() == "code_metrics"
    end

    test "requires filesystem capability" do
      assert CodeMetrics.required_capabilities() == [:filesystem]
    end
  end

  # Mock filesystem capability for testing
  defmodule MockFilesystem do
    @sample_code """
    defmodule MyApp.Example do
      @moduledoc "Example module"

      # A helper function
      def hello(name) do
        "Hello, \#{name}!"
      end

      # Another function
      defp private_helper do
        :ok
      end

      def goodbye do
        "Bye!"
      end
    end
    """

    def read(_path), do: {:ok, %{content: @sample_code}}
  end

  defmodule ErrorFilesystem do
    def read(_path), do: {:error, "File not found"}
  end

  describe "line_count action" do
    test "counts lines in a file" do
      caps = %{filesystem: MockFilesystem}

      assert {:ok, %{line_count: count}} =
               CodeMetrics.execute(%{"action" => "line_count", "path" => "lib/example.ex"}, caps)

      assert count > 0
    end
  end

  describe "function_count action" do
    test "counts def and defp functions" do
      caps = %{filesystem: MockFilesystem}

      assert {:ok, %{function_count: count, public: pub, private: priv}} =
               CodeMetrics.execute(
                 %{"action" => "function_count", "path" => "lib/example.ex"},
                 caps
               )

      assert count == 3
      assert pub == 2
      assert priv == 1
    end
  end

  describe "module_count action" do
    test "counts defmodule declarations" do
      caps = %{filesystem: MockFilesystem}

      assert {:ok, %{module_count: 1}} =
               CodeMetrics.execute(
                 %{"action" => "module_count", "path" => "lib/example.ex"},
                 caps
               )
    end
  end

  describe "comment_ratio action" do
    test "calculates ratio of comment lines" do
      caps = %{filesystem: MockFilesystem}

      assert {:ok, %{comment_ratio: ratio, comment_lines: _, total_lines: _}} =
               CodeMetrics.execute(
                 %{"action" => "comment_ratio", "path" => "lib/example.ex"},
                 caps
               )

      assert is_float(ratio)
      assert ratio >= 0.0 and ratio <= 1.0
    end
  end

  describe "error cases" do
    test "returns error for unknown action" do
      assert {:error, _} =
               CodeMetrics.execute(%{"action" => "unknown", "path" => "lib/x.ex"}, %{
                 filesystem: MockFilesystem
               })
    end

    test "returns error for missing path" do
      assert {:error, _} =
               CodeMetrics.execute(%{"action" => "line_count"}, %{filesystem: MockFilesystem})
    end

    test "propagates filesystem errors" do
      caps = %{filesystem: ErrorFilesystem}

      assert {:error, _} =
               CodeMetrics.execute(%{"action" => "line_count", "path" => "lib/missing.ex"}, caps)
    end
  end
end
