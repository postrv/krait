defmodule Krait.Skills.Community.TextTransformTest do
  use ExUnit.Case, async: true

  alias Krait.Skills.Community.TextTransform

  describe "behaviour compliance" do
    test "implements CapableSkill callbacks" do
      assert Code.ensure_loaded?(TextTransform)
      assert function_exported?(TextTransform, :name, 0)
      assert function_exported?(TextTransform, :description, 0)
      assert function_exported?(TextTransform, :required_capabilities, 0)
      assert function_exported?(TextTransform, :execute, 2)
    end

    test "name returns expected value" do
      assert TextTransform.name() == "text_transform"
    end

    test "description is non-empty" do
      assert is_binary(TextTransform.description())
      assert String.length(TextTransform.description()) > 0
    end

    test "requires no capabilities" do
      assert TextTransform.required_capabilities() == []
    end
  end

  describe "uppercase action" do
    test "converts text to uppercase" do
      assert {:ok, %{result: "HELLO WORLD"}} =
               TextTransform.execute(%{"action" => "uppercase", "text" => "hello world"}, %{})
    end

    test "handles empty string" do
      assert {:ok, %{result: ""}} =
               TextTransform.execute(%{"action" => "uppercase", "text" => ""}, %{})
    end
  end

  describe "lowercase action" do
    test "converts text to lowercase" do
      assert {:ok, %{result: "hello world"}} =
               TextTransform.execute(%{"action" => "lowercase", "text" => "HELLO WORLD"}, %{})
    end
  end

  describe "reverse action" do
    test "reverses the text" do
      assert {:ok, %{result: "dlrow olleh"}} =
               TextTransform.execute(%{"action" => "reverse", "text" => "hello world"}, %{})
    end

    test "handles empty string" do
      assert {:ok, %{result: ""}} =
               TextTransform.execute(%{"action" => "reverse", "text" => ""}, %{})
    end
  end

  describe "word_count action" do
    test "counts words in text" do
      assert {:ok, %{result: 3}} =
               TextTransform.execute(
                 %{"action" => "word_count", "text" => "hello beautiful world"},
                 %{}
               )
    end

    test "returns 0 for empty string" do
      assert {:ok, %{result: 0}} =
               TextTransform.execute(%{"action" => "word_count", "text" => ""}, %{})
    end

    test "handles extra whitespace" do
      assert {:ok, %{result: 2}} =
               TextTransform.execute(
                 %{"action" => "word_count", "text" => "  hello   world  "},
                 %{}
               )
    end
  end

  describe "slug action" do
    test "converts text to URL slug" do
      assert {:ok, %{result: "hello-beautiful-world"}} =
               TextTransform.execute(
                 %{"action" => "slug", "text" => "Hello Beautiful World!"},
                 %{}
               )
    end

    test "handles special characters" do
      assert {:ok, %{result: "hello-world-123"}} =
               TextTransform.execute(%{"action" => "slug", "text" => "Hello & World @123"}, %{})
    end

    test "collapses multiple hyphens" do
      assert {:ok, %{result: "hello-world"}} =
               TextTransform.execute(%{"action" => "slug", "text" => "hello---world"}, %{})
    end
  end

  describe "snake_case action" do
    test "converts camelCase to snake_case" do
      assert {:ok, %{result: "hello_world"}} =
               TextTransform.execute(%{"action" => "snake_case", "text" => "helloWorld"}, %{})
    end

    test "converts PascalCase to snake_case" do
      assert {:ok, %{result: "hello_world"}} =
               TextTransform.execute(%{"action" => "snake_case", "text" => "HelloWorld"}, %{})
    end

    test "handles spaces" do
      assert {:ok, %{result: "hello_world"}} =
               TextTransform.execute(%{"action" => "snake_case", "text" => "Hello World"}, %{})
    end
  end

  describe "title_case action" do
    test "capitalizes first letter of each word" do
      assert {:ok, %{result: "Hello Beautiful World"}} =
               TextTransform.execute(
                 %{"action" => "title_case", "text" => "hello beautiful world"},
                 %{}
               )
    end
  end

  describe "truncate action" do
    test "truncates text to specified length" do
      assert {:ok, %{result: "hello wo..."}} =
               TextTransform.execute(
                 %{"action" => "truncate", "text" => "hello world", "max_length" => "8"},
                 %{}
               )
    end

    test "does not truncate short text" do
      assert {:ok, %{result: "hi"}} =
               TextTransform.execute(
                 %{"action" => "truncate", "text" => "hi", "max_length" => "10"},
                 %{}
               )
    end

    test "defaults to 100 characters" do
      long_text = String.duplicate("a", 150)

      assert {:ok, %{result: result}} =
               TextTransform.execute(%{"action" => "truncate", "text" => long_text}, %{})

      assert String.length(result) <= 103
      assert String.ends_with?(result, "...")
    end
  end

  describe "error cases" do
    test "returns error for unknown action" do
      assert {:error, _} =
               TextTransform.execute(%{"action" => "unknown", "text" => "hello"}, %{})
    end

    test "returns error for missing text param" do
      assert {:error, _} = TextTransform.execute(%{"action" => "uppercase"}, %{})
    end

    test "returns error for missing action" do
      assert {:error, _} = TextTransform.execute(%{"text" => "hello"}, %{})
    end
  end
end
