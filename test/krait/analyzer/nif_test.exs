defmodule Krait.Analyzer.NifTest do
  use ExUnit.Case, async: true
  @moduletag :nif_required

  describe "Nif.quick_validate/2" do
    test "accepts valid Elixir code" do
      {:ok, %{complexity: c, hash: h}} =
        Krait.Analyzer.Nif.quick_validate("defmodule M do end", "elixir")

      assert is_integer(c)
      assert is_binary(h) and byte_size(h) == 64
    end

    test "rejects non-allowlisted Code.eval_string (KRAIT-ALW)" do
      {:policy_violation, %{rule: "KRAIT-ALW"}} =
        Krait.Analyzer.Nif.quick_validate(
          ~S'defmodule E do def r(s), do: Code.eval_string(s) end',
          "elixir"
        )
    end

    test "rejects non-allowlisted System.cmd (KRAIT-ALW)" do
      {:policy_violation, %{rule: "KRAIT-ALW"}} =
        Krait.Analyzer.Nif.quick_validate(
          ~S'defmodule E do def r(c), do: System.cmd("bash", ["-c", c]) end',
          "elixir"
        )
    end

    test "rejects non-allowlisted apply(System, :cmd, ...) (KRAIT-ALW)" do
      {:policy_violation, %{rule: "KRAIT-ALW"}} =
        Krait.Analyzer.Nif.quick_validate(
          ~S'defmodule E do def r(c), do: apply(System, :cmd, ["bash", ["-c", c]]) end',
          "elixir"
        )
    end

    test "rejects non-allowlisted Req.post! (KRAIT-ALW)" do
      {:policy_violation, %{rule: "KRAIT-ALW"}} =
        Krait.Analyzer.Nif.quick_validate(
          ~S'defmodule E do def r(u), do: Req.post!(u, body: "data") end',
          "elixir"
        )
    end

    test "rejects non-allowlisted Code.load_file (KRAIT-ALW)" do
      # Code module is not on the allowlist — KRAIT-ALW fires
      {:policy_violation, %{rule: "KRAIT-ALW"}} =
        Krait.Analyzer.Nif.quick_validate(
          ~S'defmodule E do def r(p), do: Code.load_file(p) end',
          "elixir"
        )
    end

    test "rejects non-allowlisted File module (KRAIT-ALW, immutable path targeting)" do
      {:policy_violation, %{rule: "KRAIT-ALW"}} =
        Krait.Analyzer.Nif.quick_validate(
          ~S'defmodule E do def r, do: File.write!("native/krait_analyzer/src/rules.rs", "") end',
          "elixir"
        )
    end

    test "produces BLAKE3 hash (different from SHA-256)" do
      {:ok, %{hash: nif_hash}} =
        Krait.Analyzer.Nif.quick_validate("defmodule M do end", "elixir")

      sha_hash = :crypto.hash(:sha256, "defmodule M do end") |> Base.encode16(case: :lower)
      assert nif_hash != sha_hash
    end

    test "same code produces same hash" do
      {:ok, %{hash: h1}} = Krait.Analyzer.Nif.quick_validate("defmodule M do end", "elixir")
      {:ok, %{hash: h2}} = Krait.Analyzer.Nif.quick_validate("defmodule M do end", "elixir")
      assert h1 == h2
    end

    test "detects syntax errors" do
      {:syntax_error, errors} =
        Krait.Analyzer.Nif.quick_validate("defmodule M do def foo(", "elixir")

      assert length(errors) > 0
    end
  end
end
