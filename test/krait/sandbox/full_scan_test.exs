defmodule Krait.Sandbox.FullScanTest do
  use ExUnit.Case, async: false

  describe "v22 SEC-04: resolve_narsil_binary/0" do
    setup do
      prev_env = Application.get_env(:krait, :env)
      prev_deep = Application.get_env(:krait, Krait.Analyzer.Deep)

      on_exit(fn ->
        if prev_env,
          do: Application.put_env(:krait, :env, prev_env),
          else: Application.delete_env(:krait, :env)

        if prev_deep,
          do: Application.put_env(:krait, Krait.Analyzer.Deep, prev_deep),
          else: Application.delete_env(:krait, Krait.Analyzer.Deep)
      end)

      :ok
    end

    test "prod env with relative path raises" do
      Application.put_env(:krait, :env, :prod)
      Application.put_env(:krait, Krait.Analyzer.Deep, narsil_binary: "narsil-mcp")

      assert_raise RuntimeError, ~r/must be an absolute path/, fn ->
        Krait.Sandbox.FullScan.resolve_narsil_binary()
      end
    end

    test "prod env with absolute path succeeds" do
      Application.put_env(:krait, :env, :prod)
      Application.put_env(:krait, Krait.Analyzer.Deep, narsil_binary: "/usr/local/bin/narsil-mcp")

      assert Krait.Sandbox.FullScan.resolve_narsil_binary() == "/usr/local/bin/narsil-mcp"
    end

    test "path with .. raises in any env" do
      Application.put_env(:krait, :env, :dev)
      Application.put_env(:krait, Krait.Analyzer.Deep, narsil_binary: "../malicious/narsil-mcp")

      assert_raise RuntimeError, ~r/must not contain '\.\.'/, fn ->
        Krait.Sandbox.FullScan.resolve_narsil_binary()
      end
    end

    test "dev env with relative path uses find_executable fallback" do
      Application.put_env(:krait, :env, :dev)
      Application.put_env(:krait, Krait.Analyzer.Deep, narsil_binary: "narsil-mcp")

      # Should not raise — falls back to find_executable or returns the name
      result = Krait.Sandbox.FullScan.resolve_narsil_binary()
      assert is_binary(result)
    end
  end
end
