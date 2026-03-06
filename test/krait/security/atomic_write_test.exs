defmodule Krait.Security.AtomicWriteTest do
  use ExUnit.Case, async: true

  alias Krait.Security.AtomicWrite

  setup do
    workspace =
      Path.join(System.tmp_dir!(), "krait_atomic_test_#{System.unique_integer([:positive])}")

    File.mkdir_p!(workspace)
    on_exit(fn -> File.rm_rf!(workspace) end)
    %{workspace: workspace}
  end

  test "writes file atomically via temp-then-rename", %{workspace: workspace} do
    assert :ok = AtomicWrite.write_safe(workspace, "hello.txt", "world")
    assert File.read!(Path.join(workspace, "hello.txt")) == "world"
  end

  test "creates intermediate directories", %{workspace: workspace} do
    assert :ok = AtomicWrite.write_safe(workspace, "a/b/c.txt", "nested")
    assert File.read!(Path.join(workspace, "a/b/c.txt")) == "nested"
  end

  test "cleans up temp file on validation failure", %{workspace: workspace} do
    # Create a symlink escape: workspace/escape -> /tmp
    escape_link = Path.join(workspace, "escape")
    File.ln_s!("/tmp", escape_link)

    result = AtomicWrite.write_safe(workspace, "escape/evil.txt", "bad")
    assert {:error, _} = result

    # No temp files should remain
    temps =
      workspace
      |> File.ls!()
      |> Enum.filter(&String.starts_with?(&1, ".krait_tmp_"))

    assert temps == []
  end

  test "validates final path after write", %{workspace: workspace} do
    assert :ok = AtomicWrite.write_safe(workspace, "safe/file.ex", "content")
    assert File.exists?(Path.join(workspace, "safe/file.ex"))
  end

  test "rejects file if post-write realpath resolves outside workspace", %{workspace: workspace} do
    # Create symlink that escapes workspace
    escape_dir = Path.join(workspace, "sneaky")
    File.ln_s!("/tmp", escape_dir)

    result = AtomicWrite.write_safe(workspace, "sneaky/evil.txt", "bad")
    assert {:error, {:path_escape, _}} = result
  end

  test "writes temp in target directory not workspace root", %{workspace: workspace} do
    assert :ok = AtomicWrite.write_safe(workspace, "sub/file.txt", "content")

    # No temp files should remain in workspace root
    temps =
      workspace
      |> File.ls!()
      |> Enum.filter(&String.starts_with?(&1, ".krait_tmp_"))

    assert temps == []

    # File should exist at expected path
    assert File.read!(Path.join(workspace, "sub/file.txt")) == "content"
  end

  test "rejects when target dir is symlink escaping workspace", %{workspace: workspace} do
    escape_target =
      System.tmp_dir!() |> Path.join("krait_escape_test_#{System.unique_integer([:positive])}")

    File.mkdir_p!(escape_target)
    on_exit(fn -> File.rm_rf!(escape_target) end)

    escape_link = Path.join(workspace, "escape_dir")
    File.ln_s!(escape_target, escape_link)

    result = AtomicWrite.write_safe(workspace, "escape_dir/evil.txt", "bad")
    assert {:error, {:path_escape, _}} = result

    # Ensure no file was written to the escape target
    refute File.exists?(Path.join(escape_target, "evil.txt"))
  end
end
