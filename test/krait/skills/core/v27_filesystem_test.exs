defmodule Krait.Skills.Core.V27FilesystemTest do
  @moduledoc "v27 H-2: Filesystem skill symlink TOCTOU hardening tests"
  use ExUnit.Case, async: false

  alias Krait.Skills.Core.Filesystem

  setup do
    # Create sandbox and outside dirs under project root (not /tmp, which is in blocked_prefixes)
    project_root = File.cwd!()
    rand = :crypto.strong_rand_bytes(4) |> Base.url_encode64(padding: false)

    sandbox = Path.join(project_root, "_v27_sandbox_#{rand}")
    outside = Path.join(project_root, "_v27_outside_#{rand}")

    File.mkdir_p!(sandbox)
    File.mkdir_p!(outside)

    prev_root = Application.get_env(:krait, :filesystem_sandbox_root)
    Application.put_env(:krait, :filesystem_sandbox_root, sandbox)

    on_exit(fn ->
      File.rm_rf!(sandbox)
      File.rm_rf!(outside)

      if prev_root do
        Application.put_env(:krait, :filesystem_sandbox_root, prev_root)
      else
        Application.delete_env(:krait, :filesystem_sandbox_root)
      end
    end)

    {:ok, sandbox: sandbox, outside: outside}
  end

  describe "safe_read symlink TOCTOU protection" do
    test "reads normal file inside sandbox", %{sandbox: sandbox} do
      file = Path.join(sandbox, "normal.txt")
      File.write!(file, "hello world")

      assert {:ok, %{content: "hello world"}} =
               Filesystem.execute(%{"action" => "read", "path" => file})
    end

    test "rejects symlink pointing outside sandbox", %{sandbox: sandbox, outside: outside} do
      # Create a file outside the sandbox (but not in blocked_prefixes)
      outside_file = Path.join(outside, "secret.txt")
      File.write!(outside_file, "secret data")

      # Create a symlink inside sandbox pointing outside
      link_path = Path.join(sandbox, "escape_link")
      File.ln_s!(outside_file, link_path)

      result = Filesystem.execute(%{"action" => "read", "path" => link_path})
      assert {:error, msg} = result
      assert msg =~ "symlink" or msg =~ "sandbox" or msg =~ "rejected"
    end

    test "rejects symlink created in directory chain", %{sandbox: sandbox, outside: outside} do
      # Create subdir with symlink pointing outside sandbox
      subdir = Path.join(sandbox, "subdir")
      File.mkdir_p!(subdir)

      File.write!(Path.join(outside, "data.txt"), "escaped!")

      # Create symlink from sandbox/subdir/link -> outside dir
      link = Path.join(subdir, "link")
      File.ln_s!(outside, link)

      # Try to read through the symlink chain
      target = Path.join(link, "data.txt")
      result = Filesystem.execute(%{"action" => "read", "path" => target})
      assert {:error, msg} = result
      assert msg =~ "symlink" or msg =~ "sandbox" or msg =~ "rejected"
    end
  end
end
