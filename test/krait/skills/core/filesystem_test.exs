defmodule Krait.Skills.Core.FilesystemTest do
  use ExUnit.Case, async: true

  test "rejects path traversal attacks" do
    assert {:error, _} =
             Krait.Skills.Core.Filesystem.execute(%{
               "action" => "read",
               "path" => "../../../etc/passwd"
             })
  end

  test "rejects paths outside sandbox" do
    assert {:error, _} =
             Krait.Skills.Core.Filesystem.execute(%{"action" => "read", "path" => "/etc/passwd"})
  end

  test "reads a file within the project" do
    assert {:ok, %{content: content}} =
             Krait.Skills.Core.Filesystem.execute(%{"action" => "read", "path" => "mix.exs"})

    assert content =~ "Krait.MixProject"
  end

  test "lists directory entries" do
    assert {:ok, %{entries: entries}} =
             Krait.Skills.Core.Filesystem.execute(%{"action" => "list", "path" => "lib"})

    assert "krait" in entries or "krait_web" in entries or "krait_web.ex" in entries
  end

  describe "sensitive file blocking (M-14)" do
    test "rejects .env file" do
      assert {:error, msg} =
               Krait.Skills.Core.Filesystem.execute(%{"action" => "read", "path" => ".env"})

      assert msg =~ "outside sandbox or restricted"
    end

    test "rejects .env.production in subdirectory" do
      assert {:error, msg} =
               Krait.Skills.Core.Filesystem.execute(%{
                 "action" => "read",
                 "path" => "config/.env.production"
               })

      assert msg =~ "outside sandbox or restricted"
    end

    test "rejects .pem certificate files" do
      assert {:error, msg} =
               Krait.Skills.Core.Filesystem.execute(%{
                 "action" => "read",
                 "path" => "certs/server.pem"
               })

      assert msg =~ "outside sandbox or restricted"
    end

    test "rejects .key private key files" do
      assert {:error, msg} =
               Krait.Skills.Core.Filesystem.execute(%{
                 "action" => "read",
                 "path" => "certs/server.key"
               })

      assert msg =~ "outside sandbox or restricted"
    end

    test "rejects credentials.json" do
      assert {:error, msg} =
               Krait.Skills.Core.Filesystem.execute(%{
                 "action" => "read",
                 "path" => "credentials.json"
               })

      assert msg =~ "outside sandbox or restricted"
    end

    test "rejects id_rsa" do
      assert {:error, msg} =
               Krait.Skills.Core.Filesystem.execute(%{
                 "action" => "read",
                 "path" => "keys/id_rsa"
               })

      assert msg =~ "outside sandbox or restricted"
    end

    test "list action still works on directories" do
      assert {:ok, %{entries: entries}} =
               Krait.Skills.Core.Filesystem.execute(%{"action" => "list", "path" => "lib"})

      assert is_list(entries)
    end

    test "legitimate .ex files still readable" do
      assert {:ok, %{content: content}} =
               Krait.Skills.Core.Filesystem.execute(%{
                 "action" => "read",
                 "path" => "lib/krait/application.ex"
               })

      assert content =~ "Krait.Application"
    end
  end

  describe "proc/sys/dev blocking" do
    test "rejects /proc/self/environ" do
      assert {:error, _} =
               Krait.Skills.Core.Filesystem.execute(%{
                 "action" => "read",
                 "path" => "/proc/self/environ"
               })
    end

    test "rejects /sys/kernel/hostname" do
      assert {:error, _} =
               Krait.Skills.Core.Filesystem.execute(%{
                 "action" => "read",
                 "path" => "/sys/kernel/hostname"
               })
    end

    test "rejects /dev/random" do
      assert {:error, _} =
               Krait.Skills.Core.Filesystem.execute(%{
                 "action" => "read",
                 "path" => "/dev/random"
               })
    end
  end

  describe "configurable sandbox root" do
    setup do
      original = Application.get_env(:krait, :filesystem_sandbox_root)

      on_exit(fn ->
        if original do
          Application.put_env(:krait, :filesystem_sandbox_root, original)
        else
          Application.delete_env(:krait, :filesystem_sandbox_root)
        end
      end)

      :ok
    end

    test "respects configured sandbox root" do
      Application.put_env(:krait, :filesystem_sandbox_root, "/nonexistent")

      assert {:error, msg} =
               Krait.Skills.Core.Filesystem.execute(%{
                 "action" => "read",
                 "path" => "mix.exs"
               })

      assert msg =~ "outside sandbox or restricted"
    end
  end

  describe "symlink traversal protection" do
    test "rejects symlinks that point outside sandbox" do
      # Create a temporary symlink that points outside the sandbox
      symlink_path = Path.join(File.cwd!(), "test_escape_symlink")
      File.rm(symlink_path)
      File.ln_s("/etc/passwd", symlink_path)

      on_exit(fn -> File.rm(symlink_path) end)

      assert {:error, msg} =
               Krait.Skills.Core.Filesystem.execute(%{
                 "action" => "read",
                 "path" => "test_escape_symlink"
               })

      assert msg =~ "symlink escapes sandbox"
    end

    test "allows symlinks that stay within sandbox" do
      # Create a symlink that stays within the project
      symlink_path = Path.join(File.cwd!(), "test_safe_symlink")
      File.rm(symlink_path)
      File.ln_s("mix.exs", symlink_path)

      on_exit(fn -> File.rm(symlink_path) end)

      assert {:ok, %{content: content}} =
               Krait.Skills.Core.Filesystem.execute(%{
                 "action" => "read",
                 "path" => "test_safe_symlink"
               })

      assert content =~ "Krait.MixProject"
    end

    test "rejects 2-hop symlink chain escaping sandbox" do
      # Chain: hop1 -> hop2 -> /etc/passwd
      hop2_path = Path.join(File.cwd!(), "test_hop2_symlink")
      hop1_path = Path.join(File.cwd!(), "test_hop1_symlink")
      File.rm(hop1_path)
      File.rm(hop2_path)

      File.ln_s("/etc/passwd", hop2_path)
      File.ln_s("test_hop2_symlink", hop1_path)

      on_exit(fn ->
        File.rm(hop1_path)
        File.rm(hop2_path)
      end)

      assert {:error, msg} =
               Krait.Skills.Core.Filesystem.execute(%{
                 "action" => "read",
                 "path" => "test_hop1_symlink"
               })

      assert msg =~ "symlink escapes sandbox"
    end

    test "rejects 3-hop symlink chain escaping sandbox" do
      # Chain: hop1 -> hop2 -> hop3 -> /etc/passwd
      hop3_path = Path.join(File.cwd!(), "test_hop3_symlink")
      hop2_path = Path.join(File.cwd!(), "test_chain_hop2_symlink")
      hop1_path = Path.join(File.cwd!(), "test_chain_hop1_symlink")
      File.rm(hop1_path)
      File.rm(hop2_path)
      File.rm(hop3_path)

      File.ln_s("/etc/passwd", hop3_path)
      File.ln_s("test_hop3_symlink", hop2_path)
      File.ln_s("test_chain_hop2_symlink", hop1_path)

      on_exit(fn ->
        File.rm(hop1_path)
        File.rm(hop2_path)
        File.rm(hop3_path)
      end)

      assert {:error, msg} =
               Krait.Skills.Core.Filesystem.execute(%{
                 "action" => "read",
                 "path" => "test_chain_hop1_symlink"
               })

      assert msg =~ "symlink escapes sandbox"
    end
  end
end
