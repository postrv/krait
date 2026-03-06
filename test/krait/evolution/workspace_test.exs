defmodule Krait.Evolution.WorkspaceTest do
  use ExUnit.Case, async: true

  alias Krait.Evolution.Workspace

  describe "apply_files/2 path containment" do
    setup do
      workspace_dir =
        Path.join(System.tmp_dir!(), "krait_ws_test_#{System.unique_integer([:positive])}")

      File.mkdir_p!(workspace_dir)
      on_exit(fn -> File.rm_rf!(workspace_dir) end)
      %{workspace_dir: workspace_dir}
    end

    test "rejects path with .. traversal", %{workspace_dir: ws} do
      files = [%{path: "../../etc/passwd", content: "evil"}]
      assert {:error, {:path_traversal, "../../etc/passwd"}} = Workspace.apply_files(ws, files)
    end

    test "rejects absolute path", %{workspace_dir: ws} do
      files = [%{path: "/etc/hosts", content: "evil"}]
      assert {:error, {:path_traversal, "/etc/hosts"}} = Workspace.apply_files(ws, files)
    end

    test "rejects nested escape via ..", %{workspace_dir: ws} do
      files = [%{path: "lib/../../../etc/shadow", content: "evil"}]

      assert {:error, {:path_traversal, "lib/../../../etc/shadow"}} =
               Workspace.apply_files(ws, files)
    end

    test "accepts valid relative path", %{workspace_dir: ws} do
      files = [
        %{path: "lib/krait/skills/community/my_skill.ex", content: "defmodule MySkill, do: :ok"}
      ]

      assert :ok = Workspace.apply_files(ws, files)
      assert File.exists?(Path.join(ws, "lib/krait/skills/community/my_skill.ex"))
    end

    test "stops at first bad path in batch", %{workspace_dir: ws} do
      files = [
        %{path: "lib/good.ex", content: "good"},
        %{path: "../../etc/evil", content: "evil"},
        %{path: "lib/also_good.ex", content: "good"}
      ]

      assert {:error, {:path_traversal, "../../etc/evil"}} = Workspace.apply_files(ws, files)
      # First file may or may not have been written (reduce_while stops at first bad)
      refute File.exists?(Path.join(ws, "lib/also_good.ex"))
    end
  end

  describe "apply_files/2 symlink escape protection" do
    setup do
      workspace_dir =
        Path.join(System.tmp_dir!(), "krait_ws_symlink_#{System.unique_integer([:positive])}")

      File.mkdir_p!(workspace_dir)
      on_exit(fn -> File.rm_rf!(workspace_dir) end)
      %{workspace_dir: workspace_dir}
    end

    test "rejects symlink that escapes workspace", %{workspace_dir: ws} do
      # Create a symlink inside the workspace pointing outside
      escape_link = Path.join(ws, "escape")
      File.ln_s!("/tmp", escape_link)

      files = [%{path: "escape/evil.txt", content: "pwned"}]

      assert {:error, {:path_escape, "escape/evil.txt"}} = Workspace.apply_files(ws, files)
    end

    test "rejects path containing .. segments", %{workspace_dir: ws} do
      files = [%{path: "../etc/passwd", content: "evil"}]
      assert {:error, {:path_traversal, "../etc/passwd"}} = Workspace.apply_files(ws, files)
    end

    test "rejects absolute path", %{workspace_dir: ws} do
      files = [%{path: "/etc/hosts", content: "evil"}]
      assert {:error, {:path_traversal, "/etc/hosts"}} = Workspace.apply_files(ws, files)
    end

    test "accepts normal relative path without symlinks", %{workspace_dir: ws} do
      files = [%{path: "lib/safe.ex", content: "defmodule Safe, do: :ok"}]
      assert :ok = Workspace.apply_files(ws, files)
      assert File.exists?(Path.join(ws, "lib/safe.ex"))
    end
  end

  # v10: M7 — repo_url scheme validation
  describe "setup/2 repo_url scheme validation" do
    test "file:// URL rejected" do
      assert {:error, :invalid_repo_url} =
               Workspace.setup("file:///etc/passwd", "test-branch")
    end

    test "gopher:// URL rejected" do
      assert {:error, :invalid_repo_url} =
               Workspace.setup("gopher://evil.com/repo", "test-branch")
    end

    test "https:// URL accepted (fails at clone, not URL validation)" do
      result = Workspace.setup("https://github.com/test/repo", "test-branch")
      assert result != {:error, :invalid_repo_url}
    end
  end

  describe "setup/2 branch name validation" do
    test "rejects branch name that looks like a git flag" do
      assert {:error, :invalid_branch_name} =
               Workspace.setup("https://example.com/repo.git", "--orphan")
    end

    test "rejects branch name with shell metacharacters" do
      assert {:error, :invalid_branch_name} =
               Workspace.setup("https://example.com/repo.git", "branch; rm -rf /")
    end

    test "rejects empty branch name" do
      assert {:error, :invalid_branch_name} = Workspace.setup("https://example.com/repo.git", "")
    end

    test "rejects branch name with path traversal" do
      assert {:error, :invalid_branch_name} =
               Workspace.setup("https://example.com/repo.git", "../../hack")
    end

    test "accepts standard krait branch format" do
      # This will fail at clone (no real repo), but branch name validation passes
      result = Workspace.setup("https://example.com/repo.git", "krait/evolve-bitcoin-1234567890")
      # Should not be :invalid_branch_name error
      assert result != {:error, :invalid_branch_name}
    end

    test "accepts feature branch with slashes" do
      result = Workspace.setup("https://example.com/repo.git", "feature/my-branch")
      assert result != {:error, :invalid_branch_name}
    end

    test "rejects branch name starting with dot" do
      assert {:error, :invalid_branch_name} =
               Workspace.setup("https://example.com/repo.git", ".hidden")
    end

    test "rejects branch name starting with hyphen" do
      assert {:error, :invalid_branch_name} =
               Workspace.setup("https://example.com/repo.git", "-flag")
    end
  end

  describe "v25 H-2: sandboxed compile_and_test" do
    test "uses Docker when allow_local_execution is false" do
      prev = Application.get_env(:krait, :allow_local_execution)
      Application.put_env(:krait, :allow_local_execution, false)

      on_exit(fn ->
        if prev != nil,
          do: Application.put_env(:krait, :allow_local_execution, prev),
          else: Application.delete_env(:krait, :allow_local_execution)
      end)

      # Will fail because docker container/image doesn't exist, but it proves
      # the sandboxed path is taken (error is from docker, not local mix)
      result = Workspace.compile_and_test("/tmp/fake_workspace")
      assert {:error, {:cmd_failed, "docker", _, _}} = result
    end

    test "uses local execution when allow_local_execution and accept_host_execution_risk are true" do
      prev_local = Application.get_env(:krait, :allow_local_execution)
      prev_risk = Application.get_env(:krait, :accept_host_execution_risk)
      Application.put_env(:krait, :allow_local_execution, true)
      Application.put_env(:krait, :accept_host_execution_risk, true)

      on_exit(fn ->
        if prev_local != nil,
          do: Application.put_env(:krait, :allow_local_execution, prev_local),
          else: Application.delete_env(:krait, :allow_local_execution)

        if prev_risk != nil,
          do: Application.put_env(:krait, :accept_host_execution_risk, prev_risk),
          else: Application.delete_env(:krait, :accept_host_execution_risk)
      end)

      # Will fail because there's no mix project in the dir, but the error
      # is from local mix, not from docker
      result = Workspace.compile_and_test("/tmp/fake_workspace")
      assert {:error, {:cmd_failed, "mix", _, _}} = result
    end

    test "sandboxed_run_cmd invokes docker" do
      result =
        Workspace.sandboxed_run_cmd(
          "krait-sandbox:latest",
          ["mix", "test"],
          workspace_dir: "/tmp/test",
          timeout: 5_000
        )

      # Will fail because docker image doesn't exist, but we verify it tried docker
      assert {:error, {error_type, "docker", _, _}} = result
      assert error_type in [:cmd_failed, :cmd_error]
    end
  end

  describe "v22 SEC-19: cleanup symlink resolution" do
    test "normal krait workspace is cleaned up successfully" do
      tmp = System.tmp_dir!()

      workspace =
        Path.join(tmp, "krait_workspace_cleanup_test_#{System.unique_integer([:positive])}")

      File.mkdir_p!(workspace)
      File.write!(Path.join(workspace, "test.txt"), "data")

      assert :ok = Workspace.cleanup(workspace)
      refute File.exists?(workspace)
    end

    test "rejects paths not under tmp_dir" do
      assert {:error, :invalid_cleanup_path} = Workspace.cleanup("/etc/krait-evil")
    end

    test "rejects paths that don't contain krait identifier" do
      tmp = System.tmp_dir!()
      workspace = Path.join(tmp, "totally_unrelated_#{System.unique_integer([:positive])}")
      File.mkdir_p!(workspace)

      on_exit(fn -> File.rm_rf(workspace) end)

      assert {:error, :invalid_cleanup_path} = Workspace.cleanup(workspace)
    end
  end
end
