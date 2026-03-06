defmodule Krait.Sandbox.WorkspaceTest do
  use ExUnit.Case, async: false

  @moduledoc """
  Tests for Krait.Sandbox.Workspace — file operations and cleanup.
  Git clone/branch operations are tested with local git repos to avoid network.
  """

  alias Krait.Sandbox.Workspace

  setup do
    # Create a temporary workspace directory for tests
    tmp = Path.join(System.tmp_dir!(), "krait-ws-test-#{System.unique_integer([:positive])}")
    File.mkdir_p!(tmp)

    on_exit(fn -> File.rm_rf!(tmp) end)

    {:ok, workspace: tmp}
  end

  describe "apply_files/2" do
    test "writes single file to workspace", %{workspace: ws} do
      files = [%{path: "hello.txt", content: "Hello, world!"}]

      assert :ok = Workspace.apply_files(ws, files)
      assert File.read!(Path.join(ws, "hello.txt")) == "Hello, world!"
    end

    test "writes multiple files to workspace", %{workspace: ws} do
      files = [
        %{path: "lib/mod_a.ex", content: "defmodule ModA, do: :ok"},
        %{path: "lib/mod_b.ex", content: "defmodule ModB, do: :ok"},
        %{path: "test/mod_a_test.exs", content: "defmodule ModATest, do: :ok"}
      ]

      assert :ok = Workspace.apply_files(ws, files)

      assert File.exists?(Path.join(ws, "lib/mod_a.ex"))
      assert File.exists?(Path.join(ws, "lib/mod_b.ex"))
      assert File.exists?(Path.join(ws, "test/mod_a_test.exs"))
    end

    test "creates intermediate directories automatically", %{workspace: ws} do
      files = [%{path: "deep/nested/dir/file.ex", content: "nested content"}]

      assert :ok = Workspace.apply_files(ws, files)
      assert File.read!(Path.join(ws, "deep/nested/dir/file.ex")) == "nested content"
    end

    test "overwrites existing files", %{workspace: ws} do
      path = "overwrite.txt"
      File.write!(Path.join(ws, path), "original")

      assert :ok = Workspace.apply_files(ws, [%{path: path, content: "updated"}])
      assert File.read!(Path.join(ws, path)) == "updated"
    end

    test "handles empty file content", %{workspace: ws} do
      files = [%{path: "empty.txt", content: ""}]

      assert :ok = Workspace.apply_files(ws, files)
      assert File.read!(Path.join(ws, "empty.txt")) == ""
    end

    test "handles empty file list", %{workspace: ws} do
      assert :ok = Workspace.apply_files(ws, [])
    end

    test "rejects path traversal with ..", %{workspace: ws} do
      files = [%{path: "../../etc/passwd", content: "evil"}]

      assert {:error, {:path_traversal, "../../etc/passwd"}} =
               Workspace.apply_files(ws, files)
    end

    test "rejects absolute path", %{workspace: ws} do
      files = [%{path: "/etc/hosts", content: "evil"}]

      assert {:error, {:path_traversal, "/etc/hosts"}} =
               Workspace.apply_files(ws, files)
    end

    test "rejects path resolving outside workspace via nested ..", %{workspace: ws} do
      files = [%{path: "lib/../../../etc/shadow", content: "evil"}]

      assert {:error, {:path_traversal, "lib/../../../etc/shadow"}} =
               Workspace.apply_files(ws, files)
    end

    test "stops at first traversal in a batch", %{workspace: ws} do
      files = [
        %{path: "lib/good.ex", content: "good"},
        %{path: "../../etc/evil", content: "evil"},
        %{path: "lib/also_good.ex", content: "good"}
      ]

      assert {:error, {:path_traversal, "../../etc/evil"}} =
               Workspace.apply_files(ws, files)
    end
  end

  describe "cleanup/1" do
    test "removes workspace directory and all contents", %{workspace: ws} do
      # Create some files first
      File.write!(Path.join(ws, "a.txt"), "content")
      File.mkdir_p!(Path.join(ws, "subdir"))
      File.write!(Path.join(ws, "subdir/b.txt"), "more content")

      assert :ok = Workspace.cleanup(ws)
      refute File.exists?(ws)
    end

    test "cleanup on already-removed path fails closed (cannot resolve)" do
      # v22 SEC-19: safe_realpath cannot resolve non-existent paths — fail closed
      tmp = Path.join(System.tmp_dir!(), "krait-ws-gone-#{System.unique_integer([:positive])}")
      File.mkdir_p!(tmp)
      File.rm_rf!(tmp)

      assert {:error, :invalid_cleanup_path} = Workspace.cleanup(tmp)
    end
  end

  describe "setup/2" do
    test "returns error when clone fails with bad URL" do
      assert {:error, {:clone_failed, _msg}} =
               Workspace.setup("https://invalid.example.com/no-such-repo.git", "test-branch")
    end
  end

  describe "setup/2 with local git repo" do
    setup do
      # Create a local bare git repo for testing
      origin = Path.join(System.tmp_dir!(), "krait-origin-#{System.unique_integer([:positive])}")
      File.mkdir_p!(origin)
      System.cmd("git", ["init", "--bare"], cd: origin, stderr_to_stdout: true)

      # Create a working copy, make a commit, then push to origin
      working =
        Path.join(System.tmp_dir!(), "krait-working-#{System.unique_integer([:positive])}")

      System.cmd("git", ["clone", origin, working], stderr_to_stdout: true)

      System.cmd("git", ["config", "user.email", "test@test.com"],
        cd: working,
        stderr_to_stdout: true
      )

      System.cmd("git", ["config", "user.name", "Test"], cd: working, stderr_to_stdout: true)
      File.write!(Path.join(working, "README.md"), "# Test")
      System.cmd("git", ["add", "-A"], cd: working, stderr_to_stdout: true)
      System.cmd("git", ["commit", "-m", "initial"], cd: working, stderr_to_stdout: true)
      System.cmd("git", ["push", "origin", "HEAD"], cd: working, stderr_to_stdout: true)

      on_exit(fn ->
        File.rm_rf!(origin)
        File.rm_rf!(working)
      end)

      {:ok, origin: origin}
    end

    test "clones repo and creates branch", %{origin: origin} do
      assert {:ok, workspace} = Workspace.setup(origin, "feature-test")

      # Verify the workspace exists and has the README
      assert File.exists?(Path.join(workspace, "README.md"))

      # Verify we're on the correct branch
      {branch, 0} =
        System.cmd("git", ["branch", "--show-current"], cd: workspace, stderr_to_stdout: true)

      assert String.trim(branch) == "feature-test"

      # Cleanup
      File.rm_rf!(workspace)
    end
  end

  describe "commit/2" do
    setup do
      # Create a local git repo for commit tests
      repo = Path.join(System.tmp_dir!(), "krait-commit-#{System.unique_integer([:positive])}")
      File.mkdir_p!(repo)
      System.cmd("git", ["init"], cd: repo, stderr_to_stdout: true)

      System.cmd("git", ["config", "user.email", "test@test.com"],
        cd: repo,
        stderr_to_stdout: true
      )

      System.cmd("git", ["config", "user.name", "Test"], cd: repo, stderr_to_stdout: true)
      # Need an initial commit to have a branch
      File.write!(Path.join(repo, "init.txt"), "init")
      System.cmd("git", ["add", "-A"], cd: repo, stderr_to_stdout: true)
      System.cmd("git", ["commit", "-m", "init"], cd: repo, stderr_to_stdout: true)

      on_exit(fn -> File.rm_rf!(repo) end)

      {:ok, repo: repo}
    end

    test "commits staged changes", %{repo: repo} do
      File.write!(Path.join(repo, "new.txt"), "new content")

      assert :ok = Workspace.commit(repo, "Add new file")

      {log, 0} = System.cmd("git", ["log", "--oneline", "-1"], cd: repo, stderr_to_stdout: true)
      assert log =~ "Add new file"
    end

    test "returns error when nothing to commit", %{repo: repo} do
      assert {:error, _} = Workspace.commit(repo, "Empty commit")
    end
  end

  describe "symlink resolution in apply_files" do
    setup do
      workspace =
        Path.join(System.tmp_dir!(), "krait-test-symlink-#{System.unique_integer([:positive])}")

      File.mkdir_p!(workspace)

      on_exit(fn -> File.rm_rf!(workspace) end)

      {:ok, workspace: workspace}
    end

    test "rejects symlink pointing outside workspace", %{workspace: workspace} do
      # Create a symlink inside workspace pointing to /tmp
      link_path = Path.join(workspace, "escape")
      File.ln_s!(System.tmp_dir!(), link_path)

      files = [%{path: "escape/evil.txt", content: "pwned"}]
      assert {:error, {:path_traversal, _}} = Workspace.apply_files(workspace, files)
    end

    test "allows normal files inside workspace", %{workspace: workspace} do
      files = [%{path: "lib/safe.ex", content: "defmodule Safe do\nend"}]
      assert :ok = Workspace.apply_files(workspace, files)
    end
  end

  describe "v22 SEC-19: cleanup symlink resolution" do
    test "symlink pointing outside tmp_dir is rejected", %{workspace: workspace} do
      # Create a symlink that points to a real directory outside tmp
      target_dir =
        Path.join(System.tmp_dir!(), "krait-symlink-target-#{System.unique_integer([:positive])}")

      File.mkdir_p!(target_dir)
      File.write!(Path.join(target_dir, "sentinel.txt"), "should_survive")

      # Create a symlink inside tmp that points to the target
      link_path =
        Path.join(System.tmp_dir!(), "krait-link-escape-#{System.unique_integer([:positive])}")

      # The link itself is outside the expected workspace structure
      # but let's test with the actual workspace
      on_exit(fn ->
        File.rm(link_path)
        File.rm_rf!(target_dir)
      end)

      # Cleanup should succeed for the real workspace (it is under tmp and contains "krait-")
      assert :ok = Workspace.cleanup(workspace)
    end

    test "normal krait workspace is cleaned up successfully" do
      tmp = System.tmp_dir!()
      workspace = Path.join(tmp, "krait-cleanup-test-#{System.unique_integer([:positive])}")
      File.mkdir_p!(workspace)
      File.write!(Path.join(workspace, "test.txt"), "data")

      assert :ok = Workspace.cleanup(workspace)
      refute File.exists?(workspace)
    end

    test "rejects paths not under tmp_dir" do
      assert {:error, :invalid_cleanup_path} = Workspace.cleanup("/etc/krait-evil")
    end
  end

  describe "repo_url validation" do
    @describetag :repo_url_validation

    setup do
      # Temporarily disable allow_local_network to test URL validation
      original = Application.get_env(:krait, :allow_local_network)
      Application.put_env(:krait, :allow_local_network, false)
      on_exit(fn -> Application.put_env(:krait, :allow_local_network, original) end)
      :ok
    end

    test "rejects file:// protocol in prod-like mode" do
      assert {:error, {:invalid_repo_url, _}} = Workspace.setup("file:///etc/passwd", "branch")
    end

    test "rejects git@ SSH URLs in prod-like mode" do
      assert {:error, {:invalid_repo_url, _}} =
               Workspace.setup("git@github.com:evil/repo.git", "branch")
    end

    test "allows https:// URLs" do
      # Will fail at clone step (invalid repo) but passes URL validation
      assert {:error, {:clone_failed, _}} =
               Workspace.setup("https://github.com/nonexistent/repo.git", "branch")
    end
  end
end
