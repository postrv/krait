defmodule Krait.Evolution.V26WorkspaceHardeningTest do
  use ExUnit.Case, async: true

  alias Krait.Evolution.Workspace

  # ---------------------------------------------------------------------------
  # Phase 1: H-1 — Docker Hardening Flags
  # ---------------------------------------------------------------------------
  describe "build_sandboxed_docker_args/3 hardening flags" do
    test "includes --security-opt=no-new-privileges" do
      args =
        Workspace.build_sandboxed_docker_args("img:latest", ["mix", "test"], workspace_dir: "/ws")

      assert "--security-opt=no-new-privileges" in args
    end

    test "includes --cap-drop=ALL" do
      args =
        Workspace.build_sandboxed_docker_args("img:latest", ["mix", "test"], workspace_dir: "/ws")

      assert "--cap-drop=ALL" in args
    end

    test "includes --user 65534:65534 (nobody)" do
      args =
        Workspace.build_sandboxed_docker_args("img:latest", ["mix", "test"], workspace_dir: "/ws")

      idx = Enum.find_index(args, &(&1 == "--user"))
      assert idx != nil
      assert Enum.at(args, idx + 1) == "65534:65534"
    end

    test "includes --pids-limit=256" do
      args =
        Workspace.build_sandboxed_docker_args("img:latest", ["mix", "test"], workspace_dir: "/ws")

      assert "--pids-limit=256" in args
    end

    test "includes --read-only" do
      args =
        Workspace.build_sandboxed_docker_args("img:latest", ["mix", "test"], workspace_dir: "/ws")

      assert "--read-only" in args
    end

    test "includes --tmpfs for /tmp" do
      args =
        Workspace.build_sandboxed_docker_args("img:latest", ["mix", "test"], workspace_dir: "/ws")

      idx = Enum.find_index(args, &(&1 == "--tmpfs"))
      assert idx != nil
      assert Enum.at(args, idx + 1) == "/tmp:rw,noexec,nosuid,size=100m"
    end

    test "appends cmd_args after image" do
      args =
        Workspace.build_sandboxed_docker_args("img:latest", ["mix", "test"], workspace_dir: "/ws")

      img_idx = Enum.find_index(args, &(&1 == "img:latest"))
      assert img_idx != nil
      assert Enum.slice(args, (img_idx + 1)..-1//1) == ["mix", "test"]
    end

    test "uses custom network from opts" do
      args =
        Workspace.build_sandboxed_docker_args("img:latest", ["mix", "deps.get"],
          workspace_dir: "/ws",
          network: "default"
        )

      net_idx = Enum.find_index(args, &(&1 == "--network"))
      assert Enum.at(args, net_idx + 1) == "default"
    end

    test "defaults network to none" do
      args =
        Workspace.build_sandboxed_docker_args("img:latest", ["mix", "test"], workspace_dir: "/ws")

      net_idx = Enum.find_index(args, &(&1 == "--network"))
      assert Enum.at(args, net_idx + 1) == "none"
    end
  end

  # ---------------------------------------------------------------------------
  # Phase 2: H-2 — Lockfile integrity functions
  # ---------------------------------------------------------------------------
  describe "lockfile_checksum/1" do
    test "returns sha256 hex for existing file" do
      path = Path.join(System.tmp_dir!(), "krait_test_lockfile_#{:rand.uniform(100_000)}")
      File.write!(path, "some lock content")

      try do
        checksum = Workspace.lockfile_checksum(path)
        assert is_binary(checksum)
        assert byte_size(checksum) == 64
        assert String.match?(checksum, ~r/^[0-9a-f]{64}$/)
      after
        File.rm(path)
      end
    end

    test "returns nil for missing file" do
      assert Workspace.lockfile_checksum("/nonexistent/path/mix.lock") == nil
    end
  end

  describe "verify_lockfile_integrity/2" do
    test "returns :ok when checksums match" do
      path = Path.join(System.tmp_dir!(), "krait_test_lockfile_#{:rand.uniform(100_000)}")
      File.write!(path, "lock content")

      try do
        checksum = Workspace.lockfile_checksum(path)
        assert Workspace.verify_lockfile_integrity(path, checksum) == :ok
      after
        File.rm(path)
      end
    end

    test "returns error when lockfile modified" do
      path = Path.join(System.tmp_dir!(), "krait_test_lockfile_#{:rand.uniform(100_000)}")
      File.write!(path, "original content")

      try do
        checksum = Workspace.lockfile_checksum(path)
        File.write!(path, "modified content")
        assert {:error, :lockfile_modified} = Workspace.verify_lockfile_integrity(path, checksum)
      after
        File.rm(path)
      end
    end

    test "returns :ok when pre_checksum is nil (no lockfile existed)" do
      assert Workspace.verify_lockfile_integrity("/any/path", nil) == :ok
    end
  end

  # ---------------------------------------------------------------------------
  # Phase 3: H-3 — Host Execution Double Confirmation
  # ---------------------------------------------------------------------------
  describe "compile_and_test/1 sandbox routing" do
    test "uses sandbox when only allow_local_execution is true" do
      original_risk = Application.get_env(:krait, :accept_host_execution_risk)

      try do
        Application.put_env(:krait, :allow_local_execution, true)
        Application.put_env(:krait, :accept_host_execution_risk, false)

        # sandboxed_run_cmd will fail because docker isn't available, but the
        # important thing is it tries the sandbox path (not local)
        result = Workspace.compile_and_test("/nonexistent/workspace")

        # Should get a docker/cmd error, not a local mix error
        assert {:error, reason} = result

        assert match?({:cmd_failed, "docker", _, _}, reason) or
                 match?({:cmd_error, "docker", _}, reason) or
                 match?({:cmd_timeout, "docker", _}, reason)
      after
        Application.put_env(:krait, :allow_local_execution, true)
        Application.put_env(:krait, :accept_host_execution_risk, original_risk)
      end
    end

    test "uses sandbox when only accept_host_execution_risk is true" do
      original_allow = Application.get_env(:krait, :allow_local_execution)

      try do
        Application.put_env(:krait, :allow_local_execution, false)
        Application.put_env(:krait, :accept_host_execution_risk, true)

        result = Workspace.compile_and_test("/nonexistent/workspace")

        assert {:error, reason} = result

        assert match?({:cmd_failed, "docker", _, _}, reason) or
                 match?({:cmd_error, "docker", _}, reason) or
                 match?({:cmd_timeout, "docker", _}, reason)
      after
        Application.put_env(:krait, :allow_local_execution, original_allow)
        Application.put_env(:krait, :accept_host_execution_risk, true)
      end
    end

    test "uses sandbox when neither flag is true" do
      original_allow = Application.get_env(:krait, :allow_local_execution)
      original_risk = Application.get_env(:krait, :accept_host_execution_risk)

      try do
        Application.put_env(:krait, :allow_local_execution, false)
        Application.put_env(:krait, :accept_host_execution_risk, false)

        result = Workspace.compile_and_test("/nonexistent/workspace")

        assert {:error, reason} = result

        assert match?({:cmd_failed, "docker", _, _}, reason) or
                 match?({:cmd_error, "docker", _}, reason) or
                 match?({:cmd_timeout, "docker", _}, reason)
      after
        Application.put_env(:krait, :allow_local_execution, original_allow)
        Application.put_env(:krait, :accept_host_execution_risk, original_risk)
      end
    end
  end
end
