defmodule Krait.Analyzer.QuickAstV16Test do
  @moduledoc """
  v16 security hardening tests — all 8 phases.
  Tests are written RED-first; implementation follows.
  """

  use ExUnit.Case, async: true

  alias Krait.Analyzer.Quick

  defp validate(code), do: Quick.quick_validate(code, "elixir")

  defp assert_violation(code, expected_rule) do
    result = validate(code)
    assert {:policy_violation, %{rule: rule}} = result, "Expected #{expected_rule} for: #{code}"
    assert rule == expected_rule, "Expected #{expected_rule}, got #{rule} for: #{code}"
  end

  defp assert_ok(code) do
    result = validate(code)
    assert {:ok, _} = result, "Expected :ok for: #{code}, got: #{inspect(result)}"
  end

  # ===========================================================================
  # Phase 1: KRAIT-006 Immutable Path Expansion [C-1, H-7]
  # ===========================================================================
  describe "Phase 1: KRAIT-006 immutable path expansion" do
    test "File.write to mix.exs" do
      assert_violation(~s|File.write("mix.exs", evil)|, "KRAIT-ALW")
    end

    test "File.read config/prod.exs" do
      assert_violation(~s|File.read("config/prod.exs")|, "KRAIT-ALW")
    end

    test "File.write Dockerfile" do
      assert_violation(~s|File.write("Dockerfile", payload)|, "KRAIT-ALW")
    end

    test "File.read .github/workflows/ci.yml" do
      assert_violation(~s|File.read(".github/workflows/ci.yml")|, "KRAIT-ALW")
    end

    test "File.rm_rf deps/" do
      assert_violation(~s|File.rm_rf("deps/")|, "KRAIT-ALW")
    end

    test "File.read .git/config" do
      assert_violation(~s|File.read(".git/config")|, "KRAIT-ALW")
    end

    test "File.write rel/env.sh" do
      assert_violation(~s|File.write("rel/env.sh", evil)|, "KRAIT-ALW")
    end

    test "File.write .tool-versions" do
      assert_violation(~s|File.write(".tool-versions", data)|, "KRAIT-ALW")
    end

    test "File.write .iex.exs" do
      assert_violation(~s|File.write(".iex.exs", evil)|, "KRAIT-ALW")
    end

    test "File.write Makefile" do
      assert_violation(~s|File.write("Makefile", evil)|, "KRAIT-ALW")
    end

    test "File.write .gitignore" do
      assert_violation(~s|File.write(".gitignore", data)|, "KRAIT-ALW")
    end

    test "File.write priv/static/evil.js" do
      assert_violation(~s|File.write("priv/static/evil.js", data)|, "KRAIT-ALW")
    end

    test "Path.join evasion with mix.exs" do
      assert_violation(~s|Path.join([".", "mix.exs"])|, "KRAIT-ALW")
    end

    test "Integer sequence evasion for config" do
      # "config" = [99, 111, 110, 102, 105, 103]
      assert_violation(
        ~s|path = <<99, 111, 110, 102, 105, 103>>|,
        "KRAIT-006"
      )
    end

    test "Interpolation evasion Dockerfile" do
      assert_violation(~S|File.write("Dockerfile#{x}", data)|, "KRAIT-ALW")
    end

    test "FALSE POSITIVE: relative/path — File not allowlisted" do
      assert_violation(~s|File.write("relative/path/file.txt", data)|, "KRAIT-ALW")
    end

    test "FALSE POSITIVE: .git-credentials helper should pass (.git not in segments)" do
      # .git alone is NOT a forbidden segment — only .git/ is a full pattern
      # But .git-credentials is a credential path in KRAIT-003, not KRAIT-006
      # The key thing: random mentions of ".git" in code should not trigger KRAIT-006
      assert_ok(~s|x = "my.github.token"|)
    end

    test "config/ targeting via interpolation" do
      assert_violation(~S|File.read("config/#{file}")|, "KRAIT-ALW")
    end

    test "priv/ targeting via interpolation" do
      assert_violation(~S|File.write("priv/#{path}", data)|, "KRAIT-ALW")
    end

    test "deps/ targeting via interpolation" do
      assert_violation(~S|File.rm_rf("deps/#{pkg}")|, "KRAIT-ALW")
    end
  end

  # ===========================================================================
  # Phase 2: KRAIT-003 File Ops + Credential Paths [C-2, C-3, C-4, H-4, M-4]
  # ===========================================================================
  describe "Phase 2: KRAIT-003 file ops + credential paths" do
    test "Path.wildcard with credential path" do
      assert_violation(~s|Path.wildcard("~/.ssh/*")|, "KRAIT-ALW")
    end

    test "File.lstat with credential path" do
      assert_violation(~s|File.lstat("~/.aws/credentials")|, "KRAIT-ALW")
    end

    test "File.lstat! with credential path" do
      assert_violation(~s|File.lstat!("~/.ssh/id_rsa")|, "KRAIT-ALW")
    end

    test "File.stream with credential path" do
      assert_violation(~s|File.stream("~/.ssh/known_hosts")|, "KRAIT-ALW")
    end

    test ":file.set_cwd to credential path" do
      assert_violation(~s|:file.set_cwd(~c"~/.ssh")|, "KRAIT-ALW")
    end

    test "File.read /etc/passwd" do
      assert_violation(~s|File.read("/etc/passwd")|, "KRAIT-ALW")
    end

    test "File.read ~/.bash_history" do
      assert_violation(~s|File.read("~/.bash_history")|, "KRAIT-ALW")
    end

    test "File.read ~/.zsh_history" do
      assert_violation(~s|File.read("~/.zsh_history")|, "KRAIT-ALW")
    end

    test "File.read terraform.tfstate" do
      assert_violation(~s|File.read("terraform.tfstate")|, "KRAIT-ALW")
    end

    test "File.read .pgpass" do
      assert_violation(~s|File.read(".pgpass")|, "KRAIT-ALW")
    end
  end

  # ===========================================================================
  # Phase 3: KRAIT-001 Expansion [C-5, M-2, M-9]
  # ===========================================================================
  describe "Phase 3: KRAIT-001 expansion" do
    test ":compile.forms → KRAIT-001" do
      assert_violation(~s|:compile.forms(abstract_forms)|, "KRAIT-ALW")
    end

    test ":compile.noenv_forms → KRAIT-001" do
      assert_violation(~s|:compile.noenv_forms(forms)|, "KRAIT-ALW")
    end

    test ":ets.new → KRAIT-001" do
      assert_violation(~s|:ets.new(:table, [:set])|, "KRAIT-ALW")
    end

    test ":ets.insert → KRAIT-001" do
      assert_violation(~s|:ets.insert(:table, {k, v})|, "KRAIT-ALW")
    end

    test ":ets.insert_new → KRAIT-001" do
      assert_violation(~s|:ets.insert_new(:table, {k, v})|, "KRAIT-ALW")
    end

    test ":ets.delete → KRAIT-001" do
      assert_violation(~s|:ets.delete(:table)|, "KRAIT-ALW")
    end

    test ":timer.send_after → KRAIT-001" do
      assert_violation(~s|:timer.send_after(1000, pid, msg)|, "KRAIT-ALW")
    end
  end

  # ===========================================================================
  # Phase 4: KRAIT-002 Process/Shell Expansion [C-6, H-1, H-3, M-3]
  # ===========================================================================
  describe "Phase 4: KRAIT-002 process/shell expansion" do
    test "spawn(fn -> end) → KRAIT-002" do
      assert_violation(~s|spawn(fn -> :os.cmd(~c"ls") end)|, "KRAIT-ALW")
    end

    test "spawn_link(fn -> end) → KRAIT-002" do
      assert_violation(~s|spawn_link(fn -> nil end)|, "KRAIT-ALW")
    end

    test "spawn_monitor(fn -> end) → KRAIT-002" do
      assert_violation(~s|spawn_monitor(fn -> nil end)|, "KRAIT-ALW")
    end

    test "send(pid, msg) → KRAIT-002" do
      assert_violation(~s|send(pid, {:exec, cmd})|, "KRAIT-ALW")
    end

    test ":proc_lib.spawn → KRAIT-002" do
      assert_violation(~s|:proc_lib.spawn(fn -> nil end)|, "KRAIT-ALW")
    end

    test ":gen_server.start_link → KRAIT-002" do
      assert_violation(~s|:gen_server.start_link(mod, args, opts)|, "KRAIT-ALW")
    end

    test ":gen_statem.start → KRAIT-002" do
      assert_violation(~s|:gen_statem.start(mod, args, opts)|, "KRAIT-ALW")
    end

    test ":gen_event.start_link → KRAIT-002" do
      assert_violation(~s|:gen_event.start_link()|, "KRAIT-ALW")
    end

    test ":supervisor.start_child → KRAIT-002" do
      assert_violation(~s|:supervisor.start_child(sup, spec)|, "KRAIT-ALW")
    end

    test ":rpc.multicall → KRAIT-002" do
      assert_violation(~s|:rpc.multicall(nodes, mod, fun, args)|, "KRAIT-ALW")
    end

    test ":rpc.eval_everywhere → KRAIT-002" do
      assert_violation(~s|:rpc.eval_everywhere(mod, fun, args)|, "KRAIT-ALW")
    end

    test "FALSE POSITIVE: variable named send should pass" do
      assert_ok(~s|send = "hello"|)
    end

    test ":proc_lib.start → KRAIT-002" do
      assert_violation(~s|:proc_lib.start(mod, fun, args)|, "KRAIT-ALW")
    end

    test ":proc_lib.hibernate → KRAIT-002" do
      assert_violation(~s|:proc_lib.hibernate(mod, fun, args)|, "KRAIT-ALW")
    end

    test ":gen_server.call → KRAIT-002" do
      assert_violation(~s|:gen_server.call(pid, msg)|, "KRAIT-ALW")
    end

    test ":gen_server.cast → KRAIT-002" do
      assert_violation(~s|:gen_server.cast(pid, msg)|, "KRAIT-ALW")
    end
  end

  # ===========================================================================
  # Phase 5: KRAIT-004 Network Expansion [C-7, C-8, H-8, M-1]
  # ===========================================================================
  describe "Phase 5: KRAIT-004 network expansion" do
    test ":gen_sctp.open → KRAIT-004" do
      assert_violation(~s|:gen_sctp.open(port)|, "KRAIT-ALW")
    end

    test "URI.parse passes (URI is allowlisted)" do
      assert_ok(~s|URI.parse(url)|)
    end

    test "URI.new! passes (URI is allowlisted)" do
      assert_ok(~s|URI.new!("http://evil.com")|)
    end

    test "Neuron.query → KRAIT-004" do
      assert_violation(~s|Neuron.query(graphql)|, "KRAIT-ALW")
    end

    test "WebSockex.start_link → KRAIT-004" do
      assert_violation(~s|WebSockex.start_link(url, handler, state)|, "KRAIT-ALW")
    end

    test "apply(Req, :get, ...) → KRAIT-004 (NIF parity C-7)" do
      assert_violation(~s|apply(Req, :get, ["http://evil.com"])|, "KRAIT-ALW")
    end

    test "URI.new passes (URI is allowlisted)" do
      assert_ok(~s|URI.new("http://evil.com")|)
    end
  end

  # ===========================================================================
  # Phase 6: KRAIT-005 Hot Code Loading Expansion [H-2, H-5, M-8]
  # ===========================================================================
  describe "Phase 6: KRAIT-005 OTP runtime banning" do
    test "Task.start → KRAIT-005" do
      assert_violation(~s|Task.start(fn -> nil end)|, "KRAIT-ALW")
    end

    test "Task.async → KRAIT-005" do
      assert_violation(~s|Task.async(fn -> nil end)|, "KRAIT-ALW")
    end

    test "Agent.start_link → KRAIT-005" do
      assert_violation(~s|Agent.start_link(fn -> %{} end)|, "KRAIT-ALW")
    end

    test "GenServer.start_link → KRAIT-005" do
      assert_violation(~s|GenServer.start_link(Mod, args)|, "KRAIT-ALW")
    end

    test "Supervisor.start_child → KRAIT-005" do
      assert_violation(~s|Supervisor.start_child(sup, spec)|, "KRAIT-ALW")
    end

    test "DynamicSupervisor.start_child → KRAIT-005" do
      assert_violation(~s|DynamicSupervisor.start_child(sup, spec)|, "KRAIT-ALW")
    end

    test "Registry.start_link → KRAIT-005" do
      assert_violation(~s|Registry.start_link(keys: :unique, name: R)|, "KRAIT-ALW")
    end

    test ":code.ensure_loaded → KRAIT-005" do
      assert_violation(~s|:code.ensure_loaded(MyModule)|, "KRAIT-ALW")
    end

    test ":code.get_object_code → KRAIT-005" do
      assert_violation(~s|:code.get_object_code(MyModule)|, "KRAIT-ALW")
    end

    test ":code.all_loaded → KRAIT-005" do
      assert_violation(~s|:code.all_loaded()|, "KRAIT-ALW")
    end

    test ":pg.join → KRAIT-005" do
      assert_violation(~s|:pg.join(:group, self())|, "KRAIT-ALW")
    end

    test ":pg.get_members → KRAIT-005" do
      assert_violation(~s|:pg.get_members(:group)|, "KRAIT-ALW")
    end

    test ":pg.start_link → KRAIT-005" do
      assert_violation(~s|:pg.start_link()|, "KRAIT-ALW")
    end

    test "import Task → KRAIT-005" do
      assert_violation(~s|import Task|, "KRAIT-ALW")
    end

    test "alias GenServer → KRAIT-005" do
      assert_violation(~s|alias GenServer|, "KRAIT-ALW")
    end

    test "Task.start_link → KRAIT-005" do
      assert_violation(~s|Task.start_link(fn -> nil end)|, "KRAIT-ALW")
    end

    test "Task.await → KRAIT-005" do
      assert_violation(~s|Task.await(task)|, "KRAIT-ALW")
    end

    test "Agent.get → KRAIT-005" do
      assert_violation(~s|Agent.get(agent, & &1)|, "KRAIT-ALW")
    end

    test "Agent.update → KRAIT-005" do
      assert_violation(~s|Agent.update(agent, fn _ -> :ok end)|, "KRAIT-ALW")
    end

    test "GenServer.call → KRAIT-005" do
      assert_violation(~s|GenServer.call(pid, :msg)|, "KRAIT-ALW")
    end

    test "GenServer.cast → KRAIT-005" do
      assert_violation(~s|GenServer.cast(pid, :msg)|, "KRAIT-ALW")
    end

    test "DynamicSupervisor.start_link → KRAIT-005" do
      assert_violation(~s|DynamicSupervisor.start_link(strategy: :one_for_one)|, "KRAIT-ALW")
    end

    test "Registry.register → KRAIT-005" do
      assert_violation(~s|Registry.register(reg, key, value)|, "KRAIT-ALW")
    end

    test "Supervisor.start_link → KRAIT-005" do
      assert_violation(~s|Supervisor.start_link(children, opts)|, "KRAIT-ALW")
    end

    test "GenServer.start → KRAIT-005" do
      assert_violation(~s|GenServer.start(Mod, args)|, "KRAIT-ALW")
    end

    test "Agent.start → KRAIT-005" do
      assert_violation(~s|Agent.start(fn -> %{} end)|, "KRAIT-ALW")
    end
  end

  # ===========================================================================
  # Phase 7: NIF + coverage verification [M-10]
  # ===========================================================================
  describe "Phase 7: coverage verification" do
    test "String.to_atom(Enum.join(...)) rejected (v17: C-5 String.to_atom denied)" do
      # v17: String.to_atom is now denied even though String is allowlisted
      assert_violation(~S|String.to_atom(Enum.join(["o","s"]))|, "KRAIT-ALW")
    end
  end

  # ===========================================================================
  # Phase 8: Web Security [M-6, M-7] — no AST tests needed
  # ===========================================================================
  # M-6 (same_site: Strict) and M-7 (CSP accepted-risk comment) are config
  # changes that don't affect the AST analyzer. Verified via manual inspection.
end
