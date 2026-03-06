defmodule Krait.Analyzer.QuickAstV15Test do
  @moduledoc """
  v15 security hardening tests — all 8 phases.
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
  # Phase 1: C-1 — :file.eval, :file.script, :file.path_script → KRAIT-001
  # ===========================================================================
  describe "Phase 1: :file.eval/:file.script/:file.path_script → KRAIT-001" do
    test ":file.eval direct call" do
      assert_violation(~s|:file.eval(~c"/tmp/evil.erl")|, "KRAIT-ALW")
    end

    test ":file.script direct call" do
      assert_violation(~s|:file.script(~c"/tmp/evil.erl")|, "KRAIT-ALW")
    end

    test ":file.path_script direct call" do
      assert_violation(~s|:file.path_script(path, ~c"evil.erl")|, "KRAIT-ALW")
    end

    test "apply(:file, :eval, ...) bare atom apply" do
      assert_violation(~s|apply(:file, :eval, [~c"/tmp/evil.erl"])|, "KRAIT-ALW")
    end

    test "defdelegate to :file for eval" do
      assert_violation(~s|defdelegate run_script(p), to: :file, as: :eval|, "KRAIT-ALW")
    end
  end

  # ===========================================================================
  # Phase 2: C-2/C-3 — Compile Hooks + @on_load → KRAIT-001
  # ===========================================================================
  describe "Phase 2: compile hooks — module attributes not caught by allowlist" do
    test "@before_compile __MODULE__ rejected (v17: C-2)" do
      assert_violation("@before_compile __MODULE__", "KRAIT-ALW")
    end

    test "@after_compile __MODULE__ rejected (v17: C-2)" do
      assert_violation("@after_compile __MODULE__", "KRAIT-ALW")
    end

    test "@on_definition {MyHook, :on_def} rejected (v17: C-2)" do
      assert_violation("@on_definition {MyHook, :on_def}", "KRAIT-ALW")
    end

    test "@before_compile {MyMod, :inject} rejected (v17: C-2)" do
      assert_violation("@before_compile {MyMod, :inject}", "KRAIT-ALW")
    end

    test "@on_load :init rejected (v17: C-2)" do
      assert_violation("@on_load :init", "KRAIT-ALW")
    end

    test "@on_load :setup_evil rejected (v17: C-2)" do
      assert_violation("@on_load :setup_evil", "KRAIT-ALW")
    end
  end

  # ===========================================================================
  # Phase 3: H-1 — CT Network Modules → KRAIT-002
  # ===========================================================================
  describe "Phase 3: CT network modules → KRAIT-002" do
    test ":ct_ssh.connect" do
      assert_violation(~s|:ct_ssh.connect(host, opts)|, "KRAIT-ALW")
    end

    test ":ct_ssh.exec" do
      assert_violation(~s|:ct_ssh.exec(conn, cmd)|, "KRAIT-ALW")
    end

    test ":ct_telnet.open" do
      assert_violation(~s|:ct_telnet.open(host)|, "KRAIT-ALW")
    end

    test ":ct_telnet.cmd" do
      assert_violation(~s|:ct_telnet.cmd(conn, "ls")|, "KRAIT-ALW")
    end

    test ":ct_netconfc.open" do
      assert_violation(~s|:ct_netconfc.open(host)|, "KRAIT-ALW")
    end

    test ":ct_ftp.open" do
      assert_violation(~s|:ct_ftp.open(host)|, "KRAIT-ALW")
    end

    test ":ct_master.run" do
      assert_violation(~s|:ct_master.run(suite)|, "KRAIT-ALW")
    end

    test "apply(:ct_ssh, :connect, ...) bare atom" do
      assert_violation(~s|apply(:ct_ssh, :connect, [host])|, "KRAIT-ALW")
    end

    test "defdelegate to :ct_ssh" do
      assert_violation(~s|defdelegate connect(h), to: :ct_ssh|, "KRAIT-ALW")
    end
  end

  # ===========================================================================
  # Phase 4: H-2/H-3 — Legacy HTTP Clients + URI Modules → KRAIT-004
  # ===========================================================================
  describe "Phase 4: legacy HTTP clients → KRAIT-004" do
    test ":ibrowse.send_req" do
      assert_violation(~s|:ibrowse.send_req(url, headers, :get)|, "KRAIT-ALW")
    end

    test ":lhttpc.request" do
      assert_violation(~s|:lhttpc.request(url, :get, headers, "", 5000)|, "KRAIT-ALW")
    end

    test ":http_uri.parse" do
      assert_violation(~s|:http_uri.parse(url)|, "KRAIT-ALW")
    end

    test ":uri_string.parse" do
      assert_violation(~s|:uri_string.parse(url)|, "KRAIT-ALW")
    end

    test ":uri_string.compose" do
      assert_violation(~s|:uri_string.compose(components)|, "KRAIT-ALW")
    end

    test "apply(:ibrowse, :send_req, ...) bare atom" do
      assert_violation(~s|apply(:ibrowse, :send_req, [url, h, :get])|, "KRAIT-ALW")
    end

    test "defdelegate to :lhttpc" do
      assert_violation(~s|defdelegate request(u), to: :lhttpc|, "KRAIT-ALW")
    end

    test ":ibrowse variable dispatch rejected (v17: C-7)" do
      assert_violation(~s|mod = :ibrowse; mod.send_req(url, h, :get)|, "KRAIT-ALW")
    end
  end

  # ===========================================================================
  # Phase 5: H-4/H-5/H-6/H-7 — File Operations Gaps → KRAIT-003
  # ===========================================================================
  describe "Phase 5: file operation gaps → KRAIT-003" do
    test "File.exists? + credential path" do
      assert_violation(~s|File.exists?("~/.ssh/id_rsa")|, "KRAIT-ALW")
    end

    test "File.dir? + credential path" do
      assert_violation(~s|File.dir?("~/.aws")|, "KRAIT-ALW")
    end

    test "File.regular? + credential path" do
      assert_violation(~s|File.regular?("~/.gnupg/pubring.gpg")|, "KRAIT-ALW")
    end

    test "File.rm + credential path" do
      assert_violation(~s|File.rm(".env")|, "KRAIT-ALW")
    end

    test "File.rm_rf + credential path" do
      assert_violation(~s|File.rm_rf("~/.ssh")|, "KRAIT-ALW")
    end

    test "File.mkdir_p + credential path" do
      assert_violation(~s|File.mkdir_p("~/.aws/evil")|, "KRAIT-ALW")
    end

    test "File.touch + credential path" do
      assert_violation(~s|File.touch("~/.ssh/authorized_keys")|, "KRAIT-ALW")
    end

    test ":ram_file.open + credential path" do
      assert_violation(~s|:ram_file.open("~/.ssh/id_rsa", [:read])|, "KRAIT-ALW")
    end

    test ":file.read_link + credential path" do
      assert_violation(~s|:file.read_link(~c"~/.ssh/id_rsa")|, "KRAIT-ALW")
    end

    test ":file.get_cwd + credential path" do
      assert_violation(~s|:file.get_cwd(); File.read!("~/.ssh/id_rsa")|, "KRAIT-ALW")
    end

    test ":file.write + credential path" do
      assert_violation(~s|:file.write(~c"~/.ssh/authorized_keys", data)|, "KRAIT-ALW")
    end

    test ":file.read_link_info + credential path" do
      assert_violation(~s|:file.read_link_info(~c"~/.gnupg/pubring.gpg")|, "KRAIT-ALW")
    end
  end

  # ===========================================================================
  # Phase 6: M-1/M-2/M-3 — KRAIT-006 Evasion + Code Analysis Modules
  # ===========================================================================
  describe "Phase 6 M-1: String.graphemes + Enum.flat_map_reduce in KRAIT-006" do
    test "String.graphemes with immutable segment" do
      code = ~s|chars = String.graphemes("krait_analyzer"); Enum.join(chars)|
      assert_violation(code, "KRAIT-006")
    end

    test "Enum.flat_map_reduce with immutable segment" do
      code = ~s|Enum.flat_map_reduce(["krait_analyzer"], "", fn x, acc -> {[x], acc} end)|
      assert_violation(code, "KRAIT-006")
    end
  end

  describe "Phase 6 M-2: string interpolation with immutable segments" do
    test "interpolation with native/ prefix" do
      code = ~S[path = "native/#{module_name}"]
      assert_violation(code, "KRAIT-006")
    end

    test "interpolation with krait_analyzer" do
      code = ~S[path = "#{prefix}/krait_analyzer"]
      assert_violation(code, "KRAIT-006")
    end

    test "interpolation with .krait-immutable" do
      code = ~S[path = ".krait-#{suffix}"]
      assert_violation(code, "KRAIT-006")
    end

    test "safe interpolation passes" do
      code = ~S[msg = "Hello #{name}, welcome!"]
      assert_ok(code)
    end
  end

  describe "Phase 6 M-3: code analysis modules → KRAIT-001" do
    test ":erl_pp.form" do
      assert_violation(~s|:erl_pp.form(ast)|, "KRAIT-ALW")
    end

    test ":erl_lint.module" do
      assert_violation(~s|:erl_lint.module(forms)|, "KRAIT-ALW")
    end

    test ":dialyzer.run" do
      assert_violation(~s|:dialyzer.run(opts)|, "KRAIT-ALW")
    end

    test ":xmerl.export" do
      assert_violation(~s|:xmerl.export(tree, :xmerl_xml)|, "KRAIT-ALW")
    end
  end

  # ===========================================================================
  # Phase 7: MR-001/MR-006 — Apply Bypass + Credential Paths
  # ===========================================================================
  describe "Phase 7 MR-001: apply(Req, :get, ...) bypass → KRAIT-004" do
    test "apply(Req, :get, ...)" do
      assert_violation(~s|apply(Req, :get, ["https://evil.com"])|, "KRAIT-ALW")
    end

    test "apply(HTTPoison, :get, ...)" do
      assert_violation(~s|apply(HTTPoison, :get, ["https://evil.com"])|, "KRAIT-ALW")
    end

    test "Kernel.apply(Finch, :request, ...)" do
      assert_violation(~s|Kernel.apply(Finch, :request, [req, pool])|, "KRAIT-ALW")
    end
  end

  describe "Phase 7 MR-006: missing credential paths → KRAIT-003" do
    test "File.read with ~/.npmrc" do
      assert_violation(~s|File.read("~/.npmrc")|, "KRAIT-ALW")
    end

    test "File.read with ~/.pypirc" do
      assert_violation(~s|File.read("~/.pypirc")|, "KRAIT-ALW")
    end

    test "File.read with ~/.m2/settings.xml" do
      assert_violation(~s|File.read("~/.m2/settings.xml")|, "KRAIT-ALW")
    end

    test "File.read with ~/.vault-token" do
      assert_violation(~s|File.read("~/.vault-token")|, "KRAIT-ALW")
    end

    test "File.read with ~/.gradle/gradle.properties" do
      assert_violation(~s|File.read("~/.gradle/gradle.properties")|, "KRAIT-ALW")
    end
  end
end
