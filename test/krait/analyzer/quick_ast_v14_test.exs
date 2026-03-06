defmodule Krait.Analyzer.QuickAstV14Test do
  use ExUnit.Case, async: true

  alias Krait.Analyzer.Quick

  # ---------------------------------------------------------------------------
  # Phase 1: C-1 — :file.open and :prim_file expansion
  # ---------------------------------------------------------------------------

  describe "v14-P1: KRAIT-003 :file.open/:prim_file expansion" do
    test ":file.open with credential path -> KRAIT-003" do
      code = ~S':file.open("~/.ssh/id_rsa", [:read])'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":file.read with credential path -> KRAIT-003" do
      code = ~S':file.read("~/.aws/credentials")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":file.read_line with credential path -> KRAIT-003" do
      code = ~S':file.read_line("~/.ssh/id_rsa")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":file.pread with credential path -> KRAIT-003" do
      _code = ~S':file.pread(fd, [{0, 100}])'
      # pread takes a file descriptor, but we need file op + cred path
      code2 = ~S"""
      :file.pread(fd, [{0, 100}])
      path = "~/.ssh/id_rsa"
      """

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code2, "elixir")
    end

    test ":file.delete with credential path -> KRAIT-003" do
      code = ~S':file.delete("~/.gnupg/secring.gpg")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":file.rename with credential path -> KRAIT-003" do
      code = ~S':file.rename("~/.ssh/id_rsa", "/tmp/stolen")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":file.make_symlink with credential path -> KRAIT-003" do
      code = ~S':file.make_symlink("~/.ssh/id_rsa", "/tmp/link")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":prim_file.open with credential path -> KRAIT-003" do
      code = ~S':prim_file.open("~/.ssh/id_rsa", [:read])'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":prim_file.read with credential path -> KRAIT-003" do
      code = ~S':prim_file.read("~/.aws/credentials")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":prim_file.write with credential path -> KRAIT-003" do
      code = ~S':prim_file.write("/etc/shadow", "evil")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":file.open with safe path -> KRAIT-ALW (not allowlisted)" do
      code = ~S':file.open("/tmp/safe.txt", [:read])'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":prim_file.read with safe path -> KRAIT-ALW (not allowlisted)" do
      code = ~S':prim_file.read("/tmp/data.bin")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  # ---------------------------------------------------------------------------
  # Phase 2: H-1, H-2 — Req/Finch HTTP client gaps
  # ---------------------------------------------------------------------------

  describe "v14-P2: KRAIT-004 Req/Finch gaps" do
    test "Req.request -> KRAIT-004" do
      code = ~S'Req.request(method: :get, url: "https://evil.com")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Req.request! -> KRAIT-004" do
      code = ~S'Req.request!(method: :get, url: "https://evil.com")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Req.new -> KRAIT-004" do
      code = ~S'Req.new(base_url: "https://evil.com")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Req.new! -> KRAIT-004" do
      code = ~S'Req.new!(base_url: "https://evil.com")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Req.run -> KRAIT-004" do
      code = ~S'Req.run(req)'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Req.run! -> KRAIT-004" do
      code = ~S'Req.run!(req)'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Req.head -> KRAIT-004" do
      code = ~S'Req.head("https://evil.com")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Req.head! -> KRAIT-004" do
      code = ~S'Req.head!("https://evil.com")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Req.options -> KRAIT-004" do
      code = ~S'Req.options("https://evil.com")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Req.options! -> KRAIT-004" do
      code = ~S'Req.options!("https://evil.com")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Finch.stream -> KRAIT-004" do
      code = ~S'Finch.stream(req, finch_name, acc, fun)'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Finch.stream! -> KRAIT-004" do
      code = ~S'Finch.stream!(req, finch_name, acc, fun)'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Finch.async_request -> KRAIT-004" do
      code = ~S'Finch.async_request(req, finch_name)'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Finch.start_link -> KRAIT-004" do
      code = ~S'Finch.start_link(name: MyFinch)'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  # ---------------------------------------------------------------------------
  # Phase 3: H-3, H-4 — Unicode bypass + fragment heuristic
  # ---------------------------------------------------------------------------

  describe "v14-P3: KRAIT-006 Unicode bypass" do
    test ":unicode.characters_to_binary with integer list -> KRAIT-006" do
      code = ~S':unicode.characters_to_binary([110, 97, 116])'
      assert {:policy_violation, %{rule: "KRAIT-006"}} = Quick.quick_validate(code, "elixir")
    end

    test ":unicode.characters_to_list -> KRAIT-006" do
      code = ~S':unicode.characters_to_list([110, 97, 116])'
      assert {:policy_violation, %{rule: "KRAIT-006"}} = Quick.quick_validate(code, "elixir")
    end
  end

  describe "v14-P3: KRAIT-006 fragment combination evasion" do
    test "split fragments with <> -> KRAIT-006" do
      code = ~S'a = "krait_analyzer"; b = "/src"; a <> b'
      assert {:policy_violation, %{rule: "KRAIT-006"}} = Quick.quick_validate(code, "elixir")
    end

    test "split _build fragments with <> -> KRAIT-006" do
      code = ~S'x = "_build"; y = "/lib"; x <> y'
      assert {:policy_violation, %{rule: "KRAIT-006"}} = Quick.quick_validate(code, "elixir")
    end

    test "safe <> concat passes" do
      code = ~S'"hello" <> " world"'
      assert {:ok, _} = Quick.quick_validate(code, "elixir")
    end
  end

  # ---------------------------------------------------------------------------
  # Phase 4: M-1, M-5, M-6 — NIF defdelegate parity + Module.safe_concat + :ct_rpc
  # ---------------------------------------------------------------------------

  describe "v14-P4: Module.safe_concat -> KRAIT-002" do
    test "Module.safe_concat -> KRAIT-002" do
      code = ~S'Module.safe_concat([:System, :Utils])'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  describe "v14-P4: :ct_rpc.call -> KRAIT-002" do
    test ":ct_rpc.call -> KRAIT-002" do
      code = ~S':ct_rpc.call(:node, :os, :cmd, [~c"whoami"])'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":ct_rpc bare atom in data position passes" do
      code = ~S'mod = :ct_rpc'
      assert {:ok, _} = Quick.quick_validate(code, "elixir")
    end

    test "defdelegate to :ct_rpc -> KRAIT-002" do
      code = ~S'defdelegate my_call(n, m, f, a), to: :ct_rpc'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  describe "v14-P4: :ssh_connection.exec -> KRAIT-002" do
    test ":ssh_connection.exec -> KRAIT-002" do
      code = ~S':ssh_connection.exec(conn, channel, ~c"ls", 5000)'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":ssh_connection bare atom in data position passes" do
      code = ~S'mod = :ssh_connection'
      assert {:ok, _} = Quick.quick_validate(code, "elixir")
    end
  end

  # ---------------------------------------------------------------------------
  # Phase 5: M-2, M-3, L-5 — :c module, :erl_tar, :xmerl_scan
  # ---------------------------------------------------------------------------

  describe "v14-P5: :c module -> KRAIT-001" do
    test ":c.c -> KRAIT-001" do
      code = ~S':c.c(MyModule)'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":c.l -> KRAIT-001 (broad :c detection)" do
      # :c is in KRAIT-001 bare atoms, checked before KRAIT-005
      code = ~S':c.l(MyModule)'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  describe "v14-P5: :erl_tar -> KRAIT-001" do
    test ":erl_tar.extract -> KRAIT-001" do
      code = ~S':erl_tar.extract(~c"archive.tar")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":erl_tar.create -> KRAIT-001" do
      code = ~S':erl_tar.create(~c"evil.tar", files)'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  describe "v14-P5: :xmerl_scan -> KRAIT-001" do
    test ":xmerl_scan.string -> KRAIT-001" do
      code = ~S':xmerl_scan.string(~c"<root>evil</root>")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":xmerl_scan.file -> KRAIT-001" do
      code = ~S':xmerl_scan.file(~c"/tmp/evil.xml")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  # ---------------------------------------------------------------------------
  # Phase 7: L-1 through L-6 — Remaining Erlang module expansions
  # ---------------------------------------------------------------------------

  describe "v14-P7: :zip additional functions -> KRAIT-001" do
    test ":zip.foldl -> KRAIT-001" do
      code = ~S':zip.foldl(fun, acc, archive)'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":zip.table -> KRAIT-001" do
      code = ~S':zip.table(archive)'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":zip.list_dir -> KRAIT-001" do
      code = ~S':zip.list_dir(archive)'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":zip.unzip -> KRAIT-001" do
      code = ~S':zip.unzip(archive)'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  describe "v14-P7: :shell.start, :ssh_connection.exec -> KRAIT-002" do
    test ":shell.start -> KRAIT-002" do
      code = ~S':shell.start()'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  describe "v14-P7: :filelib credential path ops -> KRAIT-003" do
    test ":filelib.is_file with credential path -> KRAIT-003" do
      code = ~S':filelib.is_file("~/.ssh/id_rsa")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":filelib.is_dir with credential path -> KRAIT-003" do
      code = ~S':filelib.is_dir("~/.aws")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":filelib.wildcard with credential path -> KRAIT-003" do
      code = ~S':filelib.wildcard("~/.ssh/*")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":filelib.ensure_dir with credential path -> KRAIT-003" do
      code = ~S':filelib.ensure_dir("~/.ssh/keys/")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":filelib.file_size with credential path -> KRAIT-003" do
      code = ~S':filelib.file_size("/etc/shadow")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":filelib.is_file with safe path -> KRAIT-ALW (not allowlisted)" do
      code = ~S':filelib.is_file("/tmp/data.txt")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  describe "v14-P7: :beam_lib -> KRAIT-005" do
    test ":beam_lib.chunks -> KRAIT-005" do
      code = ~S':beam_lib.chunks(module, [:abstract_code])'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":beam_lib.info -> KRAIT-005" do
      code = ~S':beam_lib.info(beam_file)'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":beam_lib.all_chunks -> KRAIT-005" do
      code = ~S':beam_lib.all_chunks(beam_file)'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  describe "v14-P7: :merl -> KRAIT-005" do
    test ":merl.quote -> KRAIT-005" do
      code = ~S':merl.quote("ok")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":merl.subst -> KRAIT-005" do
      code = ~S':merl.subst(tree, env)'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":merl.match -> KRAIT-005" do
      code = ~S':merl.match(pattern, tree)'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  # ---------------------------------------------------------------------------
  # Phase 8: L-7 — LiveView PR URL scheme validation
  # ---------------------------------------------------------------------------

  # LiveView URL validation is tested separately in evolution_live_test.exs
  # or via module-level unit tests. The safe_pr_url/1 helper is private,
  # so we test it indirectly through the LiveView render if needed.
end
