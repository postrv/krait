defmodule Krait.Analyzer.AllowlistEnforcementTest do
  use ExUnit.Case, async: true

  alias Krait.Analyzer.Quick

  # Helper: parse code and run check_allowlist
  defp check(code) do
    {:ok, ast} = Code.string_to_quoted(code)
    Quick.check_allowlist(ast)
  end

  # ---------------------------------------------------------------------------
  # Allowlisted modules PASS
  # ---------------------------------------------------------------------------

  describe "allowlisted modules pass" do
    test "Enum.map passes" do
      assert :ok =
               check(~S"""
               defmodule MySkill do
                 def run(list), do: Enum.map(list, & &1)
               end
               """)
    end

    test "Map.get passes" do
      assert :ok = check(~S"Map.get(%{a: 1}, :a)")
    end

    test "String.upcase passes" do
      assert :ok = check(~S'String.upcase("hello")')
    end

    test "Jason.encode! passes" do
      assert :ok = check(~S"Jason.encode!(%{a: 1})")
    end

    test "Regex.match? passes" do
      assert :ok = check(~S'Regex.match?(~r/foo/, "foobar")')
    end

    test "Date.utc_today passes" do
      assert :ok = check(~S"Date.utc_today()")
    end

    test ":math.pow passes" do
      assert :ok = check(~S":math.pow(2, 10)")
    end

    test ":lists.reverse passes" do
      assert :ok = check(~S":lists.reverse([1, 2, 3])")
    end

    test ":rand.uniform passes" do
      assert :ok = check(~S":rand.uniform()")
    end

    test "Krait.Skills.Skill behaviour passes" do
      assert :ok =
               check(~S"""
               defmodule Krait.Skills.Test do
                 @behaviour Krait.Skills.Skill
                 @impl true
                 def name, do: "test"
                 @impl true
                 def description, do: "test"
                 @impl true
                 def execute(_), do: {:ok, nil}
               end
               """)
    end

    test "Krait.Skills.Core.WebFetch call passes" do
      assert :ok =
               check(~S"""
               defmodule MySkill do
                 def run do
                   Krait.Skills.Core.WebFetch.execute(%{"url" => "https://example.com"})
                 end
               end
               """)
    end

    test "multiple allowed modules in one module" do
      assert :ok =
               check(~S"""
               defmodule MySkill do
                 def run(list) do
                   list
                   |> Enum.map(&String.upcase/1)
                   |> Enum.join(", ")
                   |> Jason.encode!()
                 end
               end
               """)
    end

    test "defstruct passes" do
      assert :ok =
               check(~S"""
               defmodule MyStruct do
                 defstruct [:name, :value]
               end
               """)
    end

    test "defprotocol rejected (M-3)" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S"""
               defprotocol MyProtocol do
                 def render(data)
               end
               """)
    end

    test "Base.encode64 passes" do
      assert :ok = check(~S'Base.encode64("hello")')
    end

    test "URI.parse passes" do
      assert :ok = check(~S'URI.parse("https://example.com")')
    end

    test "pattern matching and guards pass" do
      assert :ok =
               check(~S"""
               defmodule MySkill do
                 def run(%{action: "price"} = params) when is_map(params) do
                   {:ok, params}
                 end
               end
               """)
    end

    test "Integer and Float modules pass" do
      assert :ok =
               check(~S"""
               defmodule MySkill do
                 def run do
                   Integer.parse("42")
                   Float.round(3.14159, 2)
                 end
               end
               """)
    end

    test "Stream module passes" do
      assert :ok = check(~S"Stream.map([1,2,3], & &1 * 2)")
    end

    test ":binary module passes" do
      assert :ok = check(~S':binary.split("hello world", " ")')
    end

    test ":base64 module passes" do
      assert :ok = check(~S':base64.encode("hello")')
    end
  end

  # ---------------------------------------------------------------------------
  # Non-allowlisted Elixir modules REJECTED with KRAIT-ALW
  # ---------------------------------------------------------------------------

  describe "non-allowlisted Elixir modules rejected" do
    test "System.cmd rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S'System.cmd("ls", [])')
    end

    test "File.read rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S'File.read("/etc/passwd")')
    end

    test "Port.open rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S'Port.open({:spawn, "cmd"}, [])')
    end

    test "Process.info rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S"Process.info(self())")
    end

    test "Node.connect rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S"Node.connect(:other@host)")
    end

    test "Task.async rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S"Task.async(fn -> :ok end)")
    end

    test "Agent.start_link rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S"Agent.start_link(fn -> %{} end)")
    end

    test "GenServer.start_link rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S"GenServer.start_link(MyMod, [])")
    end

    test "Supervisor.start_link rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S"Supervisor.start_link([], strategy: :one_for_one)")
    end

    test "Code.eval_string rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S'Code.eval_string("1 + 1")')
    end

    test "Req.get rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S'Req.get("https://example.com")')
    end

    test "HTTPoison.get rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S'HTTPoison.get("https://example.com")')
    end

    test "Application.put_env rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S"Application.put_env(:my_app, :key, :value)")
    end
  end

  # ---------------------------------------------------------------------------
  # Non-allowlisted Erlang modules REJECTED
  # ---------------------------------------------------------------------------

  describe "non-allowlisted Erlang modules rejected" do
    test ":os.cmd rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S':os.cmd(~c"ls")')
    end

    test ":file.read_file rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S':file.read_file("/etc/passwd")')
    end

    test ":gen_tcp.connect rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S':gen_tcp.connect(~c"localhost", 80, [])')
    end

    test ":code.load_binary rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S':code.load_binary(MyMod, ~c"mymod.beam", <<>>)')
    end

    test ":ets.new rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S":ets.new(:my_table, [:set])")
    end

    test ":erlang.apply rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S':erlang.apply(System, :cmd, ["ls", []])')
    end

    test ":compile.forms rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S":compile.forms([])")
    end

    test ":gen_server.start rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S":gen_server.start(MyMod, [], [])")
    end
  end

  # ---------------------------------------------------------------------------
  # Indirection patterns caught
  # ---------------------------------------------------------------------------

  describe "indirection patterns caught" do
    test "apply(System, :cmd, ...) rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S'apply(System, :cmd, ["ls", []])')
    end

    test "Function.capture(System, :cmd, 2) rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S"Function.capture(System, :cmd, 2)")
    end

    test "&System.cmd/2 capture shorthand rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S"fun = &System.cmd/2")
    end

    test "import System rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S"import System")
    end

    test "alias System rejected" do
      # alias is technically renaming, but referencing System at all is not allowed
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S"alias System")
    end

    test "use SomeUnknown rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S"use SomeUnknown")
    end

    test "require SomeUnknown rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S"require SomeUnknown")
    end

    test "defdelegate to: System rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S"defdelegate my_cmd(cmd, args), to: System")
    end

    test "defdelegate to: :os rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S"defdelegate my_cmd(cmd), to: :os")
    end

    test "apply(:os, :cmd, ...) bare atom rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S'apply(:os, :cmd, [~c"ls"])')
    end

    test "@mod = System; @mod.cmd(...) module attribute indirection rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S"""
               defmodule Evil do
                 @target System
                 def run, do: @target.cmd("ls", [])
               end
               """)
    end

    test "@mod = :os; @mod.cmd(...) erlang attribute indirection rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S"""
               defmodule Evil do
                 @target :os
                 def run, do: @target.cmd(~c"ls")
               end
               """)
    end

    test "Kernel.apply(System, :cmd, ...) rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S'Kernel.apply(System, :cmd, ["ls", []])')
    end

    test "Kernel.apply(:os, :cmd, ...) rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S'Kernel.apply(:os, :cmd, [~c"ls"])')
    end

    test "apply(@attr, :cmd, ...) with attr resolving to forbidden module" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S"""
               defmodule Evil do
                 @target :os
                 def run, do: apply(@target, :cmd, [~c"ls"])
               end
               """)
    end

    test "Function.capture(:os, :cmd, 1) rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S"Function.capture(:os, :cmd, 1)")
    end
  end

  # ---------------------------------------------------------------------------
  # Kernel function restrictions
  # ---------------------------------------------------------------------------

  describe "Kernel function restrictions" do
    test "spawn/1 rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S"spawn(fn -> :ok end)")
    end

    test "spawn_link/1 rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S"spawn_link(fn -> :ok end)")
    end

    test "send/2 rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S"send(pid, :message)")
    end

    test "self/0 rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S"self()")
    end

    test "exit/1 rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S"exit(:normal)")
    end

    test "node/0 rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S"node()")
    end

    test "make_ref/0 rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S"make_ref()")
    end

    test "if/unless/cond/case pass" do
      assert :ok =
               check(~S"""
               defmodule MySkill do
                 def run(x) do
                   if x > 0 do
                     cond do
                       x > 10 -> :big
                       true -> :small
                     end
                   else
                     unless x < -10, do: :medium, else: :tiny
                   end
                 end
               end
               """)
    end

    test "raise passes" do
      assert :ok = check(~S'raise "boom"')
    end

    test "inspect passes" do
      assert :ok = check(~S"inspect(%{a: 1})")
    end

    test "pattern matching and guards pass" do
      assert :ok =
               check(~S"""
               defmodule MySkill do
                 def run(x) when is_integer(x) and x > 0, do: x
                 def run(_), do: 0
               end
               """)
    end
  end

  # ---------------------------------------------------------------------------
  # defmacro/defmacrop banned
  # ---------------------------------------------------------------------------

  describe "defmacro/defmacrop banned" do
    test "defmacro rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S"""
               defmodule Evil do
                 defmacro my_macro(expr) do
                   quote do: unquote(expr)
                 end
               end
               """)
    end

    test "defmacrop rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S"""
               defmodule Evil do
                 defmacrop my_macro(expr) do
                   quote do: unquote(expr)
                 end
               end
               """)
    end
  end

  # ---------------------------------------------------------------------------
  # KRAIT-ALW rule ID
  # ---------------------------------------------------------------------------

  describe "KRAIT-ALW rule ID" do
    test "violation returns rule KRAIT-ALW" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S'System.cmd("ls", [])')
    end

    test "violation includes explanation" do
      {:policy_violation, %{rule: "KRAIT-ALW", explanation: explanation}} =
        check(~S'System.cmd("ls", [])')

      assert is_binary(explanation)
      assert String.contains?(explanation, "System")
    end

    test "violation includes location map" do
      {:policy_violation, %{location: location}} =
        check(~S'System.cmd("ls", [])')

      assert is_map(location)
    end
  end

  # v25 H-4: @derive catch-all fail-closed
  describe "v25 H-4: @derive fail-closed" do
    test "unknown @derive format is rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S"""
               defmodule MySkill do
                 @derive {SomeUnknownProtocol, []}
                 defstruct [:name]
               end
               """)
    end

    test "allowed @derive Inspect passes" do
      assert :ok =
               check(~S"""
               defmodule MySkill do
                 @derive Inspect
                 defstruct [:name]
               end
               """)
    end

    test "allowed @derive [Inspect, Enumerable] passes" do
      assert :ok =
               check(~S"""
               defmodule MySkill do
                 @derive [Inspect, Enumerable]
                 defstruct [:name]
               end
               """)
    end
  end

  # v25 H-4: use options module inspection
  describe "v25 H-4: use option module refs" do
    test "use with non-allowlisted module in options is rejected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               check(~S"""
               defmodule MySkill do
                 use Krait.Skills.Skill, handler: File
               end
               """)
    end

    test "use with atom option value (not a module ref) passes" do
      assert :ok =
               check(~S"""
               defmodule MySkill do
                 use Krait.Skills.Skill, restart: :transient
               end
               """)
    end
  end
end
