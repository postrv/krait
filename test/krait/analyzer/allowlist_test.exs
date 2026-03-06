defmodule Krait.Analyzer.AllowlistTest do
  use ExUnit.Case, async: true

  alias Krait.Analyzer.Allowlist

  # ---------------------------------------------------------------------------
  # Tier 1: Pure computation modules
  # ---------------------------------------------------------------------------

  describe "Tier 1 — pure computation modules" do
    test "Enum is allowed" do
      assert Allowlist.allowed_module?(Enum)
    end

    test "Map is allowed" do
      assert Allowlist.allowed_module?(Map)
    end

    test "List is allowed" do
      assert Allowlist.allowed_module?(List)
    end

    test "Keyword is allowed" do
      assert Allowlist.allowed_module?(Keyword)
    end

    test "Tuple is allowed" do
      assert Allowlist.allowed_module?(Tuple)
    end

    test "MapSet is allowed" do
      assert Allowlist.allowed_module?(MapSet)
    end

    test "Stream is allowed" do
      assert Allowlist.allowed_module?(Stream)
    end

    test "Range is allowed" do
      assert Allowlist.allowed_module?(Range)
    end

    test "Access is allowed" do
      assert Allowlist.allowed_module?(Access)
    end

    test "String is allowed" do
      assert Allowlist.allowed_module?(String)
    end

    test "Regex is allowed" do
      assert Allowlist.allowed_module?(Regex)
    end

    test "Base is allowed" do
      assert Allowlist.allowed_module?(Base)
    end

    test "URI is allowed" do
      assert Allowlist.allowed_module?(URI)
    end

    test "Integer is allowed" do
      assert Allowlist.allowed_module?(Integer)
    end

    test "Float is allowed" do
      assert Allowlist.allowed_module?(Float)
    end

    test "Bitwise is allowed" do
      assert Allowlist.allowed_module?(Bitwise)
    end

    test "Date is allowed" do
      assert Allowlist.allowed_module?(Date)
    end

    test "DateTime is allowed" do
      assert Allowlist.allowed_module?(DateTime)
    end

    test "NaiveDateTime is allowed" do
      assert Allowlist.allowed_module?(NaiveDateTime)
    end

    test "Time is allowed" do
      assert Allowlist.allowed_module?(Time)
    end

    test "Calendar is allowed" do
      assert Allowlist.allowed_module?(Calendar)
    end

    test "Jason is allowed" do
      assert Allowlist.allowed_module?(Jason)
    end

    test "Inspect is allowed" do
      assert Allowlist.allowed_module?(Inspect)
    end

    test "Collectable is allowed" do
      assert Allowlist.allowed_module?(Collectable)
    end

    test "Enumerable is allowed" do
      assert Allowlist.allowed_module?(Enumerable)
    end

    test "Kernel is allowed" do
      assert Allowlist.allowed_module?(Kernel)
    end
  end

  # ---------------------------------------------------------------------------
  # Tier 2: Restricted Kernel functions
  # ---------------------------------------------------------------------------

  describe "Tier 2 — Kernel function restrictions" do
    test "arithmetic operators are allowed" do
      for fun <- [:+, :-, :*, :/, :div, :rem] do
        assert Allowlist.allowed_kernel_function?(fun),
               "Expected #{fun} to be allowed"
      end
    end

    test "comparison operators are allowed" do
      for fun <- [:==, :!=, :>, :<, :>=, :<=, :===, :!==] do
        assert Allowlist.allowed_kernel_function?(fun),
               "Expected #{fun} to be allowed"
      end
    end

    test "type checks are allowed" do
      for fun <- [
            :is_atom,
            :is_binary,
            :is_integer,
            :is_float,
            :is_list,
            :is_map,
            :is_nil,
            :is_boolean,
            :is_tuple,
            :is_number
          ] do
        assert Allowlist.allowed_kernel_function?(fun),
               "Expected #{fun} to be allowed"
      end
    end

    test "basic functions are allowed" do
      for fun <- [
            :length,
            :to_string,
            :inspect,
            :abs,
            :max,
            :min,
            :not,
            :and,
            :or,
            :in,
            :hd,
            :tl,
            :elem,
            :map_size,
            :tuple_size,
            :byte_size,
            :bit_size
          ] do
        assert Allowlist.allowed_kernel_function?(fun),
               "Expected #{fun} to be allowed"
      end
    end

    test "control flow macros are allowed" do
      for fun <- [:if, :unless, :cond, :case, :raise, :reraise] do
        assert Allowlist.allowed_kernel_function?(fun),
               "Expected #{fun} to be allowed"
      end
    end

    test "match?/2 is allowed" do
      assert Allowlist.allowed_kernel_function?(:match?)
    end

    test "spawn/1 is denied" do
      assert Allowlist.denied_kernel_function?(:spawn)
      refute Allowlist.allowed_kernel_function?(:spawn)
    end

    test "spawn_link/1 is denied" do
      assert Allowlist.denied_kernel_function?(:spawn_link)
    end

    test "spawn_monitor/1 is denied" do
      assert Allowlist.denied_kernel_function?(:spawn_monitor)
    end

    test "send/2 is denied" do
      assert Allowlist.denied_kernel_function?(:send)
    end

    test "self/0 is denied" do
      assert Allowlist.denied_kernel_function?(:self)
    end

    test "apply/2 and apply/3 are denied" do
      assert Allowlist.denied_kernel_function?(:apply)
    end

    test "exit/1 is denied" do
      assert Allowlist.denied_kernel_function?(:exit)
    end

    test "node/0 is denied" do
      assert Allowlist.denied_kernel_function?(:node)
    end

    test "make_ref/0 is denied" do
      assert Allowlist.denied_kernel_function?(:make_ref)
    end

    test "throw/1 is denied" do
      assert Allowlist.denied_kernel_function?(:throw)
    end

    test "open_port/2 is denied" do
      assert Allowlist.denied_kernel_function?(:open_port)
    end

    test "process_flag/2 is denied" do
      assert Allowlist.denied_kernel_function?(:process_flag)
    end
  end

  # ---------------------------------------------------------------------------
  # Tier 3: Safe Erlang modules
  # ---------------------------------------------------------------------------

  describe "Tier 3 — safe Erlang modules" do
    test ":math is allowed" do
      assert Allowlist.allowed_erlang_module?(:math)
    end

    test ":lists is allowed" do
      assert Allowlist.allowed_erlang_module?(:lists)
    end

    test ":maps is allowed" do
      assert Allowlist.allowed_erlang_module?(:maps)
    end

    test ":binary is allowed" do
      assert Allowlist.allowed_erlang_module?(:binary)
    end

    test ":string is allowed" do
      assert Allowlist.allowed_erlang_module?(:string)
    end

    test ":unicode is allowed" do
      assert Allowlist.allowed_erlang_module?(:unicode)
    end

    test ":calendar is allowed" do
      assert Allowlist.allowed_erlang_module?(:calendar)
    end

    test ":base64 is allowed" do
      assert Allowlist.allowed_erlang_module?(:base64)
    end

    test ":rand is allowed" do
      assert Allowlist.allowed_erlang_module?(:rand)
    end

    test ":os is NOT allowed" do
      refute Allowlist.allowed_erlang_module?(:os)
    end

    test ":file is NOT allowed" do
      refute Allowlist.allowed_erlang_module?(:file)
    end

    test ":code is NOT allowed" do
      refute Allowlist.allowed_erlang_module?(:code)
    end

    test ":compile is NOT allowed" do
      refute Allowlist.allowed_erlang_module?(:compile)
    end

    test ":ets is NOT allowed" do
      refute Allowlist.allowed_erlang_module?(:ets)
    end

    test ":gen_tcp is NOT allowed" do
      refute Allowlist.allowed_erlang_module?(:gen_tcp)
    end

    test ":gen_server is NOT allowed" do
      refute Allowlist.allowed_erlang_module?(:gen_server)
    end

    test ":erl_eval is NOT allowed" do
      refute Allowlist.allowed_erlang_module?(:erl_eval)
    end

    test ":erlang is NOT allowed" do
      refute Allowlist.allowed_erlang_module?(:erlang)
    end

    test ":application is NOT allowed" do
      refute Allowlist.allowed_erlang_module?(:application)
    end

    test ":proc_lib is NOT allowed" do
      refute Allowlist.allowed_erlang_module?(:proc_lib)
    end
  end

  # ---------------------------------------------------------------------------
  # Tier 4: Approved deps (initially empty)
  # ---------------------------------------------------------------------------

  describe "Tier 4 — approved dependencies" do
    test "Decimal is NOT allowed by default" do
      refute Allowlist.allowed_dep?(Decimal)
    end

    test "tier 4 is initially empty" do
      assert MapSet.size(Allowlist.tier_4_deps()) == 0
    end
  end

  # ---------------------------------------------------------------------------
  # Tier 5: Krait framework interfaces
  # ---------------------------------------------------------------------------

  describe "Tier 5 — Krait framework interfaces" do
    test "Krait.Skills.Skill is allowed" do
      assert Allowlist.allowed_module?(Krait.Skills.Skill)
    end

    test "Krait.Skills.Core.WebFetch is allowed" do
      assert Allowlist.allowed_module?(Krait.Skills.Core.WebFetch)
    end

    test "Krait.Skills.Core.Filesystem is allowed" do
      assert Allowlist.allowed_module?(Krait.Skills.Core.Filesystem)
    end

    test "Krait.Skills.Core.MemorySkill is allowed" do
      assert Allowlist.allowed_module?(Krait.Skills.Core.MemorySkill)
    end

    test "Krait.Evolution is NOT allowed" do
      refute Allowlist.allowed_module?(Krait.Evolution)
    end

    test "Krait.Analyzer is NOT allowed" do
      refute Allowlist.allowed_module?(Krait.Analyzer)
    end

    test "Krait.Sandbox is NOT allowed" do
      refute Allowlist.allowed_module?(Krait.Sandbox)
    end

    test "Krait.Brain is NOT allowed" do
      refute Allowlist.allowed_module?(Krait.Brain)
    end

    test "Krait.Repo is NOT allowed" do
      refute Allowlist.allowed_module?(Krait.Repo)
    end

    test "KraitWeb is NOT allowed" do
      refute Allowlist.allowed_module?(KraitWeb)
    end
  end

  # ---------------------------------------------------------------------------
  # Structural declarations
  # ---------------------------------------------------------------------------

  describe "structural declarations — allowed macros" do
    test "def is allowed" do
      assert Allowlist.allowed_macro?(:def)
    end

    test "defp is allowed" do
      assert Allowlist.allowed_macro?(:defp)
    end

    test "defmodule is allowed" do
      assert Allowlist.allowed_macro?(:defmodule)
    end

    test "defstruct is allowed" do
      assert Allowlist.allowed_macro?(:defstruct)
    end

    test "defprotocol is denied (v17: M-3)" do
      refute Allowlist.allowed_macro?(:defprotocol)
    end

    test "defimpl is denied (v17: M-3)" do
      refute Allowlist.allowed_macro?(:defimpl)
    end

    test "defguard is allowed" do
      assert Allowlist.allowed_macro?(:defguard)
    end

    test "defguardp is allowed" do
      assert Allowlist.allowed_macro?(:defguardp)
    end

    test "defexception is allowed" do
      assert Allowlist.allowed_macro?(:defexception)
    end
  end

  describe "structural declarations — denied macros" do
    test "defmacro is denied" do
      assert Allowlist.denied_macro?(:defmacro)
      refute Allowlist.allowed_macro?(:defmacro)
    end

    test "defmacrop is denied" do
      assert Allowlist.denied_macro?(:defmacrop)
      refute Allowlist.allowed_macro?(:defmacrop)
    end
  end

  describe "allowed module attributes" do
    test "standard documentation attrs" do
      for attr <- [:doc, :moduledoc, :spec, :type, :typep, :opaque] do
        assert Allowlist.allowed_attr?(attr), "Expected @#{attr} to be allowed"
      end
    end

    test "behaviour attrs" do
      for attr <- [:behaviour, :impl, :callback, :optional_callbacks] do
        assert Allowlist.allowed_attr?(attr), "Expected @#{attr} to be allowed"
      end
    end

    test "struct attrs" do
      for attr <- [:enforce_keys, :derive] do
        assert Allowlist.allowed_attr?(attr), "Expected @#{attr} to be allowed"
      end
    end

    test "@dialyzer is allowed" do
      assert Allowlist.allowed_attr?(:dialyzer)
    end
  end

  # ---------------------------------------------------------------------------
  # Default deny
  # ---------------------------------------------------------------------------

  describe "default deny" do
    test "SomeRandomModule is NOT allowed" do
      refute Allowlist.allowed_module?(SomeRandomModule)
    end

    test ":some_random_erlang is NOT allowed" do
      refute Allowlist.allowed_erlang_module?(:some_random_erlang)
    end

    test "System is NOT allowed" do
      refute Allowlist.allowed_module?(System)
    end

    test "File is NOT allowed" do
      refute Allowlist.allowed_module?(File)
    end

    test "Process is NOT allowed" do
      refute Allowlist.allowed_module?(Process)
    end

    test "Code is NOT allowed" do
      refute Allowlist.allowed_module?(Code)
    end

    test "Node is NOT allowed" do
      refute Allowlist.allowed_module?(Node)
    end

    test "Port is NOT allowed" do
      refute Allowlist.allowed_module?(Port)
    end

    test "Task is NOT allowed" do
      refute Allowlist.allowed_module?(Task)
    end

    test "Agent is NOT allowed" do
      refute Allowlist.allowed_module?(Agent)
    end

    test "GenServer is NOT allowed" do
      refute Allowlist.allowed_module?(GenServer)
    end

    test "Supervisor is NOT allowed" do
      refute Allowlist.allowed_module?(Supervisor)
    end

    test "Application is NOT allowed" do
      refute Allowlist.allowed_module?(Application)
    end

    test "Req is NOT allowed" do
      refute Allowlist.allowed_module?(Req)
    end

    test "HTTPoison is NOT allowed" do
      refute Allowlist.allowed_module?(HTTPoison)
    end

    test "unknown macros are not in allowed set" do
      refute Allowlist.allowed_macro?(:defwhatever)
    end

    test "unknown attrs are not in allowed set" do
      refute Allowlist.allowed_attr?(:before_compile)
      refute Allowlist.allowed_attr?(:after_compile)
      refute Allowlist.allowed_attr?(:on_definition)
      refute Allowlist.allowed_attr?(:on_load)
    end
  end

  # ---------------------------------------------------------------------------
  # allowed_krait_module?/1 — direct Tier 5 check
  # ---------------------------------------------------------------------------

  describe "allowed_krait_module?/1" do
    test "returns true for framework interfaces" do
      assert Allowlist.allowed_krait_module?(Krait.Skills.Skill)
      assert Allowlist.allowed_krait_module?(Krait.Skills.Core.WebFetch)
    end

    test "returns false for internal modules" do
      refute Allowlist.allowed_krait_module?(Krait.Evolution)
      refute Allowlist.allowed_krait_module?(Krait.Analyzer)
    end
  end
end
