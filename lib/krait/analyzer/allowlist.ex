defmodule Krait.Analyzer.Allowlist do
  @moduledoc """
  Defines the module/function allowlist for agent-generated code.

  Only explicitly permitted modules and functions are accepted — everything
  else is denied by default. This inverts the previous denylist model where
  each dangerous entry point had to be enumerated individually.

  ## Tiers

  1. **Pure computation** — Enum, Map, String, Jason, etc.
  2. **Restricted Kernel** — arithmetic, guards, control flow (no spawn/send/apply)
  3. **Safe Erlang** — :math, :lists, :maps, :binary, :rand, etc.
  4. **Approved deps** — initially empty, extended per-project
  5. **Krait framework** — Skill behaviour, capability interfaces

  All sets are compile-time MapSets for O(1) lookups with zero runtime cost.
  """

  # ---------------------------------------------------------------------------
  # Tier 1: Pure computation modules (Elixir standard library)
  # ---------------------------------------------------------------------------

  @tier_1_modules MapSet.new([
                    Enum,
                    Map,
                    List,
                    Keyword,
                    Tuple,
                    MapSet,
                    Stream,
                    Range,
                    Access,
                    String,
                    Regex,
                    Base,
                    URI,
                    Integer,
                    Float,
                    Bitwise,
                    Date,
                    DateTime,
                    NaiveDateTime,
                    Time,
                    Calendar,
                    Jason,
                    Inspect,
                    Collectable,
                    Enumerable,
                    Kernel
                  ])

  # ---------------------------------------------------------------------------
  # Tier 2: Restricted Kernel functions
  # ---------------------------------------------------------------------------

  # Kernel functions that are DENIED in generated code
  @denied_kernel_functions MapSet.new([
                             :spawn,
                             :spawn_link,
                             :spawn_monitor,
                             :send,
                             :self,
                             :apply,
                             :exit,
                             :node,
                             :nodes,
                             :make_ref,
                             :throw,
                             :open_port,
                             :process_flag,
                             :register,
                             :whereis,
                             :monitor,
                             :demonitor,
                             :link,
                             :unlink,
                             :group_leader,
                             :disconnect_node,
                             # v17: H-6 — expanded denied kernel functions
                             :binding,
                             :var!,
                             :macro_exported?,
                             :function_exported?,
                             :dbg,
                             :struct,
                             :struct!,
                             :tap
                           ])

  # ---------------------------------------------------------------------------
  # Tier 3: Safe Erlang modules
  # ---------------------------------------------------------------------------

  @tier_3_erlang_modules MapSet.new([
                           :math,
                           :lists,
                           :maps,
                           :binary,
                           :string,
                           :unicode,
                           :calendar,
                           :base64,
                           :rand
                         ])

  # ---------------------------------------------------------------------------
  # Tier 4: Approved external dependencies (initially empty)
  # ---------------------------------------------------------------------------

  @tier_4_deps MapSet.new([])

  # ---------------------------------------------------------------------------
  # Tier 5: Krait framework interfaces
  # ---------------------------------------------------------------------------

  @tier_5_krait_modules MapSet.new([
                          Krait.Skills.Skill,
                          Krait.Skills.Core.WebFetch,
                          Krait.Skills.Core.Filesystem,
                          Krait.Skills.Core.MemorySkill,
                          Krait.Skills.CapableSkill,
                          Krait.Skills.Capabilities.FilesystemCap,
                          Krait.Skills.Capabilities.NetworkCap,
                          Krait.Skills.Capabilities.MemoryCap
                        ])

  # ---------------------------------------------------------------------------
  # Structural declarations
  # ---------------------------------------------------------------------------

  # ---------------------------------------------------------------------------
  # Denied functions on otherwise-allowed modules (C-5, H-5)
  # ---------------------------------------------------------------------------

  @denied_on_allowed_modules %{
    String => MapSet.new([:to_atom, :to_existing_atom]),
    Stream => MapSet.new([:resource, :run, :repeatedly, :iterate, :unfold])
  }

  # Macros allowed in generated code
  @allowed_macros MapSet.new([
                    :def,
                    :defp,
                    :defmodule,
                    :defstruct,
                    :defguard,
                    :defguardp,
                    :defexception
                  ])

  # Macros explicitly denied in generated code
  @denied_macros MapSet.new([
                   :defmacro,
                   :defmacrop
                 ])

  # Module attributes allowed in generated code
  @allowed_attrs MapSet.new([
                   :doc,
                   :moduledoc,
                   :spec,
                   :type,
                   :typep,
                   :opaque,
                   :behaviour,
                   :impl,
                   :enforce_keys,
                   :derive,
                   :callback,
                   :optional_callbacks,
                   :dialyzer
                 ])

  # ---------------------------------------------------------------------------
  # Public API
  # ---------------------------------------------------------------------------

  @doc "Check if an Elixir module is on the allowlist (any tier)"
  @spec allowed_module?(module()) :: boolean()
  def allowed_module?(module) when is_atom(module) do
    MapSet.member?(@tier_1_modules, module) or
      MapSet.member?(@tier_4_deps, module) or
      MapSet.member?(@tier_5_krait_modules, module)
  end

  @doc "Check if a Kernel function (by atom name) is allowed"
  @spec allowed_kernel_function?(atom()) :: boolean()
  def allowed_kernel_function?(function) when is_atom(function) do
    not MapSet.member?(@denied_kernel_functions, function)
  end

  @doc "Check if a Kernel function is denied"
  @spec denied_kernel_function?(atom()) :: boolean()
  def denied_kernel_function?(function) when is_atom(function) do
    MapSet.member?(@denied_kernel_functions, function)
  end

  @doc "Check if an Erlang module (atom) is on the allowlist"
  @spec allowed_erlang_module?(atom()) :: boolean()
  def allowed_erlang_module?(module) when is_atom(module) do
    MapSet.member?(@tier_3_erlang_modules, module)
  end

  @doc "Check if a Krait framework module is allowed"
  @spec allowed_krait_module?(module()) :: boolean()
  def allowed_krait_module?(module) when is_atom(module) do
    MapSet.member?(@tier_5_krait_modules, module)
  end

  @doc "Check if a macro/special form is allowed in generated code"
  @spec allowed_macro?(atom()) :: boolean()
  def allowed_macro?(macro) when is_atom(macro) do
    MapSet.member?(@allowed_macros, macro)
  end

  @doc "Check if a macro is explicitly denied"
  @spec denied_macro?(atom()) :: boolean()
  def denied_macro?(macro) when is_atom(macro) do
    MapSet.member?(@denied_macros, macro)
  end

  @doc "Check if a module attribute is allowed"
  @spec allowed_attr?(atom()) :: boolean()
  def allowed_attr?(attr) when is_atom(attr) do
    MapSet.member?(@allowed_attrs, attr)
  end

  @doc "Check if a specific function is denied on an otherwise-allowed module"
  @spec denied_function_on_allowed_module?(module(), atom()) :: boolean()
  def denied_function_on_allowed_module?(module, function)
      when is_atom(module) and is_atom(function) do
    case Map.get(@denied_on_allowed_modules, module) do
      nil -> false
      denied_set -> MapSet.member?(denied_set, function)
    end
  end

  @doc "Check if a dependency module is approved"
  @spec allowed_dep?(module()) :: boolean()
  def allowed_dep?(module) when is_atom(module) do
    MapSet.member?(@tier_4_deps, module)
  end

  # Protocols allowed in @derive declarations
  @allowed_derive_protocols MapSet.new([Inspect, Collectable, Enumerable, String.Chars, Access])

  @doc "Check if a protocol is allowed in @derive declarations"
  @spec allowed_derive_protocol?(module()) :: boolean()
  def allowed_derive_protocol?(protocol) when is_atom(protocol) do
    MapSet.member?(@allowed_derive_protocols, protocol)
  end

  # Compile-time hook attributes that are banned
  @banned_compile_attrs MapSet.new([:before_compile, :after_compile, :on_load, :on_definition])

  @doc "Check if a module attribute is a banned compile hook"
  @spec banned_compile_attr?(atom()) :: boolean()
  def banned_compile_attr?(attr) when is_atom(attr) do
    MapSet.member?(@banned_compile_attrs, attr)
  end

  # ---------------------------------------------------------------------------
  # Tier accessors (for testing / introspection)
  # ---------------------------------------------------------------------------

  @doc false
  def tier_1_modules, do: @tier_1_modules

  @doc false
  def tier_3_erlang_modules, do: @tier_3_erlang_modules

  @doc false
  def tier_4_deps, do: @tier_4_deps

  @doc false
  def tier_5_krait_modules, do: @tier_5_krait_modules

  @doc false
  def denied_kernel_functions_set, do: @denied_kernel_functions

  @doc false
  def allowed_macros_set, do: @allowed_macros

  @doc false
  def denied_macros_set, do: @denied_macros

  @doc false
  def allowed_attrs_set, do: @allowed_attrs
end
