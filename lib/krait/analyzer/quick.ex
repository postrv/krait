defmodule Krait.Analyzer.Quick do
  @moduledoc """
  Pure-Elixir fallback implementation of the Quick Analyzer.

  Uses AST walking via `Macro.prewalk/3` to detect policy violations,
  `Code.string_to_quoted/2` for syntax checking, and simple heuristics
  for complexity scoring.

  This module implements `Krait.Analyzer.QuickBehaviour` and will be
  replaced by a Rust NIF (tree-sitter + BLAKE3) once that integration
  is ready. The interface stays the same.
  """

  @behaviour Krait.Analyzer.QuickBehaviour

  alias Krait.Analyzer.Allowlist

  require Logger

  # ---------------------------------------------------------------------------
  # KRAIT Policy Rules — AST-based definitions
  # ---------------------------------------------------------------------------

  # KRAIT-003: Credential path access (compound: file op + credential path in string literal)
  @krait_003_file_op_calls [
    {[:File], :read},
    {[:File], :read!},
    {[:File], :write},
    {[:File], :write!},
    {[:Path], :expand},
    # v12: V11-H3 — expanded File operations
    {[:File], :stream!},
    {[:File], :open},
    {[:File], :cp},
    {[:File], :cp!},
    {[:File], :cp_r},
    {[:File], :cp_r!},
    {[:File], :rename},
    {[:File], :rename!},
    {[:File], :ln_s},
    {[:File], :ln_s!},
    {[:File], :stat},
    {[:File], :stat!},
    {[:File], :ls},
    {[:File], :ls!},
    # v12: V11-C1 — Path.join as file op for credential path construction
    {[:Path], :join},
    # v15: H-4/H-5 — missing File operations
    {[:File], :exists?},
    {[:File], :dir?},
    {[:File], :regular?},
    {[:File], :rm},
    {[:File], :rm!},
    {[:File], :rm_rf},
    {[:File], :rm_rf!},
    {[:File], :mkdir_p},
    {[:File], :mkdir_p!},
    {[:File], :touch},
    {[:File], :touch!},
    # v16: C-2/C-3/H-4 — missing file ops
    {[:Path], :wildcard},
    {[:File], :lstat},
    {[:File], :lstat!},
    {[:File], :stream}
  ]
  @krait_003_erlang_file_ops [
    {:file, :read_file},
    {:file, :write_file},
    {:file, :read_file_info},
    # v12: V11-H3 — expanded :file operations
    {:file, :list_dir},
    {:file, :consult},
    {:file, :del_dir_r},
    {:file, :make_dir_p},
    {:file, :copy},
    # v12: Phase 3 — :prim_file low-level bypass
    {:prim_file, :read_file},
    {:prim_file, :write_file},
    {:prim_file, :list_dir},
    # v14: C-1 — :file low-level operations bypass
    {:file, :open},
    {:file, :read},
    {:file, :read_line},
    {:file, :pread},
    {:file, :delete},
    {:file, :rename},
    {:file, :make_symlink},
    # v14: C-1 — :prim_file low-level bypass expansion
    {:prim_file, :open},
    {:prim_file, :read},
    {:prim_file, :write},
    # v14: L-3 — :filelib credential path operations
    {:filelib, :is_file},
    {:filelib, :is_dir},
    {:filelib, :wildcard},
    {:filelib, :ensure_dir},
    {:filelib, :file_size},
    # v15: H-6/H-7 — :ram_file and missing :file ops
    {:ram_file, :open},
    {:ram_file, :read},
    {:ram_file, :write},
    {:ram_file, :get_file},
    {:file, :read_link},
    {:file, :read_link_info},
    {:file, :get_cwd},
    {:file, :write},
    # v16: M-4 — :file.set_cwd
    {:file, :set_cwd}
  ]

  @krait_003_credential_paths [
    "~/.ssh",
    "~/.aws",
    "~/.config/gcloud",
    "~/.gnupg",
    ".env",
    "credentials",
    "secrets",
    # v10: H7 expanded credential paths
    "~/.kube/config",
    "~/.docker/config.json",
    "~/.netrc",
    "~/.git-credentials",
    "/etc/shadow",
    # v10: H4 — /proc/self/* credential exfiltration
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/proc/self/maps",
    "/proc/self/exe",
    "/proc/self/fd",
    # v15: MR-006 — missing credential paths
    "~/.npmrc",
    "~/.pypirc",
    "~/.m2/settings.xml",
    "~/.vault-token",
    "~/.gradle/gradle.properties",
    # v16: C-4 — additional credential paths
    "/etc/passwd",
    "~/.bash_history",
    "~/.zsh_history",
    "terraform.tfstate",
    ".pgpass"
  ]

  # v10: M1 — Credential path segments for split-path detection
  # These catch Path.expand("~") <> "/.ssh/id_rsa" where no single string contains "~/.ssh"
  @krait_003_credential_segments [
    "/.ssh/",
    "/.aws/",
    "/.gnupg/",
    "/.config/gcloud/",
    "/.kube/",
    "/.docker/",
    "/.netrc",
    "/.git-credentials",
    "/proc/self/",
    # v12: V11-C1 — bare directory names for partial match (Path.join detection)
    ".ssh",
    ".aws",
    ".gnupg",
    ".config/gcloud",
    ".kube",
    ".docker",
    ".netrc",
    ".git-credentials",
    # v15: MR-006 — missing credential segments
    ".npmrc",
    ".pypirc",
    ".m2/settings.xml",
    ".vault-token",
    ".gradle/gradle.properties",
    # v16: C-4 — additional credential segments
    ".bash_history",
    ".zsh_history",
    "terraform.tfstate",
    ".pgpass"
  ]

  # KRAIT-006: Immutable path targeting — checked via string literals in AST
  @krait_006_patterns [
    "native/krait_analyzer",
    ".krait-immutable",
    "krait-rules.yaml",
    # v13: H1 — _build/ path protection
    "_build/",
    # v16: C-1/H-7 — supply chain / CI/CD / persistent backdoor paths
    "mix.exs",
    ".iex.exs",
    "config/",
    "priv/",
    ".github/",
    "Dockerfile",
    "Makefile",
    "deps/",
    ".git/",
    "rel/",
    ".gitignore",
    ".tool-versions"
  ]

  # Forbidden segments for integer sequence detection (broader than patterns)
  @krait_006_forbidden_segments [
    "native/krait_analyzer",
    "krait_analyzer",
    ".krait-immutable",
    "krait-rules.yaml",
    "krait-rules",
    # v13: H1 — _build/ path protection
    "_build",
    # v16: C-1/H-7 — supply chain paths (NOTE: ".git" excluded — substring of .github/.gitignore)
    "mix.exs",
    ".iex.exs",
    "config",
    "priv",
    ".github",
    "Dockerfile",
    "Makefile",
    "deps",
    ".tool-versions",
    "rel/"
  ]

  # KRAIT-007: KRAIT internals tampering — forbidden module prefixes
  @krait_007_forbidden_prefixes [
    [:Krait, :Evolution],
    [:Krait, :Analyzer],
    [:Krait, :Sandbox],
    [:Krait, :Brain],
    [:Krait, :Gateway],
    [:Krait, :Memory],
    # v10: H8 expanded prefixes
    [:Krait, :LLM],
    [:Krait, :Skills, :Registry],
    [:Krait, :Repo],
    [:KraitWeb],
    [:Krait, :GitHub]
  ]

  # ---------------------------------------------------------------------------
  # Complexity heuristic — regex patterns for branching constructs
  # ---------------------------------------------------------------------------

  @complexity_patterns [
    ~r/\bif\b/,
    ~r/\bcase\b/,
    ~r/\bcond\b/,
    ~r/\bwith\b/,
    ~r/\btry\b/,
    ~r/\brescue\b/,
    ~r/\bcatch\b/,
    ~r/\bfn\b/,
    ~r/\breceive\b/,
    ~r/\bfor\b/,
    ~r/\bunless\b/,
    ~r/\s->\s/
  ]

  # ---------------------------------------------------------------------------
  # Public API
  # ---------------------------------------------------------------------------

  # v26 M-7: Limit code size to prevent atom table exhaustion via Code.string_to_quoted
  @max_code_size 1_048_576

  @impl true
  @spec quick_validate(String.t(), String.t()) ::
          Krait.Analyzer.QuickBehaviour.validation_result()
  def quick_validate(code, "elixir") when is_binary(code) and byte_size(code) > @max_code_size do
    {:error, %{reason: :code_too_large, size: byte_size(code), max: @max_code_size}}
  end

  def quick_validate(code, "elixir") when is_binary(code) do
    case Code.string_to_quoted(code) do
      {:ok, ast} ->
        case check_forbidden_ast(ast) do
          :ok ->
            {:ok, %{complexity: compute_complexity(code), hash: compute_hash(code)}}

          violation ->
            violation
        end

      {:error, {meta, message, token}} ->
        line = extract_line(meta)
        msg = format_syntax_error(message, token)
        {:syntax_error, [%{line: line, message: msg}]}
    end
  end

  def quick_validate(code, language) when is_binary(code) and is_binary(language) do
    Logger.debug("Quick validate (non-Elixir)", language: language, code_size: byte_size(code))

    with :ok <- check_forbidden_patterns_string(code) do
      {:ok, %{complexity: compute_complexity(code), hash: compute_hash(code)}}
    end
  end

  # ---------------------------------------------------------------------------
  # Syntax error formatting
  # ---------------------------------------------------------------------------

  defp extract_line(meta) when is_list(meta), do: Keyword.get(meta, :line, 0)

  defp format_syntax_error(message, token) when is_binary(message) and is_binary(token) do
    message <> token
  end

  defp format_syntax_error({msg1, msg2}, token) when is_binary(msg1) and is_binary(msg2) do
    msg1 <> msg2 <> token
  end

  defp format_syntax_error(message, token) do
    "#{inspect(message)}#{inspect(token)}"
  end

  # ---------------------------------------------------------------------------
  # Allowlist-based validation (Elixir only)
  # ---------------------------------------------------------------------------

  @doc false
  @spec check_allowlist(Macro.t(), map() | nil) :: :ok | {:policy_violation, map()}
  def check_allowlist(ast, module_attrs \\ nil) do
    attrs = module_attrs || collect_module_attr_atoms(ast)
    refs = extract_all_module_refs(ast, attrs)

    case check_refs_against_allowlist(refs) do
      :ok ->
        case check_banned_macros(ast) do
          :ok ->
            case check_derive_protocols(ast) do
              :ok -> check_variable_module_binding(ast)
              violation -> violation
            end

          violation ->
            violation
        end

      violation ->
        violation
    end
  end

  # Extract ALL module references from AST as tagged tuples
  # IMPORTANT: Pattern ordering matters — more specific patterns (Kernel.apply,
  # Function.capture, @attr.func) must come BEFORE the generic Module.func pattern,
  # since Macro.prewalk uses first-match and {nil, acc} stops child traversal.
  defp extract_all_module_refs(ast, module_attrs) do
    {_, refs} =
      Macro.prewalk(ast, [], fn
        # Skip doc/moduledoc attributes (string content, not code)
        {:@, _, [{doc_attr, _, _}]}, acc when doc_attr in [:moduledoc, :doc] ->
          {nil, acc}

        # --- Specific patterns BEFORE generic Module.func ---

        # Kernel.apply(Module, :func, args) — must precede generic qualified call
        {{:., _, [{:__aliases__, _, kernel_aliases}, :apply]}, _,
         [{:__aliases__, _, mod_aliases}, _fun | _rest]},
        acc ->
          if aliases_match?(kernel_aliases, [:Kernel]) do
            mod = resolve_elixir_module(mod_aliases)
            {nil, [{:apply_elixir, mod} | acc]}
          else
            # Not Kernel — treat as generic qualified call
            mod = resolve_elixir_module(kernel_aliases)
            {nil, [{:elixir_module, mod} | acc]}
          end

        # Kernel.apply(:erlang_mod, :func, args) — must precede generic qualified call
        {{:., _, [{:__aliases__, _, kernel_aliases}, :apply]}, _, [mod, _fun | _rest]}, acc
        when is_atom(mod) and not is_boolean(mod) and not is_nil(mod) ->
          if aliases_match?(kernel_aliases, [:Kernel]) do
            {nil, [{:apply_erlang, mod} | acc]}
          else
            caller = resolve_elixir_module(kernel_aliases)
            {nil, [{:elixir_module, caller} | acc]}
          end

        # Function.capture(Module, :func, arity) — must precede generic qualified call
        {{:., _, [{:__aliases__, _, func_aliases}, :capture]}, _,
         [{:__aliases__, _, mod_aliases} | _rest]},
        acc ->
          if aliases_match?(func_aliases, [:Function]) do
            mod = resolve_elixir_module(mod_aliases)
            {nil, [{:capture_elixir, mod} | acc]}
          else
            caller = resolve_elixir_module(func_aliases)
            {nil, [{:elixir_module, caller} | acc]}
          end

        # Function.capture(:erlang_mod, :func, arity) — must precede generic qualified call
        {{:., _, [{:__aliases__, _, func_aliases}, :capture]}, _, [mod | _rest]}, acc
        when is_atom(mod) and not is_boolean(mod) and not is_nil(mod) ->
          if aliases_match?(func_aliases, [:Function]) do
            {nil, [{:capture_erlang, mod} | acc]}
          else
            caller = resolve_elixir_module(func_aliases)
            {nil, [{:elixir_module, caller} | acc]}
          end

        # @attr.func() calls — must precede generic Erlang dot call
        {{:., _, [{:@, _, [{attr_name, _, nil}]}, _func]}, _, _args}, acc
        when is_atom(attr_name) ->
          resolved = Map.get(module_attrs, attr_name)

          if resolved do
            {nil, [{:attr_call, resolved} | acc]}
          else
            {nil, acc}
          end

        # --- Generic qualified calls ---

        # Qualified Elixir call: Module.func(args) — multi-segment alias
        {{:., _, [{:__aliases__, _, aliases}, fun]}, _, _args}, acc
        when is_list(aliases) and is_atom(fun) ->
          mod = resolve_elixir_module(aliases)

          if Allowlist.denied_function_on_allowed_module?(mod, fun) do
            {nil, [{:denied_function_on_allowed, mod, fun} | acc]}
          else
            if Allowlist.allowed_module?(mod) and Allowlist.denied_kernel_function?(fun) and
                 mod == Kernel do
              {nil, [{:kernel_qualified_denied, fun} | acc]}
            else
              {nil, [{:elixir_module, mod} | acc]}
            end
          end

        # Qualified Erlang call: :module.func(args)
        {{:., _, [mod, _fun]}, _, _args}, acc
        when is_atom(mod) and not is_boolean(mod) and not is_nil(mod) ->
          {nil, [{:erlang_module, mod} | acc]}

        # --- Directives ---

        # import/alias/use/require directives
        # v25 H-4: Also extract module refs from use options
        {directive, _, [{:__aliases__, _, aliases} | rest]}, acc
        when directive in [:import, :alias, :use, :require] ->
          mod = resolve_elixir_module(aliases)
          option_refs = if directive == :use, do: extract_use_option_modules(rest), else: []
          {nil, option_refs ++ [{:directive, directive, mod} | acc]}

        # --- Delegation ---

        # defdelegate to: Module
        {:defdelegate, _, [_func, opts]}, acc when is_list(opts) ->
          case Keyword.get(opts, :to) do
            {:__aliases__, _, aliases} when is_list(aliases) ->
              mod = resolve_elixir_module(aliases)
              {nil, [{:defdelegate, mod} | acc]}

            target when is_atom(target) and not is_boolean(target) and not is_nil(target) ->
              {nil, [{:defdelegate_erlang, target} | acc]}

            # defdelegate to: @attr
            {:@, _, [{attr_name, _, _}]} when is_atom(attr_name) ->
              resolved = Map.get(module_attrs, attr_name)

              if resolved do
                {nil, [{:defdelegate_attr, resolved} | acc]}
              else
                {nil, acc}
              end

            _ ->
              {nil, acc}
          end

        # --- Apply patterns ---

        # apply(Module, :func, args)
        {:apply, _, [{:__aliases__, _, aliases}, _fun | _rest]}, acc
        when is_list(aliases) ->
          mod = resolve_elixir_module(aliases)
          {nil, [{:apply_elixir, mod} | acc]}

        # apply(:erlang_mod, :func, args)
        {:apply, _, [mod, _fun | _rest]}, acc
        when is_atom(mod) and not is_boolean(mod) and not is_nil(mod) ->
          {nil, [{:apply_erlang, mod} | acc]}

        # apply(@attr, :func, args)
        {:apply, _, [{:@, _, [{attr_name, _, _}]}, _fun | _rest]}, acc
        when is_atom(attr_name) ->
          resolved = Map.get(module_attrs, attr_name)

          if resolved do
            {nil, [{:apply_attr, resolved} | acc]}
          else
            {nil, acc}
          end

        # --- Capture patterns ---

        # &Module.func/arity capture shorthand
        {:&, _, [{:/, _, [{{:., _, [{:__aliases__, _, aliases}, _fun]}, _, _}, _arity]}]}, acc ->
          mod = resolve_elixir_module(aliases)
          {nil, [{:capture_shorthand, mod} | acc]}

        # --- Bare Kernel function calls ---

        # spawn/1, send/2, self/0, etc.
        {fun_name, _meta, args}, acc
        when is_atom(fun_name) and is_list(args) and
               fun_name in [
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
                 # v17: H-6 expanded
                 :binding,
                 :var!,
                 :macro_exported?,
                 :function_exported?,
                 :dbg,
                 :struct,
                 :struct!,
                 :tap
               ] ->
          {nil, [{:kernel_function, fun_name} | acc]}

        node, acc ->
          {node, acc}
      end)

    refs
  end

  # Convert alias segments to a module atom
  # v25 H-4: Extract module references from `use` options (keyword list values)
  # Only flags explicit Elixir module forms ({:__aliases__, _, _}) — bare atoms
  # like :transient, :permanent are config values, not module references.
  defp extract_use_option_modules([]), do: []

  defp extract_use_option_modules([opts]) when is_list(opts) do
    Enum.flat_map(opts, fn
      {_key, {:__aliases__, _, aliases}} ->
        [{:use_option_module, resolve_elixir_module(aliases)}]

      _ ->
        []
    end)
  end

  defp extract_use_option_modules(_), do: []

  defp resolve_elixir_module(aliases) do
    # Handle Elixir.Module form
    clean =
      case aliases do
        [:"Elixir" | rest] -> rest
        other -> other
      end

    Module.concat(clean)
  end

  # Check all extracted refs against the allowlist
  defp check_refs_against_allowlist(refs) do
    Enum.reduce_while(refs, :ok, fn ref, :ok ->
      case check_single_ref(ref) do
        :ok -> {:cont, :ok}
        violation -> {:halt, violation}
      end
    end)
  end

  defp check_single_ref({:elixir_module, mod}) do
    if Allowlist.allowed_module?(mod) do
      :ok
    else
      violation("KRAIT-ALW", "Module #{inspect(mod)} is not on the allowlist")
    end
  end

  defp check_single_ref({:erlang_module, mod}) do
    # Erlang modules are atoms like :os, :file, :math
    # Elixir modules via atom form (:"Elixir.System") are also atoms
    cond do
      Allowlist.allowed_erlang_module?(mod) ->
        :ok

      # Check if it's an Elixir module in atom form (:"Elixir.Module")
      is_elixir_module_atom?(mod) ->
        if Allowlist.allowed_module?(mod) do
          :ok
        else
          violation("KRAIT-ALW", "Module #{inspect(mod)} is not on the allowlist")
        end

      true ->
        violation("KRAIT-ALW", "Erlang module #{inspect(mod)} is not on the allowlist")
    end
  end

  defp check_single_ref({:directive, directive, mod}) do
    if Allowlist.allowed_module?(mod) do
      :ok
    else
      violation(
        "KRAIT-ALW",
        "#{directive} of non-allowlisted module #{inspect(mod)}"
      )
    end
  end

  # v25 H-4: Module references passed as use options must also be allowlisted
  defp check_single_ref({:use_option_module, mod}) when is_atom(mod) do
    cond do
      Allowlist.allowed_module?(mod) ->
        :ok

      Allowlist.allowed_erlang_module?(mod) ->
        :ok

      true ->
        violation("KRAIT-ALW", "use option references non-allowlisted module #{inspect(mod)}")
    end
  end

  defp check_single_ref({:defdelegate, mod}) do
    if Allowlist.allowed_module?(mod) do
      :ok
    else
      violation("KRAIT-ALW", "defdelegate to non-allowlisted module #{inspect(mod)}")
    end
  end

  defp check_single_ref({:defdelegate_erlang, mod}) do
    if Allowlist.allowed_erlang_module?(mod) do
      :ok
    else
      violation("KRAIT-ALW", "defdelegate to non-allowlisted Erlang module #{inspect(mod)}")
    end
  end

  defp check_single_ref({:defdelegate_attr, resolved}) do
    check_resolved_attr(resolved, "defdelegate to @attr resolving to")
  end

  defp check_single_ref({:apply_elixir, mod}) do
    if Allowlist.allowed_module?(mod) do
      :ok
    else
      violation("KRAIT-ALW", "apply with non-allowlisted module #{inspect(mod)}")
    end
  end

  defp check_single_ref({:apply_erlang, mod}) do
    if Allowlist.allowed_erlang_module?(mod) do
      :ok
    else
      violation("KRAIT-ALW", "apply with non-allowlisted Erlang module #{inspect(mod)}")
    end
  end

  defp check_single_ref({:apply_attr, resolved}) do
    check_resolved_attr(resolved, "apply with @attr resolving to")
  end

  defp check_single_ref({:attr_call, resolved}) do
    check_resolved_attr(resolved, "@attr.func() call resolving to")
  end

  defp check_single_ref({:capture_elixir, mod}) do
    if Allowlist.allowed_module?(mod) do
      :ok
    else
      violation("KRAIT-ALW", "Function.capture of non-allowlisted module #{inspect(mod)}")
    end
  end

  defp check_single_ref({:capture_erlang, mod}) do
    if Allowlist.allowed_erlang_module?(mod) do
      :ok
    else
      violation(
        "KRAIT-ALW",
        "Function.capture of non-allowlisted Erlang module #{inspect(mod)}"
      )
    end
  end

  defp check_single_ref({:capture_shorthand, mod}) do
    if Allowlist.allowed_module?(mod) do
      :ok
    else
      violation("KRAIT-ALW", "Capture of non-allowlisted module #{inspect(mod)}")
    end
  end

  defp check_single_ref({:kernel_function, fun_name}) do
    if Allowlist.denied_kernel_function?(fun_name) do
      violation("KRAIT-ALW", "Kernel function #{fun_name} is not allowed in generated code")
    else
      :ok
    end
  end

  defp check_single_ref({:kernel_qualified_denied, fun_name}) do
    violation(
      "KRAIT-ALW",
      "Kernel.#{fun_name} is not allowed in generated code"
    )
  end

  defp check_single_ref({:denied_function_on_allowed, mod, fun}) do
    violation(
      "KRAIT-ALW",
      "#{inspect(mod)}.#{fun} is not allowed in generated code"
    )
  end

  defp check_single_ref({:variable_module_call, mod}) do
    violation(
      "KRAIT-ALW",
      "Variable-based dispatch with non-allowlisted module #{inspect(mod)}"
    )
  end

  # Helper: check resolved module attribute against both Elixir and Erlang allowlists
  defp check_resolved_attr(resolved, context_msg) do
    cond do
      is_elixir_module_atom?(resolved) and Allowlist.allowed_module?(resolved) ->
        :ok

      Allowlist.allowed_erlang_module?(resolved) ->
        :ok

      true ->
        violation("KRAIT-ALW", "#{context_msg} non-allowlisted module #{inspect(resolved)}")
    end
  end

  # Check if an atom represents an Elixir module (starts with "Elixir.")
  defp is_elixir_module_atom?(atom) when is_atom(atom) do
    String.starts_with?(Atom.to_string(atom), "Elixir.")
  end

  # Check for banned macros, compile hooks, receive, quote, defprotocol, defimpl, defoverridable
  defp check_banned_macros(ast) do
    {_, result} =
      Macro.prewalk(ast, :ok, fn
        {:defmacro, _, _}, :ok ->
          {nil, violation("KRAIT-ALW", "defmacro is not allowed in generated code")}

        {:defmacrop, _, _}, :ok ->
          {nil, violation("KRAIT-ALW", "defmacrop is not allowed in generated code")}

        # M-3: defprotocol/defimpl denied
        {:defprotocol, _, _}, :ok ->
          {nil, violation("KRAIT-ALW", "defprotocol is not allowed in generated code")}

        {:defimpl, _, _}, :ok ->
          {nil, violation("KRAIT-ALW", "defimpl is not allowed in generated code")}

        # M-4: defoverridable denied
        {:defoverridable, _, _}, :ok ->
          {nil, violation("KRAIT-ALW", "defoverridable is not allowed in generated code")}

        # C-2: Compile hook attributes
        {:@, _, [{attr_name, _, _}]}, :ok
        when attr_name in [:before_compile, :after_compile, :on_load, :on_definition] ->
          {nil,
           violation("KRAIT-ALW", "@#{attr_name} compile hook is not allowed in generated code")}

        # C-3: receive blocks
        {:receive, _, _}, :ok ->
          {nil, violation("KRAIT-ALW", "receive is not allowed in generated code")}

        # C-4: quote blocks
        {:quote, _, _}, :ok ->
          {nil, violation("KRAIT-ALW", "quote is not allowed in generated code")}

        node, acc ->
          {node, acc}
      end)

    result
  end

  # Phase 7 v18: @derive protocol checking
  # Only allowlisted protocols (Inspect, Collectable, etc.) may be derived
  defp check_derive_protocols(ast) do
    {_, result} =
      Macro.prewalk(ast, :ok, fn
        {:@, _, [{:derive, _, [protocols]}]}, :ok when is_list(protocols) ->
          case check_protocol_list(protocols) do
            :ok -> {nil, :ok}
            violation -> {nil, violation}
          end

        {:@, _, [{:derive, _, [{:__aliases__, _, _aliases} = protocol]}]}, :ok ->
          check_single_protocol(protocol)

        # v25 H-4: @derive {Module, opts} single-tuple form
        {:@, _, [{:derive, _, [{{:__aliases__, _, aliases}, _opts}]}]}, :ok ->
          mod = resolve_elixir_module(aliases)

          if Allowlist.allowed_derive_protocol?(mod) do
            {nil, :ok}
          else
            {nil, violation("KRAIT-ALW", "@derive with non-allowlisted protocol #{mod}")}
          end

        {:@, _, [{:derive, _, [protocol]}]}, :ok when is_atom(protocol) ->
          if Allowlist.allowed_derive_protocol?(protocol) do
            {nil, :ok}
          else
            {nil,
             violation("KRAIT-ALW", "@derive with non-allowlisted protocol #{inspect(protocol)}")}
          end

        node, acc ->
          {node, acc}
      end)

    result
  end

  defp check_protocol_list(protocols) do
    Enum.reduce_while(protocols, :ok, fn
      {:__aliases__, _, aliases}, :ok ->
        mod = resolve_elixir_module(aliases)

        if Allowlist.allowed_derive_protocol?(mod) do
          {:cont, :ok}
        else
          {:halt, violation("KRAIT-ALW", "@derive with non-allowlisted protocol #{mod}")}
        end

      {mod, _opts}, :ok when is_atom(mod) ->
        if Allowlist.allowed_derive_protocol?(mod) do
          {:cont, :ok}
        else
          {:halt, violation("KRAIT-ALW", "@derive with non-allowlisted protocol #{inspect(mod)}")}
        end

      {{:__aliases__, _, aliases}, _opts}, :ok ->
        mod = resolve_elixir_module(aliases)

        if Allowlist.allowed_derive_protocol?(mod) do
          {:cont, :ok}
        else
          {:halt, violation("KRAIT-ALW", "@derive with non-allowlisted protocol #{mod}")}
        end

      # v25 H-4: Fail-closed — reject unknown @derive formats
      other, :ok ->
        {:halt,
         violation("KRAIT-ALW", "@derive with unrecognized format: #{inspect(other, limit: 50)}")}
    end)
  end

  defp check_single_protocol({:__aliases__, _, aliases}) do
    mod = resolve_elixir_module(aliases)

    if Allowlist.allowed_derive_protocol?(mod) do
      {nil, :ok}
    else
      {nil, violation("KRAIT-ALW", "@derive with non-allowlisted protocol #{mod}")}
    end
  end

  # C-7: Variable-based dynamic dispatch detection
  # Detects: m = System; m.cmd("ls", []) — variable bound to non-allowlisted module then called
  defp check_variable_module_binding(ast) do
    # Phase 1: Collect all variable → module bindings
    {_, bindings} =
      Macro.prewalk(ast, %{}, fn
        # var = Module (Elixir)
        {:=, _, [{var_name, _, nil}, {:__aliases__, _, aliases}]}, acc
        when is_atom(var_name) ->
          mod = resolve_elixir_module(aliases)
          {nil, Map.put(acc, var_name, {:elixir, mod})}

        # var = :erlang_mod
        {:=, _, [{var_name, _, nil}, mod]}, acc
        when is_atom(var_name) and is_atom(mod) and not is_boolean(mod) and not is_nil(mod) ->
          {nil, Map.put(acc, var_name, {:erlang, mod})}

        # v20 H-1 Fix 2: Tuple destructuring — {v1, v2} = {Mod1, Mod2}
        {:=, _, [{:{}, _, lhs_elements}, {:{}, _, rhs_elements}]}, acc ->
          {nil, collect_tuple_bindings(lhs_elements, rhs_elements, acc)}

        # 2-tuple shorthand: {v1, v2} = {Mod, val}
        {:=, _, [{lhs1, lhs2}, {rhs1, rhs2}]}, acc ->
          {nil, collect_tuple_bindings([lhs1, lhs2], [rhs1, rhs2], acc)}

        # v20 H-1 Fix 2: List destructuring — [var] = [Module]
        {:=, _, [lhs_list, rhs_list]}, acc
        when is_list(lhs_list) and is_list(rhs_list) ->
          {nil, collect_list_bindings(lhs_list, rhs_list, acc)}

        # v25 L-2: Variable reassignment chains — b = a where a is already tracked
        {:=, _, [{var_name, _, nil}, {other_var, _, nil}]}, acc
        when is_atom(var_name) and is_atom(other_var) ->
          case Map.get(acc, other_var) do
            nil -> {nil, acc}
            binding -> {nil, Map.put(acc, var_name, binding)}
          end

        node, acc ->
          {node, acc}
      end)

    if map_size(bindings) == 0 do
      # Even with no tracked bindings, check for apply with non-literal targets
      check_apply_with_nonliteral_target(ast)
    else
      # Phase 2: Check if any bound variable is used in a dot call or apply(var, ...)
      {_, violation_result} =
        Macro.prewalk(ast, :ok, fn
          # var.func() — dot call with bound variable
          {{:., _, [{var_name, _, nil}, _fun]}, _, _args}, :ok when is_atom(var_name) ->
            check_var_binding(bindings, var_name)

          # v20 H-1 Fix 1: apply(var, :func, args) — variable as first arg to apply
          {:apply, _, [{var_name, _, nil}, _fun | _rest]}, :ok when is_atom(var_name) ->
            check_var_binding(bindings, var_name)

          node, acc ->
            {node, acc}
        end)

      case violation_result do
        :ok -> check_apply_with_nonliteral_target(ast)
        violation -> violation
      end
    end
  end

  # v20 H-1: Check a variable name against the bindings map
  defp check_var_binding(bindings, var_name) do
    case Map.get(bindings, var_name) do
      {:elixir, mod} ->
        if Allowlist.allowed_module?(mod) do
          {nil, :ok}
        else
          {nil,
           violation(
             "KRAIT-ALW",
             "Variable-based dispatch with non-allowlisted module #{inspect(mod)}"
           )}
        end

      {:erlang, mod} ->
        if Allowlist.allowed_erlang_module?(mod) do
          {nil, :ok}
        else
          {nil,
           violation(
             "KRAIT-ALW",
             "Variable-based dispatch with non-allowlisted Erlang module #{inspect(mod)}"
           )}
        end

      nil ->
        {nil, :ok}
    end
  end

  # v20 H-1 Fix 2: Collect bindings from tuple destructuring
  defp collect_tuple_bindings(lhs_elements, rhs_elements, acc) do
    lhs_elements
    |> Enum.zip(rhs_elements)
    |> Enum.reduce(acc, fn
      {{var_name, _, nil}, {:__aliases__, _, aliases}}, acc when is_atom(var_name) ->
        mod = resolve_elixir_module(aliases)
        Map.put(acc, var_name, {:elixir, mod})

      {{var_name, _, nil}, mod}, acc
      when is_atom(var_name) and is_atom(mod) and not is_boolean(mod) and not is_nil(mod) ->
        Map.put(acc, var_name, {:erlang, mod})

      _, acc ->
        acc
    end)
  end

  # v20 H-1 Fix 2: Collect bindings from list destructuring
  defp collect_list_bindings(lhs_list, rhs_list, acc) do
    lhs_list
    |> Enum.zip(rhs_list)
    |> Enum.reduce(acc, fn
      {{var_name, _, nil}, {:__aliases__, _, aliases}}, acc when is_atom(var_name) ->
        mod = resolve_elixir_module(aliases)
        Map.put(acc, var_name, {:elixir, mod})

      {{var_name, _, nil}, mod}, acc
      when is_atom(var_name) and is_atom(mod) and not is_boolean(mod) and not is_nil(mod) ->
        Map.put(acc, var_name, {:erlang, mod})

      _, acc ->
        acc
    end)
  end

  # v20 H-1 Fix 3: Catch-all — flag apply/Kernel.apply where first arg is not a literal module
  # This catches: apply(var, ...), apply(func_result, ...), apply(config.mod, ...), etc.
  defp check_apply_with_nonliteral_target(ast) do
    {_, result} =
      Macro.prewalk(ast, :ok, fn
        # apply(non_literal, :func, args) — first arg is not alias or atom literal
        {:apply, _, [first_arg, _fun | _rest]}, :ok ->
          if literal_module_target?(first_arg) do
            {nil, :ok}
          else
            {nil,
             violation(
               "KRAIT-ALW",
               "apply with non-literal module target is not allowed in generated code"
             )}
          end

        # Kernel.apply(non_literal, :func, args)
        {{:., _, [{:__aliases__, _, [:Kernel]}, :apply]}, _, [first_arg, _fun | _rest]}, :ok ->
          if literal_module_target?(first_arg) do
            {nil, :ok}
          else
            {nil,
             violation(
               "KRAIT-ALW",
               "Kernel.apply with non-literal module target is not allowed in generated code"
             )}
          end

        node, acc ->
          {node, acc}
      end)

    result
  end

  # Check if an AST node is a literal module target (alias or atom)
  defp literal_module_target?({:__aliases__, _, _}), do: true

  defp literal_module_target?(atom)
       when is_atom(atom) and not is_boolean(atom) and not is_nil(atom),
       do: true

  defp literal_module_target?(_), do: false

  # ---------------------------------------------------------------------------
  # AST-based forbidden pattern scanning (Elixir only)
  # ---------------------------------------------------------------------------

  # Primary mode: allowlist authoritative for module checks, KRAIT-003/006/007 retained
  defp check_forbidden_ast(ast) do
    module_attrs = collect_module_attr_atoms(ast)
    allowlist_result = check_allowlist(ast, module_attrs)

    case allowlist_result do
      {:policy_violation, _} ->
        allowlist_result

      :ok ->
        # Only run path-based and self-modification checks (orthogonal to module allowlist)
        with :ok <- check_ast_krait_003(ast),
             :ok <- check_ast_krait_006(ast) do
          check_ast_krait_007(ast)
        end
    end
  end

  # KRAIT-003: Credential path access (compound: file op call + credential path string literal)
  defp check_ast_krait_003(ast) do
    # v13: Phase 8 — @external_resource with credential path (no file op needed)
    if ast_has_external_resource_cred?(ast) do
      violation("KRAIT-003", "Credential path access detected (@external_resource)")
    else
      has_file_op =
        ast_has_any_call?(ast, @krait_003_file_op_calls) or
          ast_has_any_erlang_call?(ast, @krait_003_erlang_file_ops)

      string_literals = ast_collect_string_literals(ast)
      has_credential = Enum.any?(string_literals, &credential_path?/1)

      if has_file_op and has_credential do
        violation("KRAIT-003", "Credential path access detected")
      else
        :ok
      end
    end
  end

  # KRAIT-006: Immutable path targeting — check string literals + concat evasion
  defp check_ast_krait_006(ast) do
    string_literals = ast_collect_string_literals(ast)

    cond do
      # v13: M1 — case-insensitive primary match
      Enum.any?(string_literals, fn s ->
        lower = String.downcase(s)
        Enum.any?(@krait_006_patterns, fn p -> String.contains?(lower, String.downcase(p)) end)
      end) ->
        violation("KRAIT-006", "Immutable path targeting detected")

      ast_has_concat_evasion?(ast) ->
        violation("KRAIT-006", "Immutable path targeting detected (string concatenation evasion)")

      ast_has_path_join_evasion?(ast) ->
        violation("KRAIT-006", "Immutable path targeting detected (Path.join evasion)")

      ast_has_enum_join_evasion?(ast) ->
        violation("KRAIT-006", "Immutable path targeting detected (Enum.join evasion)")

      ast_has_iodata_evasion?(ast) ->
        violation("KRAIT-006", "Immutable path targeting detected (iodata evasion)")

      ast_has_runtime_string_construction?(ast) ->
        violation(
          "KRAIT-006",
          "Immutable path targeting detected (runtime string construction evasion)"
        )

      ast_has_suspicious_integer_sequence?(ast, @krait_006_forbidden_segments) ->
        violation(
          "KRAIT-006",
          "Immutable path targeting detected (integer sequence evasion)"
        )

      # v12: Phase 3 — :filename.join, :filelib.is_file, :string.concat
      ast_has_erlang_path_op_evasion?(ast) ->
        violation(
          "KRAIT-006",
          "Immutable path targeting detected (erlang path operation evasion)"
        )

      # v12: Phase 6 — String.replace / Regex.replace evasion
      ast_has_replace_evasion?(ast) ->
        violation(
          "KRAIT-006",
          "Immutable path targeting detected (string replacement evasion)"
        )

      # v12: Phase 8 — case-insensitive evasion
      ast_has_case_evasion?(ast) ->
        violation(
          "KRAIT-006",
          "Immutable path targeting detected (case-insensitive evasion)"
        )

      # v13: Phase 8 — @external_resource with immutable path
      ast_has_external_resource_immutable?(ast) ->
        violation(
          "KRAIT-006",
          "Immutable path targeting detected (@external_resource)"
        )

      # v13: Phase 9 — advanced path evasion (Atom.to_string, String.reverse, etc.)
      ast_has_advanced_path_evasion?(ast) ->
        violation(
          "KRAIT-006",
          "Immutable path targeting detected (advanced path evasion)"
        )

      # v14: H-3 — fragment combination evasion (split literals with <>)
      ast_has_fragment_combination_evasion?(ast) ->
        violation(
          "KRAIT-006",
          "Immutable path targeting detected (fragment combination evasion)"
        )

      # v15: Phase 6 M-2 — string interpolation with partial immutable segments
      ast_has_interpolation_evasion?(ast) ->
        violation(
          "KRAIT-006",
          "Immutable path targeting detected (interpolation evasion)"
        )

      true ->
        :ok
    end
  end

  # KRAIT-007: KRAIT internals tampering — check module alias references
  defp check_ast_krait_007(ast) do
    if ast_has_forbidden_module_prefix?(ast) do
      violation("KRAIT-007", "KRAIT internals tampering detected")
    else
      :ok
    end
  end

  # ---------------------------------------------------------------------------
  # AST walking helpers
  # ---------------------------------------------------------------------------

  # Check if AST contains a direct call like Module.function(...)
  # Also matches Elixir.Module.function(...) — the [:Elixir, :Module] alias form
  defp ast_has_call?(ast, module_atoms, function_atom) do
    {_, found} =
      Macro.prewalk(ast, false, fn
        # Direct call: Module.function(...) or Elixir.Module.function(...)
        {{:., _, [{:__aliases__, _, aliases}, fun]}, _, _args}, acc ->
          if fun == function_atom and aliases_match?(aliases, module_atoms) do
            {nil, true}
          else
            {nil, acc}
          end

        node, acc ->
          {node, acc}
      end)

    found
  end

  # Match both [:System] and [:Elixir, :System] forms against target [:System]
  defp aliases_match?(aliases, target), do: aliases == target or aliases == [:"Elixir" | target]

  defp ast_has_any_call?(ast, call_list) do
    Enum.any?(call_list, fn {mod, fun} -> ast_has_call?(ast, mod, fun) end)
  end

  # Check for erlang-style calls like :os.cmd(...)
  # v12: Phase 9 — zero-width Unicode stripping for atom comparison
  defp ast_has_erlang_call?(ast, module_atom, function_atom) do
    {_, found} =
      Macro.prewalk(ast, false, fn
        {{:., _, [mod, fun]}, _, _args}, acc
        when is_atom(mod) and is_atom(fun) ->
          cleaned_mod =
            mod
            |> Atom.to_string()
            |> strip_zero_width()
            |> then(fn s ->
              try do
                String.to_existing_atom(s)
              rescue
                ArgumentError -> mod
              end
            end)

          if (mod == module_atom or cleaned_mod == module_atom) and fun == function_atom do
            {nil, true}
          else
            {nil, acc}
          end

        node, acc ->
          {node, acc}
      end)

    found
  end

  defp ast_has_any_erlang_call?(ast, call_list) do
    Enum.any?(call_list, fn {mod, fun} -> ast_has_erlang_call?(ast, mod, fun) end)
  end

  # Collect module attribute atom assignments from AST: @target :os -> %{target: :os}
  # Used for indirection detection (Phase 4: H1)
  defp collect_module_attr_atoms(ast) do
    {_, attrs} =
      Macro.prewalk(ast, %{}, fn
        {:@, _, [{name, _, [value]}]}, acc
        when is_atom(name) and is_atom(value) and not is_boolean(value) and not is_nil(value) ->
          {nil, Map.put(acc, name, value)}

        # Also collect @attr Module alias form (single segment)
        {:@, _, [{name, _, [{:__aliases__, _, [mod_atom]}]}]}, acc
        when is_atom(name) and is_atom(mod_atom) ->
          {nil, Map.put(acc, name, mod_atom)}

        # v26 M-8: Multi-segment module aliases — @target Some.Deep.Module
        {:@, _, [{name, _, [{:__aliases__, _, aliases}]}]}, acc
        when is_atom(name) and is_list(aliases) and length(aliases) > 1 ->
          if Enum.all?(aliases, &is_atom/1) do
            {nil, Map.put(acc, name, Module.concat(aliases))}
          else
            {nil, acc}
          end

        # v25 L-3: Module attribute alias chains — @b @a (2-deep)
        # Propagates: if @a = :os and we see @b = @a, then @b = :os
        {:@, _, [{name, _, [{:@, _, [{other_name, _, _}]}]}]}, acc
        when is_atom(name) and is_atom(other_name) ->
          case Map.get(acc, other_name) do
            nil -> {nil, acc}
            value -> {nil, Map.put(acc, name, value)}
          end

        node, acc ->
          {node, acc}
      end)

    # v26 M-8: Resolve transitive chains (N-depth, max 10 iterations)
    resolve_attr_chains(attrs)
  end

  # Resolve transitive module attribute chains: @a = :os, @b = @a, @c = @b -> @c = :os
  defp resolve_attr_chains(attrs, max_iterations \\ 10)
  defp resolve_attr_chains(attrs, 0), do: attrs

  defp resolve_attr_chains(attrs, remaining) do
    updated =
      Enum.reduce(attrs, attrs, fn {name, value}, acc ->
        case Map.get(attrs, value) do
          nil -> acc
          resolved when is_atom(resolved) -> Map.put(acc, name, resolved)
          _ -> acc
        end
      end)

    if updated == attrs, do: attrs, else: resolve_attr_chains(updated, remaining - 1)
  end

  # Collect all string literals from AST (excludes comments, doc attributes are still strings)
  # We extract from function bodies only, skipping @moduledoc/@doc attributes
  defp ast_collect_string_literals(ast) do
    {_, strings} =
      Macro.prewalk(ast, [], fn
        # Skip @moduledoc, @doc — their string contents are documentation, not code
        {:@, _, [{doc_attr, _, _}]} = _node, acc when doc_attr in [:moduledoc, :doc] ->
          {nil, acc}

        # Binary strings (regular string literals)
        str, acc when is_binary(str) ->
          {str, [str | acc]}

        # v13: H2 — Charlist detection: list of small integers → decode to string
        list, acc when is_list(list) and length(list) > 0 ->
          if Enum.all?(list, fn el -> is_integer(el) and el >= 0 and el <= 0x10FFFF end) do
            try do
              decoded = List.to_string(list)
              {list, [decoded | acc]}
            rescue
              _ -> {list, acc}
            end
          else
            {list, acc}
          end

        node, acc ->
          {node, acc}
      end)

    strings
  end

  defp credential_path?(str) do
    Enum.any?(@krait_003_credential_paths, &String.contains?(str, &1)) or
      Enum.any?(@krait_003_credential_segments, &String.contains?(str, &1))
  end

  # Check if AST references any forbidden KRAIT module prefix
  defp ast_has_forbidden_module_prefix?(ast) do
    {_, found} =
      Macro.prewalk(ast, false, fn
        # Skip @moduledoc/@doc — doc strings may mention module names
        {:@, _, [{doc_attr, _, _}]} = _node, acc when doc_attr in [:moduledoc, :doc] ->
          {nil, acc}

        {:__aliases__, _, aliases}, acc ->
          if forbidden_prefix?(aliases) do
            {nil, true}
          else
            {nil, acc}
          end

        # v10: C5 — bare atom matching Krait module names (from :"Elixir.Krait.X.Y")
        # When Code.string_to_quoted parses :"Elixir.Krait.Evolution.Workspace",
        # it becomes the atom Krait.Evolution.Workspace (a bare atom, not an alias node)
        atom, acc when is_atom(atom) and not is_boolean(atom) and not is_nil(atom) ->
          if krait_module_atom?(atom), do: {nil, true}, else: {nil, acc}

        node, acc ->
          {node, acc}
      end)

    found
  end

  # Check if a bare atom represents a forbidden Krait module
  # :"Elixir.Krait.Evolution.Workspace" becomes atom Krait.Evolution.Workspace
  # Atom.to_string gives "Elixir.Krait.Evolution.Workspace"
  defp krait_module_atom?(atom) do
    atom_str =
      atom
      |> Atom.to_string()
      |> String.replace_prefix("Elixir.", "")

    Enum.any?(@krait_007_forbidden_prefixes, fn prefix ->
      prefix_str = Enum.map_join(prefix, ".", &Atom.to_string/1)
      String.starts_with?(atom_str, prefix_str)
    end)
  end

  defp forbidden_prefix?([:"Elixir" | rest]), do: forbidden_prefix?(rest)

  defp forbidden_prefix?(aliases) do
    Enum.any?(@krait_007_forbidden_prefixes, fn prefix ->
      List.starts_with?(aliases, prefix)
    end)
  end

  # Check for binary concatenation that could assemble an immutable path
  # e.g., "native/" <> "krait_analyzer"
  defp ast_has_concat_evasion?(ast) do
    # Collect all string fragments from binary concatenation operations
    concat_strings = ast_collect_concat_fragments(ast)

    # Check if any pair of adjacent fragments could form a forbidden path
    Enum.any?(@krait_006_patterns, fn pattern ->
      full = Enum.join(concat_strings)
      String.contains?(full, pattern)
    end)
  end

  defp ast_collect_concat_fragments(ast) do
    {_, fragments} =
      Macro.prewalk(ast, [], fn
        # Binary concat: left <> right
        {:<>, _, [left, right]}, acc ->
          left_strs = if is_binary(left), do: [left], else: []
          right_strs = if is_binary(right), do: [right], else: []
          {nil, acc ++ left_strs ++ right_strs}

        node, acc ->
          {node, acc}
      end)

    fragments
  end

  # Check for Path.join with list literals that could assemble an immutable path
  # e.g., Path.join(["native", "krait_analyzer"])
  defp ast_has_path_join_evasion?(ast) do
    {_, found} =
      Macro.prewalk(ast, false, fn
        # Path.join(["native", "krait_analyzer"])
        {{:., _, [{:__aliases__, _, [:Path]}, :join]}, _, [args]}, acc when is_list(args) ->
          joined =
            args
            |> Enum.filter(&is_binary/1)
            |> Enum.join("/")

          if Enum.any?(@krait_006_patterns, &String.contains?(joined, &1)) do
            {nil, true}
          else
            {nil, acc}
          end

        # Path.join("native", "krait_analyzer")
        {{:., _, [{:__aliases__, _, [:Path]}, :join]}, _, [left, right]}, acc
        when is_binary(left) and is_binary(right) ->
          joined = left <> "/" <> right

          if Enum.any?(@krait_006_patterns, &String.contains?(joined, &1)) do
            {nil, true}
          else
            {nil, acc}
          end

        node, acc ->
          {node, acc}
      end)

    found
  end

  # Check for Enum.join/map_join(["native", "krait_analyzer"], "/") evasion
  defp ast_has_enum_join_evasion?(ast) do
    {_, found} =
      Macro.prewalk(ast, false, fn
        # Enum.join(list, separator) or Enum.map_join(list, separator, fun)
        {{:., _, [{:__aliases__, _, [:Enum]}, join_fn]}, _, [args, sep | _rest]}, acc
        when join_fn in [:join, :map_join] and is_list(args) and is_binary(sep) ->
          joined =
            args
            |> Enum.filter(&is_binary/1)
            |> Enum.join(sep)

          if Enum.any?(@krait_006_patterns, &String.contains?(joined, &1)) do
            {nil, true}
          else
            {nil, acc}
          end

        # Enum.join(list) — default "" separator
        {{:., _, [{:__aliases__, _, [:Enum]}, :join]}, _, [args]}, acc when is_list(args) ->
          joined =
            args
            |> Enum.filter(&is_binary/1)
            |> Enum.join()

          if Enum.any?(@krait_006_patterns, &String.contains?(joined, &1)) do
            {nil, true}
          else
            {nil, acc}
          end

        node, acc ->
          {node, acc}
      end)

    found
  end

  # Check for IO.iodata_to_binary(["native/", "krait_analyzer"]) evasion
  defp ast_has_iodata_evasion?(ast) do
    {_, found} =
      Macro.prewalk(ast, false, fn
        {{:., _, [{:__aliases__, _, [:IO]}, :iodata_to_binary]}, _, [args]}, acc
        when is_list(args) ->
          joined =
            args
            |> Enum.filter(&is_binary/1)
            |> Enum.join()

          if Enum.any?(@krait_006_patterns, &String.contains?(joined, &1)) do
            {nil, true}
          else
            {nil, acc}
          end

        node, acc ->
          {node, acc}
      end)

    found
  end

  # Check for runtime string construction that could bypass string literal detection
  # Catches: List.to_string([ints]), :erlang.list_to_binary, Base.decode64!/decode64,
  # and for comprehensions building binaries from integer lists
  defp ast_has_runtime_string_construction?(ast) do
    {_, found} =
      Macro.prewalk(ast, false, fn
        # List.to_string([110, 97, 116, ...]) — integer list to string
        {{:., _, [{:__aliases__, _, [:List]}, :to_string]}, _, [arg]}, acc
        when is_list(arg) ->
          if Enum.all?(arg, &is_integer/1) and length(arg) > 0 do
            {nil, true}
          else
            {nil, acc}
          end

        # :erlang.list_to_binary(...) — no legitimate use in skill code
        {{:., _, [:erlang, :list_to_binary]}, _, _}, _acc ->
          {nil, true}

        # :binary.list_to_bin(...) — erlang binary conversion
        {{:., _, [:binary, :list_to_bin]}, _, _}, _acc ->
          {nil, true}

        # Base.decode64!(...) or Base.decode64(...) — suspicious in skill code
        {{:., _, [{:__aliases__, _, [:Base]}, func]}, _, _}, _acc
        when func in [:decode64!, :decode64] ->
          {nil, true}

        # String.Chars.to_string(...) — protocol dispatch
        {{:., _, [{:__aliases__, _, [:String, :Chars]}, :to_string]}, _, _}, _acc ->
          {nil, true}

        # IO.chardata_to_string(...) — chardata conversion
        {{:., _, [{:__aliases__, _, [:IO]}, :chardata_to_string]}, _, _}, _acc ->
          {nil, true}

        # v14: H-4 — :unicode.characters_to_binary/list bypass
        {{:., _, [:unicode, :characters_to_binary]}, _, _}, _acc ->
          {nil, true}

        {{:., _, [:unicode, :characters_to_list]}, _, _}, _acc ->
          {nil, true}

        # Bare to_string([...]) — Kernel.to_string dispatch
        {:to_string, _, [arg]}, acc when is_list(arg) ->
          if Enum.all?(arg, &is_integer/1) and length(arg) > 0 do
            {nil, true}
          else
            {nil, acc}
          end

        # for c <- [ints], into: "", do: <<c>> — binary construction from integers
        {:for, _, args}, acc when is_list(args) ->
          if has_binary_comprehension_pattern?(args) do
            {nil, true}
          else
            {nil, acc}
          end

        node, acc ->
          {node, acc}
      end)

    found
  end

  # Detect `for ... into: "", do: <<...>>` pattern
  defp has_binary_comprehension_pattern?(args) do
    # for comprehension args: [generator, [into: "", do: body]]
    # The keyword list contains both :into and :do keys
    Enum.any?(args, fn
      kwl when is_list(kwl) ->
        Keyword.get(kwl, :into) == "" and match?({:<<>>, _, _}, Keyword.get(kwl, :do))

      _ ->
        false
    end)
  end

  # Check for integer sequences anywhere in the AST that decode to forbidden paths.
  # Catches: <<110, 97, ...>>, [110, 97, ...] in any context (lists, binaries, module attrs).
  defp ast_has_suspicious_integer_sequence?(ast, forbidden_segments) do
    {_, found} =
      Macro.prewalk(ast, false, fn
        # Binary literal: <<110, 97, 116, ...>>
        {:<<>>, _, args}, acc when is_list(args) ->
          if length(args) > 3 and Enum.all?(args, &is_integer/1) do
            check_integer_sequence(args, forbidden_segments, acc)
          else
            {nil, acc}
          end

        # Integer list: [110, 97, 116, ...] anywhere in AST
        list, acc when is_list(list) and length(list) > 3 ->
          if Enum.all?(list, &is_integer/1) do
            check_integer_sequence(list, forbidden_segments, acc)
          else
            {nil, acc}
          end

        node, acc ->
          {node, acc}
      end)

    found
  end

  defp check_integer_sequence(ints, forbidden_segments, acc) do
    if Enum.all?(ints, &(&1 >= 0 and &1 <= 255)) do
      try do
        binary = :binary.list_to_bin(ints)

        if Enum.any?(forbidden_segments, &String.contains?(binary, &1)) do
          {nil, true}
        else
          {nil, acc}
        end
      rescue
        _ -> {nil, acc}
      end
    else
      {nil, acc}
    end
  end

  # v12: Phase 3 — :filename.join, :filelib.is_file, :string.concat evasion for KRAIT-006
  defp ast_has_erlang_path_op_evasion?(ast) do
    has_op =
      ast_has_any_erlang_call?(ast, [
        {:filename, :join},
        {:filename, :absname},
        {:filelib, :is_file},
        {:filelib, :is_dir},
        {:filelib, :wildcard},
        {:string, :concat}
      ])

    if has_op do
      string_literals = ast_collect_string_literals(ast)

      Enum.any?(string_literals, fn s ->
        Enum.any?(@krait_006_forbidden_segments, &String.contains?(s, &1))
      end)
    else
      false
    end
  end

  # v12: Phase 6 — String.replace / Regex.replace / Enum.reduce evasion for KRAIT-006
  defp ast_has_replace_evasion?(ast) do
    has_replace =
      ast_has_any_call?(ast, [
        {[:String], :replace},
        {[:Regex], :replace},
        {[:Enum], :reduce},
        # v15: M-1 — String.graphemes + Enum.flat_map_reduce
        {[:String], :graphemes},
        {[:Enum], :flat_map_reduce}
      ])

    if has_replace do
      string_literals = ast_collect_string_literals(ast)

      Enum.any?(string_literals, fn s ->
        Enum.any?(@krait_006_forbidden_segments, &String.contains?(s, &1))
      end)
    else
      false
    end
  end

  # v12: Phase 8 — case-insensitive evasion for KRAIT-006
  defp ast_has_case_evasion?(ast) do
    has_downcase =
      ast_has_any_call?(ast, [{[:String], :downcase}]) or
        ast_has_any_erlang_call?(ast, [{:string, :lowercase}, {:string, :to_lower}])

    if has_downcase do
      string_literals = ast_collect_string_literals(ast)

      Enum.any?(string_literals, fn s ->
        downcased = String.downcase(s)
        Enum.any?(@krait_006_forbidden_segments, &String.contains?(downcased, &1))
      end)
    else
      false
    end
  end

  # v13: Phase 8 — @external_resource with credential path detection
  defp ast_has_external_resource_cred?(ast) do
    {_, found} =
      Macro.prewalk(ast, false, fn
        {:@, _, [{:external_resource, _, [path]}]}, acc when is_binary(path) ->
          if credential_path?(path), do: {nil, true}, else: {nil, acc}

        node, acc ->
          {node, acc}
      end)

    found
  end

  # v13: Phase 8 — @external_resource with immutable path detection
  defp ast_has_external_resource_immutable?(ast) do
    {_, found} =
      Macro.prewalk(ast, false, fn
        {:@, _, [{:external_resource, _, [path]}]}, acc when is_binary(path) ->
          lower = String.downcase(path)

          if Enum.any?(@krait_006_patterns, &String.contains?(lower, &1)) do
            {nil, true}
          else
            {nil, acc}
          end

        node, acc ->
          {node, acc}
      end)

    found
  end

  # v15: Phase 6 M-2 — string interpolation with partial immutable segments
  @interpolation_partial_segments [
    "native/",
    "krait_analyzer",
    ".krait-immutable",
    ".krait-",
    "krait-rules",
    "_build/",
    # v16: C-1/H-7 — supply chain paths
    "config/",
    "priv/",
    ".github/",
    "deps/",
    ".git/",
    "rel/",
    "Dockerfile",
    "Makefile"
  ]

  defp ast_has_interpolation_evasion?(ast) do
    {_, found} =
      Macro.prewalk(ast, false, fn
        # Binary/string with interpolation: {:<<>>, _, parts} where parts mix literals and expressions
        {:<<>>, _, parts}, acc when is_list(parts) ->
          has_interpolation = Enum.any?(parts, &match?({:"::", _, _}, &1))

          if has_interpolation do
            literal_fragments =
              parts
              |> Enum.filter(&is_binary/1)

            has_suspicious =
              Enum.any?(literal_fragments, fn frag ->
                Enum.any?(@interpolation_partial_segments, &String.contains?(frag, &1))
              end)

            if has_suspicious, do: {nil, true}, else: {nil, acc}
          else
            {nil, acc}
          end

        node, acc ->
          {node, acc}
      end)

    found
  end

  # v13: Phase 9 — Atom.to_string / String.reverse / advanced path evasion
  defp ast_has_advanced_path_evasion?(ast) do
    has_construction =
      ast_has_any_call?(ast, [
        {[:Atom], :to_string},
        {[:String], :reverse},
        {[:Enum], :flat_map},
        {[:String], :slice}
      ])

    if has_construction do
      # Check for forbidden atom literals in the AST
      ast_has_forbidden_atom_literals?(ast) or ast_has_reversed_immutable_segments?(ast)
    else
      false
    end
  end

  # v13: Phase 9 — Check for atom literals matching forbidden segments
  defp ast_has_forbidden_atom_literals?(ast) do
    {_, found} =
      Macro.prewalk(ast, false, fn
        atom, acc
        when is_atom(atom) and not is_boolean(atom) and not is_nil(atom) ->
          atom_str = Atom.to_string(atom)

          if Enum.any?(@krait_006_forbidden_segments, &String.contains?(atom_str, &1)) do
            {nil, true}
          else
            {nil, acc}
          end

        node, acc ->
          {node, acc}
      end)

    found
  end

  # v13: Phase 9 — Check for reversed immutable segments in string literals
  defp ast_has_reversed_immutable_segments?(ast) do
    string_literals = ast_collect_string_literals(ast)

    Enum.any?(string_literals, fn s ->
      reversed = String.reverse(s)

      Enum.any?(@krait_006_forbidden_segments, fn seg ->
        String.contains?(s, seg) or String.contains?(reversed, seg)
      end)
    end)
  end

  # v14: H-3 — Fragment combination evasion detection
  # When <> is present and individual string literals match any forbidden segment,
  # flag it — catches `a = "krait_analyzer"; b = "/src"; a <> b`
  defp ast_has_fragment_combination_evasion?(ast) do
    if ast_has_binary_concat?(ast) do
      string_literals = ast_collect_string_literals(ast)

      Enum.any?(string_literals, fn s ->
        Enum.any?(@krait_006_forbidden_segments, fn seg ->
          String.contains?(s, seg)
        end)
      end)
    else
      false
    end
  end

  # Check if AST contains <> binary concatenation operator
  defp ast_has_binary_concat?(ast) do
    {_, found} =
      Macro.prewalk(ast, false, fn
        {:<>, _, _}, _acc -> {nil, true}
        node, acc -> {node, acc}
      end)

    found
  end

  # v12: Phase 9 — zero-width Unicode character stripping
  @zero_width_chars [
    <<0x200B::utf8>>,
    <<0x200C::utf8>>,
    <<0x200D::utf8>>,
    <<0xFEFF::utf8>>,
    <<0x00AD::utf8>>
  ]
  defp strip_zero_width(str) when is_binary(str) do
    Enum.reduce(@zero_width_chars, str, fn char, acc ->
      String.replace(acc, char, "")
    end)
  end

  # ---------------------------------------------------------------------------
  # String-based fallback for non-Elixir languages
  # ---------------------------------------------------------------------------

  # NOTE: This string-based fallback is intentionally preserved for non-Elixir code
  # (Rust, Python, JS, etc.) where the AST-based allowlist (KRAIT-ALW) does not apply.
  # For Elixir code, the allowlist in check_allowlist/2 is the primary gate and this
  # function is never called. These patterns cover KRAIT-001/002/004/005 (subsumed by
  # the allowlist for Elixir) plus KRAIT-006/007 (defense-in-depth for all languages).
  # Do not remove these patterns — they are the only validation layer for non-Elixir code.
  defp check_forbidden_patterns_string(code) do
    all_patterns = [
      {"KRAIT-001",
       [
         "Code.eval_string",
         "Code.eval_quoted",
         "Code.eval_file",
         "EEx.eval_string",
         "EEx.eval_file",
         "EEx.compile_string",
         "Elixir.Code",
         "Elixir.Application",
         "Application.put_env",
         "Application.delete_env",
         "Application.get_all_env",
         "Application.spec",
         ":erlang.binary_to_atom",
         ":erlang.list_to_atom",
         ":erlang.binary_to_existing_atom",
         ":erlang.list_to_existing_atom",
         ":erlang.binary_to_term",
         ":compile.file",
         "String.to_atom",
         "String.to_existing_atom",
         "import Code",
         "use Code",
         "import EEx",
         "import Application"
       ], "Dynamic code evaluation detected"},
      {"KRAIT-002",
       [
         # Elixir-specific
         "System.cmd",
         "System.shell",
         "Elixir.System",
         "Elixir.Port",
         ":os.cmd",
         ":os.getenv",
         ":os.putenv",
         ":init.stop",
         ":erpc.call",
         "Function.capture(System",
         "Port.open",
         "&System.cmd",
         "&System.shell",
         "&Port.open",
         "Module.concat",
         ":erlang.apply",
         "Mix.shell",
         ":ssh.connect",
         ":ftp.open",
         ":slave.start",
         ":peer.start",
         ":rpc.call",
         "import System",
         "alias System",
         "use System",
         "import Port",
         "import Mix",
         "&apply/",
         # Cross-language: Python
         "os.system(",
         "os.popen(",
         "subprocess.call",
         "subprocess.run",
         "subprocess.Popen",
         "import subprocess",
         "from subprocess",
         # Cross-language: JavaScript/TypeScript
         "child_process",
         "require('child_process')",
         "execSync(",
         "spawnSync("
       ], "Shell command execution detected"},
      {"KRAIT-004",
       [
         # Elixir-specific
         "Req.get",
         "Req.post",
         "Req.put",
         "HTTPoison",
         ":httpc.request",
         "Finch.build",
         ":hackney.request",
         ":hackney.get",
         ":hackney.post",
         ":gen_tcp.connect",
         ":gen_udp.open",
         ":ssl.connect",
         "import Req",
         "import HTTPoison",
         "import Finch",
         "Tesla.get",
         "Tesla.post",
         "Mojito.get",
         "Mojito.post",
         "import Tesla",
         "import Mojito",
         # Cross-language: Python
         "urllib.request",
         "requests.get",
         "requests.post",
         "import requests",
         "httpx.get",
         "httpx.post",
         # Cross-language: JavaScript
         "require('http')",
         "require('https')",
         "require('node-fetch')",
         "import fetch"
       ], "Raw HTTP client usage detected — use WebFetch skill"},
      {"KRAIT-005",
       [
         "Code.load_file",
         "Code.require_file",
         "Node.connect",
         "Elixir.Node",
         ":net_kernel.connect_node"
       ], "Hot code loading detected"},
      {"KRAIT-006",
       [
         "native/krait_analyzer",
         ".krait-immutable",
         "krait-rules.yaml",
         "_build/",
         "List.to_string",
         ":erlang.list_to_binary",
         ":binary.list_to_bin",
         "Base.decode64",
         "IO.chardata_to_string",
         "String.Chars.to_string"
       ], "Immutable path targeting detected"},
      {"KRAIT-007",
       [
         "Krait.Evolution",
         "Krait.Analyzer",
         "Krait.Sandbox",
         "Krait.Brain",
         "Krait.Gateway",
         "Krait.Memory",
         "Krait.LLM",
         "Krait.Skills",
         "Krait.Repo",
         "KraitWeb",
         "Krait.GitHub"
       ], "KRAIT internals tampering detected"}
    ]

    Enum.reduce_while(all_patterns, :ok, fn {rule, patterns, explanation}, :ok ->
      if Enum.any?(patterns, &String.contains?(code, &1)) do
        Logger.warning("Policy violation detected", rule: rule)
        {:halt, {:policy_violation, %{rule: rule, location: %{}, explanation: explanation}}}
      else
        {:cont, :ok}
      end
    end)
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp violation(rule, explanation) do
    Logger.warning("Policy violation detected", rule: rule)
    {:policy_violation, %{rule: rule, location: %{}, explanation: explanation}}
  end

  # ---------------------------------------------------------------------------
  # Complexity scoring
  # ---------------------------------------------------------------------------

  defp compute_complexity(code) do
    Enum.reduce(@complexity_patterns, 1, fn pattern, acc ->
      acc + length(Regex.scan(pattern, code))
    end)
  end

  # ---------------------------------------------------------------------------
  # Hashing (SHA-256; will be replaced by BLAKE3 when the NIF arrives)
  # ---------------------------------------------------------------------------

  defp compute_hash(code) do
    :crypto.hash(:sha256, code) |> Base.encode16(case: :lower)
  end
end
