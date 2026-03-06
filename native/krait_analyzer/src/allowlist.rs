use std::collections::HashSet;
use std::sync::OnceLock;
use streaming_iterator::StreamingIterator;
use tree_sitter::{Query, QueryCursor, Tree};

#[allow(dead_code)]
pub struct Violation {
    pub rule: String,
    pub explanation: String,
}

// ---------------------------------------------------------------------------
// Tier 1: Pure computation Elixir modules (single-segment aliases)
// ---------------------------------------------------------------------------

const ALLOWED_ELIXIR_MODULES: &[&str] = &[
    "Enum", "Map", "List", "Keyword", "Tuple", "MapSet", "Stream", "Range",
    "Access", "String", "Regex", "Base", "URI", "Integer", "Float", "Bitwise",
    "Date", "DateTime", "NaiveDateTime", "Time", "Calendar", "Jason",
    "Inspect", "Collectable", "Enumerable", "Kernel",
];

// ---------------------------------------------------------------------------
// Tier 3: Safe Erlang modules
// ---------------------------------------------------------------------------

const ALLOWED_ERLANG_MODULES: &[&str] = &[
    "math", "lists", "maps", "binary", "string", "unicode",
    "calendar", "base64", "rand",
];

// ---------------------------------------------------------------------------
// Tier 5: Krait framework interfaces (multi-segment aliases)
// ---------------------------------------------------------------------------

const ALLOWED_KRAIT_MODULES: &[&str] = &[
    "Krait.Skills.Skill",
    "Krait.Skills.Core.WebFetch",
    "Krait.Skills.Core.Filesystem",
    "Krait.Skills.Core.MemorySkill",
    // Capability system modules (Phase 3)
    "Krait.Skills.CapableSkill",
    "Krait.Skills.Capabilities.FilesystemCap",
    "Krait.Skills.Capabilities.NetworkCap",
    "Krait.Skills.Capabilities.MemoryCap",
];

// ---------------------------------------------------------------------------
// Tier 2: Denied Kernel functions
// ---------------------------------------------------------------------------

const DENIED_KERNEL_FUNCTIONS: &[&str] = &[
    "spawn", "spawn_link", "spawn_monitor", "send", "self", "apply",
    "exit", "node", "nodes", "make_ref", "throw", "open_port",
    "process_flag", "register", "whereis", "monitor", "demonitor",
    "link", "unlink", "group_leader", "disconnect_node",
    // v17: H-6 expanded
    "binding", "var!", "macro_exported?", "function_exported?",
    "dbg", "struct", "struct!", "tap",
];

// v17: C-5 — Denied functions on otherwise-allowed modules
const DENIED_STRING_FUNCTIONS: &[&str] = &["to_atom", "to_existing_atom"];
const DENIED_STREAM_FUNCTIONS: &[&str] = &["resource", "run", "repeatedly", "iterate", "unfold"];

// ---------------------------------------------------------------------------
// Lazy-initialized HashSets
// ---------------------------------------------------------------------------

static ALLOWED_ELIXIR_SET: OnceLock<HashSet<String>> = OnceLock::new();
static ALLOWED_ERLANG_SET: OnceLock<HashSet<String>> = OnceLock::new();
static ALLOWED_KRAIT_SET: OnceLock<HashSet<String>> = OnceLock::new();
static DENIED_KERNEL_SET: OnceLock<HashSet<String>> = OnceLock::new();

fn elixir_set() -> &'static HashSet<String> {
    ALLOWED_ELIXIR_SET.get_or_init(|| {
        ALLOWED_ELIXIR_MODULES.iter().map(|s| s.to_string()).collect()
    })
}

fn erlang_set() -> &'static HashSet<String> {
    ALLOWED_ERLANG_SET.get_or_init(|| {
        ALLOWED_ERLANG_MODULES.iter().map(|s| s.to_string()).collect()
    })
}

fn krait_set() -> &'static HashSet<String> {
    ALLOWED_KRAIT_SET.get_or_init(|| {
        ALLOWED_KRAIT_MODULES.iter().map(|s| s.to_string()).collect()
    })
}

fn denied_kernel_set() -> &'static HashSet<String> {
    DENIED_KERNEL_SET.get_or_init(|| {
        DENIED_KERNEL_FUNCTIONS.iter().map(|s| s.to_string()).collect()
    })
}

fn is_allowed_module(name: &str) -> bool {
    // Strip Elixir. prefix if present
    let clean = name.strip_prefix("Elixir.").unwrap_or(name);

    // Check single-segment Elixir modules (Enum, String, etc.)
    if elixir_set().contains(clean) {
        return true;
    }
    // Check multi-segment Krait modules (Krait.Skills.Skill, etc.)
    if krait_set().contains(clean) {
        return true;
    }
    // Check if it's a sub-module of an allowed Krait module
    // e.g., Krait.Skills.Core.WebFetch.SomeChild — not allowed unless explicitly listed
    false
}

fn is_allowed_erlang(name: &str) -> bool {
    erlang_set().contains(name)
}

fn is_denied_kernel_function(name: &str) -> bool {
    denied_kernel_set().contains(name)
}

// ---------------------------------------------------------------------------
// Main check function
// ---------------------------------------------------------------------------

/// Check code against the module/function allowlist.
/// Returns Some(Violation) if non-allowlisted module/function is used.
pub fn check_allowlist(code: &str, tree: &Tree) -> Option<Violation> {
    // 1. Check all qualified Elixir calls (Module.func)
    if let Some(v) = check_elixir_dot_calls(code, tree) {
        return Some(v);
    }
    // 2. Check all qualified Erlang calls (:mod.func)
    if let Some(v) = check_erlang_dot_calls(code, tree) {
        return Some(v);
    }
    // 3. Check directives (import/alias/use/require)
    if let Some(v) = check_directives(code, tree) {
        return Some(v);
    }
    // 4. Check bare denied Kernel function calls
    if let Some(v) = check_bare_kernel_calls(code, tree) {
        return Some(v);
    }
    // 5. Check defmacro/defmacrop (string-based)
    if let Some(v) = check_defmacro(code) {
        return Some(v);
    }
    // 6. Check apply() calls (string-based for reliability)
    if let Some(v) = check_apply_calls(code, tree) {
        return Some(v);
    }
    // 7. Check defdelegate (string-based)
    if let Some(v) = check_defdelegate(code) {
        return Some(v);
    }
    // 8. Check &Module.func/arity capture shorthand (string-based)
    if let Some(v) = check_capture_shorthand(code) {
        return Some(v);
    }
    // 9. v17: C-6 — Module attribute indirection
    if let Some(v) = check_module_attr_indirection(code) {
        return Some(v);
    }
    // 10. v17: C-7 — Variable-based dynamic dispatch
    if let Some(v) = check_variable_dispatch(code) {
        return Some(v);
    }
    None
}

// ---------------------------------------------------------------------------
// 1. Qualified Elixir calls: Module.func(args)
// Uses the same query as rules.rs has_dot_call
// ---------------------------------------------------------------------------

fn check_elixir_dot_calls(code: &str, tree: &Tree) -> Option<Violation> {
    let query_str = r#"(call
        target: (dot
            left: (alias) @mod
            right: (identifier) @fn))"#;

    let query = match Query::new(&tree_sitter_elixir::LANGUAGE.into(), query_str) {
        Ok(q) => q,
        Err(_) => return None,
    };

    let bytes = code.as_bytes();
    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&query, tree.root_node(), bytes);

    while let Some(m) = matches.next() {
        if m.captures.len() < 2 {
            continue;
        }
        let Some(mod_text) = utf8_text(m.captures[0].node, bytes) else {
            continue;
        };
        let Some(fn_text) = utf8_text(m.captures[1].node, bytes) else {
            continue;
        };
        let resolved = mod_text.strip_prefix("Elixir.").unwrap_or(mod_text);

        // C-1: Kernel.denied_fn() bypass
        if resolved == "Kernel" && is_denied_kernel_function(fn_text) {
            return Some(Violation {
                rule: "KRAIT-ALW".to_string(),
                explanation: format!("Kernel.{} is not allowed in generated code", fn_text),
            });
        }
        // C-5: Denied functions on allowed modules
        if resolved == "String" && DENIED_STRING_FUNCTIONS.contains(&fn_text) {
            return Some(Violation {
                rule: "KRAIT-ALW".to_string(),
                explanation: format!("String.{} is not allowed in generated code", fn_text),
            });
        }
        if resolved == "Stream" && DENIED_STREAM_FUNCTIONS.contains(&fn_text) {
            return Some(Violation {
                rule: "KRAIT-ALW".to_string(),
                explanation: format!("Stream.{} is not allowed in generated code", fn_text),
            });
        }
        if !is_allowed_module(resolved) {
            return Some(Violation {
                rule: "KRAIT-ALW".to_string(),
                explanation: format!("Module {} is not on the allowlist", resolved),
            });
        }
    }
    None
}

// ---------------------------------------------------------------------------
// 2. Qualified Erlang calls: :mod.func(args)
// Uses the same query as rules.rs has_atom_dot_call
// ---------------------------------------------------------------------------

fn check_erlang_dot_calls(code: &str, tree: &Tree) -> Option<Violation> {
    let query_str = r#"(call
        target: (dot
            left: (atom) @mod
            right: (identifier) @fn))"#;

    let query = match Query::new(&tree_sitter_elixir::LANGUAGE.into(), query_str) {
        Ok(q) => q,
        Err(_) => return None,
    };

    let bytes = code.as_bytes();
    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&query, tree.root_node(), bytes);

    while let Some(m) = matches.next() {
        let Some(cap0) = m.captures.first() else {
            continue;
        };
        let Some(mod_text) = utf8_text(cap0.node, bytes) else {
            continue;
        };
        let mod_name = mod_text.trim_start_matches(':');
        if !is_allowed_erlang(mod_name) {
            return Some(Violation {
                rule: "KRAIT-ALW".to_string(),
                explanation: format!(
                    "Erlang module :{} is not on the allowlist",
                    mod_name
                ),
            });
        }
    }

    // Also check quoted_atom dot calls
    let quoted_query_str = r#"(call
        target: (dot
            left: (quoted_atom) @mod
            right: (identifier) @fn))"#;
    if let Ok(query) = Query::new(&tree_sitter_elixir::LANGUAGE.into(), quoted_query_str) {
        let mut cursor2 = QueryCursor::new();
        let mut matches2 = cursor2.matches(&query, tree.root_node(), bytes);
        while let Some(m) = matches2.next() {
            let Some(cap0) = m.captures.first() else {
                continue;
            };
            let Some(mod_text) = utf8_text(cap0.node, bytes) else {
                continue;
            };
            // Quoted atom: :"module_name"
            if mod_text.starts_with(":\"") && mod_text.ends_with('"') && mod_text.len() > 3 {
                let inner = &mod_text[2..mod_text.len() - 1];
                if !is_allowed_erlang(inner) && !is_allowed_module(inner) {
                    return Some(Violation {
                        rule: "KRAIT-ALW".to_string(),
                        explanation: format!(
                            "Module {} is not on the allowlist",
                            inner
                        ),
                    });
                }
            }
        }
    }

    None
}

// ---------------------------------------------------------------------------
// 3. Directives: import/alias/use/require
// ---------------------------------------------------------------------------

fn check_directives(code: &str, tree: &Tree) -> Option<Violation> {
    // Use has_alias_reference-style query to find all alias nodes,
    // then cross-reference with directive context
    let query_str = r#"(call
        target: (identifier) @directive
        (arguments (alias) @mod))"#;

    let query = match Query::new(&tree_sitter_elixir::LANGUAGE.into(), query_str) {
        Ok(q) => q,
        Err(_) => return check_directives_string_fallback(code),
    };

    let bytes = code.as_bytes();
    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&query, tree.root_node(), bytes);

    while let Some(m) = matches.next() {
        if m.captures.len() < 2 {
            continue;
        }
        let Some(dir_text) = utf8_text(m.captures[0].node, bytes) else {
            continue;
        };
        let Some(mod_text) = utf8_text(m.captures[1].node, bytes) else {
            continue;
        };

        if matches!(dir_text, "import" | "alias" | "use" | "require") {
            let resolved = mod_text.strip_prefix("Elixir.").unwrap_or(mod_text);
            if !is_allowed_module(resolved) {
                return Some(Violation {
                    rule: "KRAIT-ALW".to_string(),
                    explanation: format!(
                        "{} of non-allowlisted module {}",
                        dir_text, resolved
                    ),
                });
            }
        }
    }
    None
}

fn check_directives_string_fallback(code: &str) -> Option<Violation> {
    for directive in &["import ", "alias ", "use ", "require "] {
        for line in code.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix(directive) {
                let mod_name = rest
                    .split([',', '\n', ' '])
                    .next()
                    .unwrap_or("");
                let mod_name = mod_name.trim();
                if !mod_name.is_empty()
                    && mod_name
                        .chars()
                        .next()
                        .is_some_and(|c| c.is_uppercase())
                {
                    let resolved = mod_name.strip_prefix("Elixir.").unwrap_or(mod_name);
                    if !is_allowed_module(resolved) {
                        return Some(Violation {
                            rule: "KRAIT-ALW".to_string(),
                            explanation: format!(
                                "{} of non-allowlisted module {}",
                                directive.trim(),
                                resolved
                            ),
                        });
                    }
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// 4. Bare Kernel function calls
// ---------------------------------------------------------------------------

fn check_bare_kernel_calls(code: &str, tree: &Tree) -> Option<Violation> {
    let query_str = r#"(call target: (identifier) @fn_name)"#;
    let query = match Query::new(&tree_sitter_elixir::LANGUAGE.into(), query_str) {
        Ok(q) => q,
        Err(_) => return None,
    };

    let bytes = code.as_bytes();
    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&query, tree.root_node(), bytes);

    while let Some(m) = matches.next() {
        let Some(cap0) = m.captures.first() else {
            continue;
        };
        let Some(text) = utf8_text(cap0.node, bytes) else {
            continue;
        };
        if is_denied_kernel_function(text) {
            return Some(Violation {
                rule: "KRAIT-ALW".to_string(),
                explanation: format!(
                    "Kernel function {} is not allowed in generated code",
                    text
                ),
            });
        }
    }
    None
}

// ---------------------------------------------------------------------------
// 5. defmacro/defmacrop (string-based)
// ---------------------------------------------------------------------------

fn check_defmacro(code: &str) -> Option<Violation> {
    for line in code.lines() {
        let trimmed = line.trim();
        // Check defmacrop first (longer prefix)
        if trimmed.starts_with("defmacrop ") || trimmed.starts_with("defmacrop(") {
            return Some(Violation {
                rule: "KRAIT-ALW".to_string(),
                explanation: "defmacrop is not allowed in generated code".to_string(),
            });
        }
        if trimmed.starts_with("defmacro ") || trimmed.starts_with("defmacro(") {
            return Some(Violation {
                rule: "KRAIT-ALW".to_string(),
                explanation: "defmacro is not allowed in generated code".to_string(),
            });
        }
        // v17: M-3 — defprotocol/defimpl
        if trimmed.starts_with("defprotocol ") || trimmed.starts_with("defprotocol(") {
            return Some(Violation {
                rule: "KRAIT-ALW".to_string(),
                explanation: "defprotocol is not allowed in generated code".to_string(),
            });
        }
        if trimmed.starts_with("defimpl ") || trimmed.starts_with("defimpl(") {
            return Some(Violation {
                rule: "KRAIT-ALW".to_string(),
                explanation: "defimpl is not allowed in generated code".to_string(),
            });
        }
        // v17: M-4 — defoverridable
        if trimmed.starts_with("defoverridable ") || trimmed.starts_with("defoverridable(") {
            return Some(Violation {
                rule: "KRAIT-ALW".to_string(),
                explanation: "defoverridable is not allowed in generated code".to_string(),
            });
        }
        // v17: C-2 — compile hook attributes
        if trimmed.starts_with("@before_compile ") || trimmed.starts_with("@before_compile(") {
            return Some(Violation {
                rule: "KRAIT-ALW".to_string(),
                explanation: "@before_compile compile hook is not allowed".to_string(),
            });
        }
        if trimmed.starts_with("@after_compile ") || trimmed.starts_with("@after_compile(") {
            return Some(Violation {
                rule: "KRAIT-ALW".to_string(),
                explanation: "@after_compile compile hook is not allowed".to_string(),
            });
        }
        if trimmed.starts_with("@on_load ") || trimmed.starts_with("@on_load(") {
            return Some(Violation {
                rule: "KRAIT-ALW".to_string(),
                explanation: "@on_load compile hook is not allowed".to_string(),
            });
        }
        if trimmed.starts_with("@on_definition ") || trimmed.starts_with("@on_definition(") {
            return Some(Violation {
                rule: "KRAIT-ALW".to_string(),
                explanation: "@on_definition compile hook is not allowed".to_string(),
            });
        }
    }
    // v17: C-3 — receive blocks (keyword-level)
    if check_receive_blocks(code) {
        return Some(Violation {
            rule: "KRAIT-ALW".to_string(),
            explanation: "receive is not allowed in generated code".to_string(),
        });
    }
    // v17: C-4 — quote blocks (keyword-level)
    if check_quote_blocks(code) {
        return Some(Violation {
            rule: "KRAIT-ALW".to_string(),
            explanation: "quote is not allowed in generated code".to_string(),
        });
    }
    None
}

// v17: C-3 — detect `receive do` pattern (v19: broader detection)
fn check_receive_blocks(code: &str) -> bool {
    for line in code.lines() {
        let trimmed = line.trim();
        // Skip comments
        if trimmed.starts_with('#') {
            continue;
        }
        // Match: "receive do", "receive(", or standalone "receive" as keyword
        if trimmed.starts_with("receive do")
            || trimmed.starts_with("receive(")
            || trimmed.contains(" receive do")
            || trimmed.contains(" receive(")
            || trimmed == "receive"
        {
            return true;
        }
    }
    false
}

// v17: C-4 — detect `quote do` pattern (v19: broader detection)
fn check_quote_blocks(code: &str) -> bool {
    for line in code.lines() {
        let trimmed = line.trim();
        // Skip comments
        if trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with("quote do")
            || trimmed.starts_with("quote(")
            || trimmed.contains(" quote do")
            || trimmed.contains(" quote(")
        {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// 6. apply() calls
// ---------------------------------------------------------------------------

fn check_apply_calls(code: &str, tree: &Tree) -> Option<Violation> {
    // Tree-sitter: apply(alias, atom, ...) or apply(atom, atom, ...)
    let query_str = r#"(call
        target: (identifier) @fn_name
        (arguments
            (alias) @mod))"#;

    if let Ok(query) = Query::new(&tree_sitter_elixir::LANGUAGE.into(), query_str) {
        let bytes = code.as_bytes();
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), bytes);

        while let Some(m) = matches.next() {
            if m.captures.len() < 2 {
                continue;
            }
            let Some(fn_text) = utf8_text(m.captures[0].node, bytes) else {
                continue;
            };
            let Some(mod_text) = utf8_text(m.captures[1].node, bytes) else {
                continue;
            };
            if fn_text == "apply" {
                let resolved = mod_text.strip_prefix("Elixir.").unwrap_or(mod_text);
                if !is_allowed_module(resolved) {
                    return Some(Violation {
                        rule: "KRAIT-ALW".to_string(),
                        explanation: format!(
                            "apply with non-allowlisted module {}",
                            resolved
                        ),
                    });
                }
            }
        }
    }

    // apply(:atom_mod, ...)
    let query_str2 = r#"(call
        target: (identifier) @fn_name
        (arguments
            (atom) @mod))"#;

    if let Ok(query) = Query::new(&tree_sitter_elixir::LANGUAGE.into(), query_str2) {
        let bytes = code.as_bytes();
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), bytes);

        while let Some(m) = matches.next() {
            if m.captures.len() < 2 {
                continue;
            }
            let Some(fn_text) = utf8_text(m.captures[0].node, bytes) else {
                continue;
            };
            let Some(mod_text) = utf8_text(m.captures[1].node, bytes) else {
                continue;
            };
            if fn_text == "apply" {
                let mod_name = mod_text.trim_start_matches(':');
                if !is_allowed_erlang(mod_name) && !is_allowed_module(mod_name) {
                    return Some(Violation {
                        rule: "KRAIT-ALW".to_string(),
                        explanation: format!(
                            "apply with non-allowlisted module {}",
                            mod_text
                        ),
                    });
                }
            }
        }
    }

    // Kernel.apply(Module, ...) — check via dot call query
    let kernel_query_str = r#"(call
        target: (dot
            left: (alias) @caller
            right: (identifier) @fn)
        (arguments
            (alias) @mod))"#;

    if let Ok(query) = Query::new(&tree_sitter_elixir::LANGUAGE.into(), kernel_query_str) {
        let bytes = code.as_bytes();
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), bytes);

        while let Some(m) = matches.next() {
            if m.captures.len() < 3 {
                continue;
            }
            let Some(caller) = utf8_text(m.captures[0].node, bytes) else {
                continue;
            };
            let Some(fn_name) = utf8_text(m.captures[1].node, bytes) else {
                continue;
            };
            let Some(mod_text) = utf8_text(m.captures[2].node, bytes) else {
                continue;
            };
            if caller == "Kernel" && fn_name == "apply" {
                let resolved = mod_text.strip_prefix("Elixir.").unwrap_or(mod_text);
                if !is_allowed_module(resolved) {
                    return Some(Violation {
                        rule: "KRAIT-ALW".to_string(),
                        explanation: format!(
                            "Kernel.apply with non-allowlisted module {}",
                            resolved
                        ),
                    });
                }
            }
        }
    }

    // Kernel.apply(:atom, ...)
    let kernel_atom_query = r#"(call
        target: (dot
            left: (alias) @caller
            right: (identifier) @fn)
        (arguments
            (atom) @mod))"#;

    if let Ok(query) = Query::new(&tree_sitter_elixir::LANGUAGE.into(), kernel_atom_query) {
        let bytes = code.as_bytes();
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), bytes);

        while let Some(m) = matches.next() {
            if m.captures.len() < 3 {
                continue;
            }
            let Some(caller) = utf8_text(m.captures[0].node, bytes) else {
                continue;
            };
            let Some(fn_name) = utf8_text(m.captures[1].node, bytes) else {
                continue;
            };
            let Some(mod_text) = utf8_text(m.captures[2].node, bytes) else {
                continue;
            };
            if caller == "Kernel" && fn_name == "apply" {
                let mod_name = mod_text.trim_start_matches(':');
                if !is_allowed_erlang(mod_name) && !is_allowed_module(mod_name) {
                    return Some(Violation {
                        rule: "KRAIT-ALW".to_string(),
                        explanation: format!(
                            "Kernel.apply with non-allowlisted module {}",
                            mod_text
                        ),
                    });
                }
            }
        }
    }

    None
}

// ---------------------------------------------------------------------------
// 7. defdelegate (string-based)
// ---------------------------------------------------------------------------

fn check_defdelegate(code: &str) -> Option<Violation> {
    for line in code.lines() {
        let trimmed = line.trim();
        // H-2: match both "defdelegate " and "defdelegate(" forms
        if !trimmed.starts_with("defdelegate ") && !trimmed.starts_with("defdelegate(") {
            continue;
        }
        if let Some(to_idx) = trimmed.find("to:") {
            let after_to = trimmed[to_idx + 3..].trim();
            if let Some(stripped) = after_to.strip_prefix(':') {
                // Erlang module: to: :os
                let mod_name: String = stripped
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                if !mod_name.is_empty() && !is_allowed_erlang(&mod_name) {
                    return Some(Violation {
                        rule: "KRAIT-ALW".to_string(),
                        explanation: format!(
                            "defdelegate to non-allowlisted Erlang module :{}",
                            mod_name
                        ),
                    });
                }
            } else if after_to
                .chars()
                .next()
                .is_some_and(|c| c.is_uppercase())
            {
                // Elixir module: to: System
                let mod_name: String = after_to
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '.')
                    .collect();
                let resolved = mod_name.strip_prefix("Elixir.").unwrap_or(&mod_name);
                if !is_allowed_module(resolved) {
                    return Some(Violation {
                        rule: "KRAIT-ALW".to_string(),
                        explanation: format!(
                            "defdelegate to non-allowlisted module {}",
                            resolved
                        ),
                    });
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// 8. &Module.func/arity capture shorthand (string-based)
// ---------------------------------------------------------------------------

fn check_capture_shorthand(code: &str) -> Option<Violation> {
    // Look for &Module.func/N patterns in each line
    for line in code.lines() {
        // Find all & characters in the line
        let bytes = line.as_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            if b != b'&' {
                continue;
            }
            let rest = &line[i + 1..].trim_start();
            // Must start with uppercase (Module name)
            if !rest.chars().next().is_some_and(|c| c.is_uppercase()) {
                continue;
            }
            // Extract module.func/arity
            if let Some(dot_idx) = rest.find('.') {
                if rest[dot_idx..].contains('/') {
                    let module_part = &rest[..dot_idx];
                    let resolved = module_part
                        .strip_prefix("Elixir.")
                        .unwrap_or(module_part);
                    if !is_allowed_module(resolved) {
                        return Some(Violation {
                            rule: "KRAIT-ALW".to_string(),
                            explanation: format!(
                                "Capture of non-allowlisted module {}",
                                resolved
                            ),
                        });
                    }
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// 9. v17: C-6 — Module attribute indirection
// Detects: @target :os / @target System; then @target.func() usage
// ---------------------------------------------------------------------------

fn check_module_attr_indirection(code: &str) -> Option<Violation> {
    // Phase 1: Collect @attr :module and @attr Module bindings
    let mut attr_bindings: Vec<(String, String)> = Vec::new(); // (attr_name, module_name)

    for line in code.lines() {
        let trimmed = line.trim();
        // @attr :erlang_mod
        if let Some(rest) = trimmed.strip_prefix('@') {
            if let Some(space_idx) = rest.find([' ', '\t']) {
                let attr_name = &rest[..space_idx];
                let value = rest[space_idx..].trim();
                if let Some(mod_name) = value.strip_prefix(':') {
                    let mod_name: String = mod_name.chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_')
                        .collect();
                    if !mod_name.is_empty() && !is_allowed_erlang(&mod_name) {
                        attr_bindings.push((attr_name.to_string(), mod_name));
                    }
                } else if value.chars().next().is_some_and(|c| c.is_uppercase()) {
                    let mod_name: String = value.chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '.')
                        .collect();
                    let resolved = mod_name.strip_prefix("Elixir.").unwrap_or(&mod_name);
                    if !is_allowed_module(resolved) {
                        attr_bindings.push((attr_name.to_string(), mod_name));
                    }
                }
            }
        }
    }

    // Phase 2: Check for @attr.func() usage
    for (attr_name, mod_name) in &attr_bindings {
        let pattern = format!("@{}.", attr_name);
        if code.contains(&pattern) {
            return Some(Violation {
                rule: "KRAIT-ALW".to_string(),
                explanation: format!(
                    "@{} attribute indirection with non-allowlisted module {}",
                    attr_name, mod_name
                ),
            });
        }
    }
    None
}

// ---------------------------------------------------------------------------
// 10. v17: C-7 — Variable-based dynamic dispatch
// Detects: m = System; m.cmd(...) or m = :os; m.cmd(...)
// ---------------------------------------------------------------------------

fn check_variable_dispatch(code: &str) -> Option<Violation> {
    let non_allowed_modules = [
        "System", "File", "Code", "Port", "Process", "Node", "Task",
        "Agent", "GenServer", "Supervisor", "Application", "Mix",
    ];
    let non_allowed_erlang = [
        ":os", ":file", ":code", ":erlang", ":ets", ":gen_tcp", ":gen_udp",
        ":ssl", ":gen_server", ":compile", ":init",
    ];

    let mut var_bindings: Vec<(String, String)> = Vec::new(); // (var_name, module)

    for line in code.lines() {
        let trimmed = line.trim();
        // var = Module
        for module in &non_allowed_modules {
            let patterns = [
                format!("= {}", module),
                format!("= Elixir.{}", module),
            ];
            for pat in &patterns {
                if let Some(idx) = trimmed.find(pat.as_str()) {
                    let before = trimmed[..idx].trim();
                    let var_name: String = before.chars().rev()
                        .take_while(|c| c.is_alphanumeric() || *c == '_')
                        .collect::<String>()
                        .chars().rev().collect();
                    if !var_name.is_empty() && var_name.chars().next().is_some_and(|c| c.is_lowercase() || c == '_') {
                        var_bindings.push((var_name, module.to_string()));
                    }
                }
            }
        }
        // var = :erlang_mod
        for module in &non_allowed_erlang {
            let pat = format!("= {}", module);
            if let Some(idx) = trimmed.find(pat.as_str()) {
                let before = trimmed[..idx].trim();
                let var_name: String = before.chars().rev()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect::<String>()
                    .chars().rev().collect();
                if !var_name.is_empty() && var_name.chars().next().is_some_and(|c| c.is_lowercase() || c == '_') {
                    var_bindings.push((var_name, module.to_string()));
                }
            }
        }

        // v20 H-1 Fix 2: Tuple destructuring — {var, _} = {:os, :cmd} or {_, var} = {:ok, System}
        collect_tuple_destructuring_bindings(trimmed, &non_allowed_modules, &non_allowed_erlang, &mut var_bindings);

        // v20 H-1 Fix 2: List destructuring — [var] = [System]
        collect_list_destructuring_bindings(trimmed, &non_allowed_modules, &non_allowed_erlang, &mut var_bindings);
    }

    // Check for var.func() or apply(var, ...) usage anywhere in code
    for (var_name, module) in &var_bindings {
        let dot_pattern = format!("{}.", var_name);
        let apply_pattern = format!("apply({},", var_name);
        let apply_pattern_space = format!("apply({} ,", var_name);
        for line in code.lines() {
            let trimmed = line.trim();
            if trimmed.contains(&dot_pattern) ||
               trimmed.contains(&apply_pattern) ||
               trimmed.contains(&apply_pattern_space) {
                return Some(Violation {
                    rule: "KRAIT-ALW".to_string(),
                    explanation: format!(
                        "Variable-based dispatch with non-allowlisted module {}",
                        module
                    ),
                });
            }
        }
    }

    // v20 H-1 Fix 3: Catch-all — apply with non-literal first argument
    if let Some(v) = check_apply_nonliteral(code) {
        return Some(v);
    }

    None
}

// v20 H-1: Extract variable bindings from tuple destructuring patterns
fn collect_tuple_destructuring_bindings(
    line: &str,
    non_allowed_modules: &[&str],
    non_allowed_erlang: &[&str],
    bindings: &mut Vec<(String, String)>,
) {
    // Pattern: {var, _} = {Module, _} or {_, var} = {_, Module}
    // Look for "} = {" as a signal
    if !line.contains("} = {") {
        return;
    }
    if let Some(eq_idx) = line.find("} = {") {
        let lhs = &line[..eq_idx + 1]; // includes }
        let rhs = &line[eq_idx + 3..];  // after "= "

        // Extract tuple contents from both sides
        let lhs_inner = extract_tuple_inner(lhs);
        let rhs_inner = extract_tuple_inner(rhs);

        if let (Some(lhs_parts), Some(rhs_parts)) = (lhs_inner, rhs_inner) {
            if lhs_parts.len() == rhs_parts.len() {
                for (lhs_part, rhs_part) in lhs_parts.iter().zip(rhs_parts.iter()) {
                    let var_name = lhs_part.trim();
                    let module = rhs_part.trim();
                    // Skip wildcards
                    if var_name == "_" || var_name.is_empty() {
                        continue;
                    }
                    // Variable must start with lowercase or _
                    if !var_name.chars().next().is_some_and(|c| c.is_lowercase() || c == '_') {
                        continue;
                    }
                    // Check if module is non-allowed
                    for m in non_allowed_modules.iter() {
                        if module == *m || module == format!("Elixir.{}", m) {
                            bindings.push((var_name.to_string(), m.to_string()));
                        }
                    }
                    for m in non_allowed_erlang.iter() {
                        if module == *m {
                            bindings.push((var_name.to_string(), m.to_string()));
                        }
                    }
                }
            }
        }
    }
}

fn extract_tuple_inner(s: &str) -> Option<Vec<String>> {
    let s = s.trim();
    if let Some(start) = s.find('{') {
        if let Some(end) = s.rfind('}') {
            if start < end {
                let inner = &s[start + 1..end];
                return Some(inner.split(',').map(|p| p.trim().to_string()).collect());
            }
        }
    }
    None
}

// v20 H-1: Extract variable bindings from list destructuring patterns
fn collect_list_destructuring_bindings(
    line: &str,
    non_allowed_modules: &[&str],
    non_allowed_erlang: &[&str],
    bindings: &mut Vec<(String, String)>,
) {
    // Pattern: [var] = [Module]
    if !line.contains("] = [") {
        return;
    }
    if let Some(eq_idx) = line.find("] = [") {
        let lhs = &line[..eq_idx + 1];
        let rhs = &line[eq_idx + 3..];

        let lhs_inner = extract_list_inner(lhs);
        let rhs_inner = extract_list_inner(rhs);

        if let (Some(lhs_parts), Some(rhs_parts)) = (lhs_inner, rhs_inner) {
            if lhs_parts.len() == rhs_parts.len() {
                for (lhs_part, rhs_part) in lhs_parts.iter().zip(rhs_parts.iter()) {
                    let var_name = lhs_part.trim();
                    let module = rhs_part.trim();
                    if var_name == "_" || var_name.is_empty() {
                        continue;
                    }
                    if !var_name.chars().next().is_some_and(|c| c.is_lowercase() || c == '_') {
                        continue;
                    }
                    for m in non_allowed_modules.iter() {
                        if module == *m || module == format!("Elixir.{}", m) {
                            bindings.push((var_name.to_string(), m.to_string()));
                        }
                    }
                    for m in non_allowed_erlang.iter() {
                        if module == *m {
                            bindings.push((var_name.to_string(), m.to_string()));
                        }
                    }
                }
            }
        }
    }
}

fn extract_list_inner(s: &str) -> Option<Vec<String>> {
    let s = s.trim();
    if let Some(start) = s.find('[') {
        if let Some(end) = s.rfind(']') {
            if start < end {
                let inner = &s[start + 1..end];
                return Some(inner.split(',').map(|p| p.trim().to_string()).collect());
            }
        }
    }
    None
}

// v20 H-1 Fix 3: Catch-all for apply() with non-literal first argument
fn check_apply_nonliteral(code: &str) -> Option<Violation> {
    for line in code.lines() {
        let trimmed = line.trim();
        // Skip comments
        if trimmed.starts_with('#') {
            continue;
        }
        // Look for apply( or Kernel.apply( patterns
        let targets = ["apply(", "Kernel.apply("];
        for target in &targets {
            if let Some(idx) = trimmed.find(target) {
                let after_paren = &trimmed[idx + target.len()..];
                let first_arg = after_paren.split([',', ')']).next().unwrap_or("").trim();
                if first_arg.is_empty() {
                    continue;
                }
                // Literal alias: starts with uppercase
                if first_arg.chars().next().is_some_and(|c| c.is_uppercase()) {
                    continue;
                }
                // Literal atom: starts with :
                if first_arg.starts_with(':') {
                    continue;
                }
                // Non-literal target — flag it
                return Some(Violation {
                    rule: "KRAIT-ALW".to_string(),
                    explanation: "apply with non-literal module target is not allowed in generated code".to_string(),
                });
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn utf8_text<'a>(node: tree_sitter::Node<'a>, source: &'a [u8]) -> Option<&'a str> {
    let range = node.byte_range();
    if range.start >= source.len() || range.end > source.len() {
        return None;
    }
    std::str::from_utf8(&source[range.start..range.end]).ok()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_elixir(code: &str) -> Tree {
        let mut parser = tree_sitter::Parser::new();
        let lang = tree_sitter_elixir::LANGUAGE;
        parser.set_language(&lang.into()).ok();
        parser.parse(code, None).expect("test: parse code")
    }

    // --- Allowlisted modules pass ---

    #[test]
    fn enum_map_passes() {
        let code = r#"Enum.map(list, & &1)"#;
        let tree = parse_elixir(code);
        assert!(check_allowlist(code, &tree).is_none(), "Enum.map should pass");
    }

    #[test]
    fn string_upcase_passes() {
        let code = r#"String.upcase("hello")"#;
        let tree = parse_elixir(code);
        assert!(
            check_allowlist(code, &tree).is_none(),
            "String.upcase should pass"
        );
    }

    #[test]
    fn jason_encode_passes() {
        let code = r#"Jason.encode!(%{a: 1})"#;
        let tree = parse_elixir(code);
        assert!(
            check_allowlist(code, &tree).is_none(),
            "Jason.encode! should pass"
        );
    }

    #[test]
    fn erlang_math_passes() {
        let code = r#":math.pow(2, 10)"#;
        let tree = parse_elixir(code);
        assert!(
            check_allowlist(code, &tree).is_none(),
            ":math.pow should pass"
        );
    }

    #[test]
    fn erlang_lists_passes() {
        let code = r#":lists.reverse([1, 2, 3])"#;
        let tree = parse_elixir(code);
        assert!(
            check_allowlist(code, &tree).is_none(),
            ":lists.reverse should pass"
        );
    }

    #[test]
    fn krait_skills_skill_passes() {
        let code = r#"Krait.Skills.Skill.name()"#;
        let tree = parse_elixir(code);
        assert!(
            check_allowlist(code, &tree).is_none(),
            "Krait.Skills.Skill should pass"
        );
    }

    #[test]
    fn krait_skills_core_webfetch_passes() {
        let code =
            r#"Krait.Skills.Core.WebFetch.execute(%{"url" => "https://example.com"})"#;
        let tree = parse_elixir(code);
        assert!(
            check_allowlist(code, &tree).is_none(),
            "Krait.Skills.Core.WebFetch should pass"
        );
    }

    // --- Non-allowlisted modules rejected ---

    #[test]
    fn system_cmd_rejected() {
        let code = r#"System.cmd("ls", [])"#;
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), "System.cmd should be rejected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    #[test]
    fn file_read_rejected() {
        let code = r#"File.read("/etc/passwd")"#;
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), "File.read should be rejected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    #[test]
    fn os_cmd_rejected() {
        let code = r#":os.cmd(~c"ls")"#;
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), ":os.cmd should be rejected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    #[test]
    fn gen_tcp_rejected() {
        let code = r#":gen_tcp.connect(~c"localhost", 80, [])"#;
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), ":gen_tcp.connect should be rejected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    #[test]
    fn ets_new_rejected() {
        let code = r#":ets.new(:my_table, [:set])"#;
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), ":ets.new should be rejected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    #[test]
    fn code_eval_string_rejected() {
        let code = r#"Code.eval_string("1 + 1")"#;
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), "Code.eval_string should be rejected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    #[test]
    fn task_async_rejected() {
        let code = r#"Task.async(fn -> :ok end)"#;
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), "Task.async should be rejected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    #[test]
    fn process_info_rejected() {
        let code = r#"Process.info(self())"#;
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), "Process.info should be rejected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    // --- Indirection ---

    #[test]
    fn import_system_rejected() {
        let code = r#"import System"#;
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), "import System should be rejected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    #[test]
    fn alias_system_rejected() {
        let code = r#"alias System"#;
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), "alias System should be rejected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    #[test]
    fn apply_system_cmd_rejected() {
        let code = r#"apply(System, :cmd, ["ls", []])"#;
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), "apply(System, :cmd, ...) should be rejected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    #[test]
    fn defdelegate_to_os_rejected() {
        let code = r#"defdelegate my_cmd(cmd), to: :os"#;
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), "defdelegate to: :os should be rejected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    // --- Macro bans ---

    #[test]
    fn defmacro_rejected() {
        let code = "defmacro my_macro(expr) do\n  quote do: unquote(expr)\nend";
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), "defmacro should be rejected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    #[test]
    fn defmacrop_rejected() {
        let code = "defmacrop my_macro(expr) do\n  quote do: unquote(expr)\nend";
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), "defmacrop should be rejected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    // --- Kernel restrictions ---

    #[test]
    fn spawn_rejected() {
        let code = r#"spawn(fn -> :ok end)"#;
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), "spawn should be rejected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    #[test]
    fn send_rejected() {
        let code = r#"send(pid, :message)"#;
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), "send should be rejected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    #[test]
    fn self_rejected() {
        let code = r#"self()"#;
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), "self() should be rejected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    // --- Capture shorthand ---

    #[test]
    fn capture_system_cmd_rejected() {
        let code = r#"fun = &System.cmd/2"#;
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), "&System.cmd/2 should be rejected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    // --- Kernel.apply ---

    #[test]
    fn kernel_apply_system_rejected() {
        let code = r#"Kernel.apply(System, :cmd, ["ls", []])"#;
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), "Kernel.apply(System, ...) should be rejected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    #[test]
    fn kernel_apply_os_rejected() {
        let code = r#"Kernel.apply(:os, :cmd, [~c"ls"])"#;
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(
            v.is_some(),
            "Kernel.apply(:os, ...) should be rejected"
        );
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    #[test]
    fn apply_os_bare_atom_rejected() {
        let code = r#"apply(:os, :cmd, [~c"ls"])"#;
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), "apply(:os, ...) should be rejected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    // --- v17: C-1 Kernel.func() bypass ---

    #[test]
    fn kernel_spawn_rejected() {
        let code = r#"Kernel.spawn(fn -> :ok end)"#;
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), "Kernel.spawn should be rejected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    #[test]
    fn kernel_exit_rejected() {
        let code = r#"Kernel.exit(:normal)"#;
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), "Kernel.exit should be rejected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    #[test]
    fn kernel_div_passes() {
        let code = r#"Kernel.div(10, 3)"#;
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_none(), "Kernel.div should pass");
    }

    // --- v17: C-2 Compile hooks ---

    #[test]
    fn before_compile_rejected() {
        let code = "defmodule Evil do\n  @before_compile __MODULE__\nend";
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), "@before_compile should be rejected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    #[test]
    fn on_load_rejected() {
        let code = "defmodule Evil do\n  @on_load :init\n  def init, do: :ok\nend";
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), "@on_load should be rejected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    // --- v17: C-3 receive ---

    #[test]
    fn receive_block_rejected() {
        let code = "def spy do\n  receive do\n    msg -> msg\n  end\nend";
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), "receive should be rejected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    // --- v17: C-4 quote ---

    #[test]
    fn quote_block_rejected() {
        let code = "quote do\n  Enum.map([1], & &1)\nend";
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), "quote should be rejected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    // --- v17: C-5 Denied functions on allowed modules ---

    #[test]
    fn string_to_atom_rejected() {
        let code = r#"String.to_atom("System")"#;
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), "String.to_atom should be rejected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    #[test]
    fn stream_resource_rejected() {
        let code = r#"Stream.resource(fn -> init end, fn acc -> next end, fn acc -> close end)"#;
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), "Stream.resource should be rejected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    #[test]
    fn stream_map_passes() {
        let code = r#"Stream.map([1, 2, 3], & &1 * 2)"#;
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_none(), "Stream.map should pass");
    }

    // --- v17: C-6 Module attribute indirection ---

    #[test]
    fn module_attr_os_indirection_rejected() {
        let code = "defmodule Evil do\n  @target :os\n  def run, do: @target.cmd(~c\"ls\")\nend";
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), "@target :os indirection should be rejected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    // --- v17: C-7 Variable dispatch ---

    #[test]
    fn variable_dispatch_system_rejected() {
        let code = "def run do\n  m = System\n  m.cmd(\"ls\", [])\nend";
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), "m = System; m.cmd() should be rejected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    // --- v17: H-2 defdelegate paren form ---

    #[test]
    fn defdelegate_paren_os_rejected() {
        let code = r#"defdelegate(my_cmd(c), to: :os)"#;
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), "defdelegate(func, to: :os) should be rejected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    // --- v17: H-6 expanded Kernel functions ---

    #[test]
    fn binding_rejected() {
        let code = r#"binding()"#;
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), "binding() should be rejected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    #[test]
    fn dbg_rejected() {
        let code = r#"dbg(x)"#;
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), "dbg() should be rejected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    // --- v17: M-3 defprotocol/defimpl ---

    #[test]
    fn defprotocol_rejected() {
        let code = "defprotocol MyProtocol do\n  def render(data)\nend";
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), "defprotocol should be rejected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    #[test]
    fn defimpl_rejected() {
        let code = "defimpl MyProtocol, for: Map do\n  def render(data), do: inspect(data)\nend";
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), "defimpl should be rejected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    // --- v17: M-4 defoverridable ---

    #[test]
    fn defoverridable_rejected() {
        let code = "defoverridable [run: 0]";
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), "defoverridable should be rejected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    // --- v18: Stream.iterate/unfold ---

    #[test]
    fn stream_iterate_rejected() {
        let code = r#"Stream.iterate(0, &(&1 + 1))"#;
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), "Stream.iterate should be rejected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    #[test]
    fn stream_unfold_rejected() {
        let code = r#"Stream.unfold(5, fn 0 -> nil; n -> {n, n - 1} end)"#;
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), "Stream.unfold should be rejected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    // --- v19: M-6 broader receive/quote detection ---

    #[test]
    fn indented_receive_rejected() {
        let code = "def spy do\n    receive do\n      msg -> msg\n    end\nend";
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), "indented receive should be rejected");
    }

    #[test]
    fn receive_paren_form_rejected() {
        let code = "receive(do: (msg -> msg))";
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), "receive( form should be rejected");
    }

    #[test]
    fn quote_paren_do_form_rejected() {
        let code = "quote(do: Enum.map(list, & &1))";
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), "quote(do: ...) should be rejected");
    }

    #[test]
    fn comment_receive_allowed() {
        // A line starting with # that contains "receive do" should pass
        let code = "def run do\n  # receive do\n  Enum.map([], & &1)\nend";
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_none(), "commented receive should pass");
    }

    // --- v20 H-1: Bypass detection ---

    #[test]
    fn tuple_destructuring_bypass_rejected() {
        let code = "def run do\n  {mod, _} = {:os, :cmd}\n  mod.cmd(~c\"ls\")\nend";
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), "tuple destructuring os/cmd should be rejected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    #[test]
    fn tuple_destructuring_second_element_rejected() {
        let code = "def run do\n  {_, mod} = {:ok, System}\n  mod.cmd(\"ls\", [])\nend";
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), "tuple destructuring ok/System should be rejected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    #[test]
    fn list_destructuring_bypass_rejected() {
        let code = "def run do\n  [mod] = [System]\n  mod.cmd(\"ls\", [])\nend";
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), "list destructuring [System] should be rejected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    #[test]
    fn apply_with_variable_target_rejected() {
        let code = "def run(mod) do\n  apply(mod, :cmd, [~c\"ls\"])\nend";
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), "apply(var, ...) should be rejected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    #[test]
    fn apply_with_literal_enum_rejected_as_kernel() {
        // Bare `apply` is a denied kernel function, even with allowed module target
        let code = "def run do\n  apply(Enum, :map, [[1, 2], &(&1 * 2)])\nend";
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), "bare apply is a denied kernel function");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    #[test]
    fn apply_with_literal_erlang_atom_rejected_as_kernel() {
        // Bare `apply` is a denied kernel function, even with allowed erlang target
        let code = "def run do\n  apply(:math, :pow, [2, 10])\nend";
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), "bare apply is a denied kernel function");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    #[test]
    fn variable_to_apply_bypass_rejected() {
        let code = "def run do\n  x = :os\n  apply(x, :cmd, [~c\"ls\"])\nend";
        let tree = parse_elixir(code);
        let v = check_allowlist(code, &tree);
        assert!(v.is_some(), "x = :os; apply(x, ...) should be rejected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }
}
