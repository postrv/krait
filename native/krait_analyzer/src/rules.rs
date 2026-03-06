use tree_sitter::{Query, QueryCursor, Tree};
use streaming_iterator::StreamingIterator;

pub struct Violation {
    pub rule: String,
    pub explanation: String,
}

/// Check all KRAIT security rules using tree-sitter AST queries.
///
/// For Elixir: the allowlist is authoritative for module-level checks (KRAIT-ALW).
/// KRAIT-006 (immutable paths) and KRAIT-007 (self-modification) are
/// orthogonal to the allowlist and run separately.
///
/// For other languages: dispatches to per-language rule implementations.
///
/// Returns the first violation found, or None if the code is clean.
pub fn check_all(code: &str, tree: &Tree, language: &str) -> Option<Violation> {
    match language {
        "elixir" => check_all_elixir(code, tree),
        other => {
            if let Some(rules) = crate::lang::get_rules(other) {
                rules.check_all(code, tree)
            } else {
                // Fail-closed: unknown language → violation
                Some(Violation {
                    rule: "KRAIT-ERR".to_string(),
                    explanation: format!("Unsupported language for security analysis: {}", other),
                })
            }
        }
    }
}

/// Elixir-specific rule checking (existing behavior, unchanged).
fn check_all_elixir(code: &str, tree: &Tree) -> Option<Violation> {
    // Primary mode: allowlist runs first and catches any non-allowlisted module as KRAIT-ALW.
    // KRAIT-006 (immutable paths) and KRAIT-007 (self-modification) only run if allowlist passes.
    if let Some(alw) = crate::allowlist::check_allowlist(code, tree) {
        return Some(Violation {
            rule: alw.rule,
            explanation: alw.explanation,
        });
    }

    // Allowlist passed — only run path-based, credential, and self-modification checks
    // (KRAIT-003, KRAIT-006, KRAIT-007 are orthogonal to module allowlisting)
    check_krait_003(code, tree)
        .or_else(|| check_krait_006(code, tree))
        .or_else(|| check_krait_007(code, tree))
}

// ---------------------------------------------------------------------------
// KRAIT-003: Credential path access (compound: file op + credential path)
// ---------------------------------------------------------------------------

/// Credential path prefixes/patterns
const CREDENTIAL_PATHS: &[&str] = &[
    "~/.ssh", "~/.aws", "~/.config/gcloud", "~/.gnupg", ".env",
    "credentials", "secrets", "~/.kube/config", "~/.docker/config.json",
    "~/.netrc", "~/.git-credentials", "/etc/shadow", "/proc/self/environ",
    "/proc/self/cmdline", "/proc/self/maps", "/proc/self/exe", "/proc/self/fd",
    "~/.npmrc", "~/.pypirc", "~/.m2/settings.xml", "~/.vault-token",
    "~/.gradle/gradle.properties", "/etc/passwd", "~/.bash_history",
    "~/.zsh_history", "terraform.tfstate", ".pgpass",
];

/// Credential path segments for split-path detection
const CREDENTIAL_SEGMENTS: &[&str] = &[
    "/.ssh/", "/.aws/", "/.gnupg/", "/.config/gcloud/", "/.kube/",
    "/.docker/", "/.netrc", "/.git-credentials", "/proc/self/",
    ".ssh", ".aws", ".gnupg", ".config/gcloud", ".kube", ".docker",
    ".netrc", ".git-credentials", ".npmrc", ".pypirc", ".m2/settings.xml",
    ".vault-token", ".gradle/gradle.properties", ".bash_history",
    ".zsh_history", "terraform.tfstate", ".pgpass",
];

/// File operation modules (Erlang)
const FILE_OP_ERLANG_MODULES: &[&str] = &[
    "file", "prim_file", "filelib", "ram_file",
];

/// KRAIT-003: Credential path access — file op + credential path in string literals
fn check_krait_003(code: &str, tree: &Tree) -> Option<Violation> {
    // Check for file operation calls (File.*, Path.*, :file.*, :prim_file.*, etc.)
    let has_file_op =
        has_dot_call(code, tree, "File", "read") ||
        has_dot_call(code, tree, "File", "read!") ||
        has_dot_call(code, tree, "File", "write") ||
        has_dot_call(code, tree, "File", "write!") ||
        has_dot_call(code, tree, "File", "open") ||
        has_dot_call(code, tree, "File", "stream!") ||
        has_dot_call(code, tree, "File", "cp") ||
        has_dot_call(code, tree, "File", "cp!") ||
        has_dot_call(code, tree, "File", "rename") ||
        has_dot_call(code, tree, "File", "rename!") ||
        has_dot_call(code, tree, "File", "rm") ||
        has_dot_call(code, tree, "File", "rm!") ||
        has_dot_call(code, tree, "File", "exists?") ||
        has_dot_call(code, tree, "File", "stat") ||
        has_dot_call(code, tree, "File", "stat!") ||
        has_dot_call(code, tree, "File", "lstat") ||
        has_dot_call(code, tree, "File", "lstat!") ||
        has_dot_call(code, tree, "File", "ls") ||
        has_dot_call(code, tree, "File", "ls!") ||
        has_dot_call(code, tree, "Path", "expand") ||
        has_dot_call(code, tree, "Path", "join") ||
        has_dot_call(code, tree, "Path", "wildcard") ||
        FILE_OP_ERLANG_MODULES.iter().any(|m| code.contains(&format!(":{}.", m)));

    if !has_file_op {
        return None;
    }

    let strings = collect_string_literals(code, tree);
    let has_credential = strings.iter().any(|s| {
        CREDENTIAL_PATHS.iter().any(|p| s.contains(p)) ||
        CREDENTIAL_SEGMENTS.iter().any(|seg| s.contains(seg))
    });

    if has_credential {
        return Some(Violation {
            rule: "KRAIT-003".to_string(),
            explanation: "Credential path access detected".to_string(),
        });
    }
    None
}

/// Immutable path segments used for evasion detection
const IMMUTABLE_SEGMENTS: &[&str] = &[
    "native/krait_analyzer",
    ".krait-immutable",
    "krait-rules.yaml",
    "krait-rules",
    "krait_analyzer",
    // v13: H1
    "_build",
    // v16: C-1/H-7 — supply chain paths (NOTE: ".git" excluded — substring of .github/.gitignore)
    "mix.exs",
    ".iex.exs",
    "config",
    "priv",
    ".github",
    "Dockerfile",
    "Makefile",
    "deps",
    ".tool-versions",
    "rel/",
];

/// KRAIT-006: No immutable path targeting — check string literals and evasion patterns
fn check_krait_006(code: &str, tree: &Tree) -> Option<Violation> {
    let full_patterns = [
        "native/krait_analyzer", ".krait-immutable", "krait-rules.yaml", "_build/",
        // v16: C-1/H-7 — supply chain paths
        "mix.exs", ".iex.exs", "config/", "priv/", ".github/",
        "dockerfile", "makefile",  // lowercase for case-insensitive match
        "deps/", ".git/", "rel/", ".gitignore", ".tool-versions",
    ];
    let strings = collect_string_literals(code, tree);

    // v13: M1 — case-insensitive primary match
    if strings
        .iter()
        .any(|s| {
            let lower = s.to_lowercase();
            full_patterns.iter().any(|p| lower.contains(p))
        })
    {
        return Some(Violation {
            rule: "KRAIT-006".to_string(),
            explanation: "Immutable path targeting detected".to_string(),
        });
    }

    // Evasion detection: Path.join, Enum.join, Enum.map_join with immutable segments in strings
    let has_join = has_dot_call(code, tree, "Path", "join")
        || has_dot_call(code, tree, "Enum", "join")
        || has_dot_call(code, tree, "Enum", "map_join")
        || has_dot_call(code, tree, "IO", "iodata_to_binary");

    if has_join {
        let has_segment = strings
            .iter()
            .any(|s| IMMUTABLE_SEGMENTS.iter().any(|seg| s.contains(seg)));
        if has_segment {
            return Some(Violation {
                rule: "KRAIT-006".to_string(),
                explanation: "Immutable path targeting detected (evasion via join/concat)".to_string(),
            });
        }
    }

    // Evasion detection: binary concat <> with immutable segments
    if code.contains("<>") {
        let has_segment = strings
            .iter()
            .any(|s| IMMUTABLE_SEGMENTS.iter().any(|seg| s.contains(seg)));
        if has_segment {
            return Some(Violation {
                rule: "KRAIT-006".to_string(),
                explanation: "Immutable path targeting detected (evasion via binary concat)".to_string(),
            });
        }
        // v14: H-3 — Fragment combination: individual literals matching forbidden segments
        let has_fragment = strings.iter().any(|s| {
            IMMUTABLE_SEGMENTS.iter().any(|seg| s == seg)
        });
        if has_fragment {
            return Some(Violation {
                rule: "KRAIT-006".to_string(),
                explanation: "Immutable path targeting detected (fragment combination evasion)".to_string(),
            });
        }
    }

    // Evasion detection: string interpolation #{} with partial immutable segments
    // e.g., "native/#{var}" where "native/" is a prefix of immutable paths
    if code.contains("#{") {
        let partial_segments: &[&str] = &[
            "native/", "krait_analyzer", ".krait-immutable",
            "krait-rules", "krait_analyzer/",
            // v16: C-1/H-7 — supply chain paths
            "config/", "priv/", ".github/", "deps/", ".git/", "rel/",
            "Dockerfile", "Makefile",
        ];
        let has_partial = strings
            .iter()
            .any(|s| partial_segments.iter().any(|seg| s.contains(seg)));
        if has_partial {
            return Some(Violation {
                rule: "KRAIT-006".to_string(),
                explanation: "Immutable path targeting detected (evasion via string interpolation)".to_string(),
            });
        }
    }

    // Evasion detection: runtime string construction methods
    // List.to_string, :erlang.list_to_binary, :binary.list_to_bin, Base.decode64/decode64!,
    // IO.chardata_to_string, String.Chars.to_string
    if has_runtime_string_construction(code, tree) {
        return Some(Violation {
            rule: "KRAIT-006".to_string(),
            explanation: "Immutable path targeting detected (runtime string construction evasion)".to_string(),
        });
    }

    // Integer sequence detection — catches binary literals and integer lists
    if has_suspicious_integer_sequence(code) {
        return Some(Violation {
            rule: "KRAIT-006".to_string(),
            explanation: "Immutable path targeting detected (integer sequence evasion)".to_string(),
        });
    }

    // v12: Phase 3 — :filename.join, :filelib.is_file, :string.concat evasion
    let has_erlang_path_op = has_atom_dot_call(code, tree, "filename", "join")
        || has_atom_dot_call(code, tree, "filename", "absname")
        || has_atom_dot_call(code, tree, "filelib", "is_file")
        || has_atom_dot_call(code, tree, "filelib", "is_dir")
        || has_atom_dot_call(code, tree, "filelib", "wildcard")
        || has_atom_dot_call(code, tree, "string", "concat");
    if has_erlang_path_op {
        let has_segment = strings
            .iter()
            .any(|s| IMMUTABLE_SEGMENTS.iter().any(|seg| s.contains(seg)));
        if has_segment {
            return Some(Violation {
                rule: "KRAIT-006".to_string(),
                explanation: "Immutable path targeting detected (erlang path operation evasion)"
                    .to_string(),
            });
        }
    }

    // v12: Phase 6 — String.replace / Regex.replace / Enum.reduce / :string.concat evasion
    let has_replace = has_dot_call(code, tree, "String", "replace")
        || has_dot_call(code, tree, "Regex", "replace")
        || has_dot_call(code, tree, "Enum", "reduce")
        // v15: M-1 — String.graphemes + Enum.flat_map_reduce
        || has_dot_call(code, tree, "String", "graphemes")
        || has_dot_call(code, tree, "Enum", "flat_map_reduce");
    if has_replace {
        let has_segment = strings
            .iter()
            .any(|s| IMMUTABLE_SEGMENTS.iter().any(|seg| s.contains(seg)));
        if has_segment {
            return Some(Violation {
                rule: "KRAIT-006".to_string(),
                explanation: "Immutable path targeting detected (string replacement evasion)"
                    .to_string(),
            });
        }
    }

    // v12: Phase 8 — case-insensitive KRAIT-006 evasion
    let has_downcase = has_dot_call(code, tree, "String", "downcase")
        || has_atom_dot_call(code, tree, "string", "lowercase")
        || has_atom_dot_call(code, tree, "string", "to_lower");
    if has_downcase {
        let has_case_segment = strings.iter().any(|s| {
            let lower = s.to_lowercase();
            IMMUTABLE_SEGMENTS.iter().any(|seg| lower.contains(seg))
        });
        if has_case_segment {
            return Some(Violation {
                rule: "KRAIT-006".to_string(),
                explanation: "Immutable path targeting detected (case-insensitive evasion)"
                    .to_string(),
            });
        }
    }

    // v13: Phase 8 — @external_resource with immutable path
    if code.contains("@external_resource") {
        let has_immutable_segment = strings.iter().any(|s| {
            let lower = s.to_lowercase();
            IMMUTABLE_SEGMENTS.iter().any(|seg| lower.contains(seg))
        });
        if has_immutable_segment {
            return Some(Violation {
                rule: "KRAIT-006".to_string(),
                explanation: "Immutable path targeting detected (@external_resource)".to_string(),
            });
        }
    }

    // v13: Phase 9 — advanced path evasion (Atom.to_string, String.reverse, etc.)
    let has_advanced_construction = has_dot_call(code, tree, "Atom", "to_string")
        || has_dot_call(code, tree, "String", "reverse")
        || has_dot_call(code, tree, "Enum", "flat_map")
        || has_dot_call(code, tree, "String", "slice");
    if has_advanced_construction {
        // Check for forbidden atom literals in the source
        let atom_patterns = [":krait_analyzer", ":native", ":krait_immutable", ":krait_rules", ":_build"];
        if atom_patterns.iter().any(|p| code.contains(p)) {
            return Some(Violation {
                rule: "KRAIT-006".to_string(),
                explanation: "Immutable path targeting detected (advanced path evasion)".to_string(),
            });
        }
        // Check for reversed immutable segments in strings
        let has_reversed = strings.iter().any(|s| {
            let reversed: String = s.chars().rev().collect();
            IMMUTABLE_SEGMENTS.iter().any(|seg| s.contains(seg) || reversed.contains(seg))
        });
        if has_reversed {
            return Some(Violation {
                rule: "KRAIT-006".to_string(),
                explanation: "Immutable path targeting detected (advanced path evasion)".to_string(),
            });
        }
    }

    None
}

/// KRAIT-007: No KRAIT internals tampering
fn check_krait_007(code: &str, tree: &Tree) -> Option<Violation> {
    let forbidden_prefixes = [
        "Krait.Evolution",
        "Krait.Analyzer",
        "Krait.Sandbox",
        "Krait.Brain",
        "Krait.Gateway",
        "Krait.Memory",
        "Krait.LLM",
        "Krait.Skills.Registry",
        "KraitWeb",
        "Krait.GitHub",
        "Krait.Repo",
    ];

    let aliases = collect_alias_references(code, tree);
    for alias in &aliases {
        if forbidden_prefixes.iter().any(|p| alias.starts_with(p)) {
            return Some(Violation {
                rule: "KRAIT-007".to_string(),
                explanation: "KRAIT internals tampering detected".to_string(),
            });
        }
    }
    // Quoted atom bypass: :"Elixir.Krait.Evolution.Workspace" etc. (C5 parity)
    for prefix in &forbidden_prefixes {
        // Match :"Elixir.PREFIX" or :"Elixir.PREFIX.anything"
        let exact_quoted = format!(":\"Elixir.{}\"", prefix);
        let sub_quoted = format!(":\"Elixir.{}.", prefix);
        if code.contains(&exact_quoted) || code.contains(&sub_quoted) {
            return Some(Violation {
                rule: "KRAIT-007".to_string(),
                explanation: "KRAIT internals tampering detected (quoted atom)".to_string(),
            });
        }
    }
    // v13: H3 — hex/unicode escape bypass in quoted atoms
    if code.contains("\\x") || code.contains("\\u{") {
        let resolved = resolve_unicode_escapes(code);
        let resolved_clean = strip_zero_width(&resolved);
        for prefix in &forbidden_prefixes {
            let exact_quoted = format!(":\"Elixir.{}\"", prefix);
            let sub_quoted = format!(":\"Elixir.{}.", prefix);
            if resolved_clean.contains(&exact_quoted) || resolved_clean.contains(&sub_quoted) {
                return Some(Violation {
                    rule: "KRAIT-007".to_string(),
                    explanation: "KRAIT internals tampering detected (escape bypass)".to_string(),
                });
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tree-sitter AST helpers using StreamingIterator
// ---------------------------------------------------------------------------

/// Check if an alias text matches the expected module name,
/// accounting for both "System" and "Elixir.System" forms (C1 fix)
fn alias_matches(mod_text: &str, module: &str) -> bool {
    mod_text == module || mod_text == format!("Elixir.{}", module)
}

/// Check for Module.function(...) dot calls in the AST
/// Also matches Elixir.Module.function(...) — the Elixir.* prefix form (C1)
fn has_dot_call(code: &str, tree: &Tree, module: &str, function: &str) -> bool {
    let query_str = r#"(call
        target: (dot
            left: (alias) @mod
            right: (identifier) @fn))"#;

    let query = match Query::new(&tree_sitter_elixir::LANGUAGE.into(), query_str) {
        Ok(q) => q,
        Err(_) => return false,
    };
    let mut cursor = QueryCursor::new();
    let bytes = code.as_bytes();
    let mut matches = cursor.matches(&query, tree.root_node(), bytes);
    while let Some(m) = matches.next() {
        let Some(cap0) = m.captures.first() else { continue };
        let Some(cap1) = m.captures.get(1) else { continue };
        // v12: Phase 10 — utf8_text_strict skip-on-failure
        let Some(mod_text) = utf8_text_strict(cap0.node, bytes) else { continue };
        let Some(fn_text) = utf8_text_strict(cap1.node, bytes) else { continue };
        if alias_matches(mod_text, module) && fn_text == function {
            return true;
        }
    }
    false
}

/// Check for :atom.function(...) erlang-style calls
fn has_atom_dot_call(code: &str, tree: &Tree, module: &str, function: &str) -> bool {
    let query_str = r#"(call
        target: (dot
            left: (atom) @mod
            right: (identifier) @fn))"#;

    let expected_mod = format!(":{}", module);

    let query = match Query::new(&tree_sitter_elixir::LANGUAGE.into(), query_str) {
        Ok(q) => q,
        Err(_) => return false,
    };
    let mut cursor = QueryCursor::new();
    let bytes = code.as_bytes();
    let mut matches = cursor.matches(&query, tree.root_node(), bytes);
    while let Some(m) = matches.next() {
        let Some(cap0) = m.captures.first() else { continue };
        let Some(cap1) = m.captures.get(1) else { continue };
        let Some(mod_text) = utf8_text_strict(cap0.node, bytes) else { continue };
        let Some(fn_text) = utf8_text_strict(cap1.node, bytes) else { continue };
        // v10: C1 — resolve hex/unicode escapes in atom text before comparison
        let mod_resolved = if mod_text.contains('\\') {
            resolve_unicode_escapes(mod_text)
        } else {
            String::new()
        };
        let mod_check = if mod_resolved.is_empty() { mod_text } else { mod_resolved.as_str() };
        // v12: Phase 9 — strip zero-width chars
        let mod_clean = strip_zero_width(mod_check);
        if (mod_check == expected_mod || mod_clean == expected_mod) && fn_text == function {
            return true;
        }
    }

    // v10: C1 — also check quoted_atom dot calls (:"\\xNN".func escape bypass)
    let quoted_query_str = r#"(call
        target: (dot
            left: (quoted_atom) @mod
            right: (identifier) @fn))"#;
    if let Ok(quoted_query) = Query::new(&tree_sitter_elixir::LANGUAGE.into(), quoted_query_str) {
        let mut cursor2 = QueryCursor::new();
        let mut matches2 = cursor2.matches(&quoted_query, tree.root_node(), bytes);
        while let Some(m) = matches2.next() {
            let Some(cap0) = m.captures.first() else { continue };
            let Some(cap1) = m.captures.get(1) else { continue };
            let Some(mod_text) = utf8_text_strict(cap0.node, bytes) else { continue };
            let Some(fn_text) = utf8_text_strict(cap1.node, bytes) else { continue };
            // Quoted atom: :"..." — resolve escapes and compare as :module
            if mod_text.starts_with(":\"") && mod_text.ends_with('"') && mod_text.len() > 3 {
                let inner = &mod_text[2..mod_text.len() - 1];
                let resolved_inner = resolve_unicode_escapes(inner);
                // v12: Phase 9 — strip zero-width chars
                let cleaned_inner = strip_zero_width(&resolved_inner);
                let resolved = format!(":{}", cleaned_inner);
                if resolved == expected_mod && fn_text == function {
                    return true;
                }
            }
        }
    }

    false
}

/// Collect all string literals from the AST (double-quoted strings, charlists, and sigils)
fn collect_string_literals(code: &str, tree: &Tree) -> Vec<String> {
    let mut strings: Vec<String> = Vec::new();

    // Double-quoted strings
    let query_str = r#"(string (quoted_content) @str)"#;
    if let Ok(query) = Query::new(&tree_sitter_elixir::LANGUAGE.into(), query_str) {
        let mut cursor = QueryCursor::new();
        let bytes = code.as_bytes();
        let mut matches = cursor.matches(&query, tree.root_node(), bytes);
        while let Some(m) = matches.next() {
            let Some(cap0) = m.captures.first() else { continue };
            if let Ok(s) = cap0.node.utf8_text(bytes) {
                strings.push(String::from(s));
            }
        }
    }

    // Charlists (single-quoted strings)
    let charlist_query = r#"(charlist (quoted_content) @str)"#;
    if let Ok(query) = Query::new(&tree_sitter_elixir::LANGUAGE.into(), charlist_query) {
        let mut cursor = QueryCursor::new();
        let bytes = code.as_bytes();
        let mut matches = cursor.matches(&query, tree.root_node(), bytes);
        while let Some(m) = matches.next() {
            let Some(cap0) = m.captures.first() else { continue };
            if let Ok(s) = cap0.node.utf8_text(bytes) {
                strings.push(String::from(s));
            }
        }
    }

    // Sigils (~s, ~S, ~c, ~C) — capture the quoted content inside sigils
    let sigil_query = r#"(sigil (quoted_content) @str)"#;
    if let Ok(query) = Query::new(&tree_sitter_elixir::LANGUAGE.into(), sigil_query) {
        let mut cursor = QueryCursor::new();
        let bytes = code.as_bytes();
        let mut matches = cursor.matches(&query, tree.root_node(), bytes);
        while let Some(m) = matches.next() {
            let Some(cap0) = m.captures.first() else { continue };
            if let Ok(s) = cap0.node.utf8_text(bytes) {
                strings.push(String::from(s));
            }
        }
    }

    strings
}

/// Collect all alias references from the AST
/// Strips Elixir. prefix for KRAIT-007 prefix matching (C1)
fn collect_alias_references(code: &str, tree: &Tree) -> Vec<String> {
    let query_str = r#"(alias) @alias"#;

    let query = match Query::new(&tree_sitter_elixir::LANGUAGE.into(), query_str) {
        Ok(q) => q,
        Err(_) => return Vec::new(),
    };
    let mut cursor = QueryCursor::new();
    let bytes = code.as_bytes();
    let mut aliases: Vec<String> = Vec::new();
    let mut matches = cursor.matches(&query, tree.root_node(), bytes);
    while let Some(m) = matches.next() {
        let Some(cap0) = m.captures.first() else { continue };
        if let Ok(s) = cap0.node.utf8_text(bytes) {
            // Store both the original and the Elixir.-stripped version
            aliases.push(String::from(s));
            if let Some(stripped) = s.strip_prefix("Elixir.") {
                aliases.push(String::from(stripped));
            }
        }
    }
    aliases
}

/// Check for runtime string construction methods that bypass literal detection
fn has_runtime_string_construction(code: &str, tree: &Tree) -> bool {
    // List.to_string(...) — integer list to string
    if has_dot_call(code, tree, "List", "to_string") {
        return true;
    }
    // :erlang.list_to_binary(...) — no legitimate use in skill code
    if has_atom_dot_call(code, tree, "erlang", "list_to_binary") {
        return true;
    }
    // :binary.list_to_bin(...) — erlang binary conversion
    if has_atom_dot_call(code, tree, "binary", "list_to_bin") {
        return true;
    }
    // Base.decode64!(...) or Base.decode64(...)
    if has_dot_call(code, tree, "Base", "decode64!") || has_dot_call(code, tree, "Base", "decode64") {
        return true;
    }
    // IO.chardata_to_string(...) — chardata conversion
    if has_dot_call(code, tree, "IO", "chardata_to_string") {
        return true;
    }
    // String.Chars.to_string(...) — protocol dispatch (M2)
    if code.contains("String.Chars.to_string") {
        return true;
    }
    // v14: H-4 — :unicode.characters_to_binary/list bypass
    if has_atom_dot_call(code, tree, "unicode", "characters_to_binary")
        || has_atom_dot_call(code, tree, "unicode", "characters_to_list")
    {
        return true;
    }
    false
}

/// Resolve unicode (\u{XXXX}) and hex (\xXX) escape sequences to actual chars (H7 fix)
fn resolve_unicode_escapes(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.peek() {
                Some(&'u') => {
                    chars.next(); // consume 'u'
                    if chars.peek() == Some(&'{') {
                        chars.next(); // consume '{'
                        let hex: String = chars.by_ref().take_while(|c| *c != '}').collect();
                        if let Ok(code_point) = u32::from_str_radix(&hex, 16) {
                            if let Some(c) = char::from_u32(code_point) {
                                result.push(c);
                                continue;
                            }
                        }
                        // Fallback: emit original sequence
                        result.push_str("\\u{");
                        result.push_str(&hex);
                        result.push('}');
                    } else {
                        result.push('\\');
                        result.push('u');
                    }
                }
                Some(&'x') => {
                    chars.next(); // consume 'x'
                    // Handle both \xXX and \x{XX} brace-delimited forms (M1 fix)
                    if chars.peek() == Some(&'{') {
                        chars.next(); // consume '{'
                        let hex: String =
                            chars.by_ref().take_while(|c| *c != '}').collect();
                        if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                            result.push(byte as char);
                            continue;
                        }
                        // Fallback: emit original sequence
                        result.push_str("\\x{");
                        result.push_str(&hex);
                        result.push('}');
                    } else {
                        let hex: String = chars.by_ref().take(2).collect();
                        if hex.len() == 2 {
                            if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                                result.push(byte as char);
                                continue;
                            }
                        }
                        result.push('\\');
                        result.push('x');
                        result.push_str(&hex);
                    }
                }
                _ => {
                    result.push('\\');
                }
            }
        } else {
            result.push(ch);
        }
    }
    result
}

/// Strip zero-width Unicode characters that can bypass atom matching
fn strip_zero_width(input: &str) -> String {
    if !input.contains('\u{200B}')
        && !input.contains('\u{200C}')
        && !input.contains('\u{200D}')
        && !input.contains('\u{FEFF}')
        && !input.contains('\u{00AD}')
    {
        return input.to_string();
    }
    input
        .chars()
        .filter(|c| {
            !matches!(
                c,
                '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}' | '\u{00AD}'
            )
        })
        .collect()
}

/// Strict UTF-8 text extraction — returns None instead of empty string on failure
fn utf8_text_strict<'a>(node: tree_sitter::Node<'a>, source: &'a [u8]) -> Option<&'a str> {
    node.utf8_text(source).ok()
}

/// Check for suspicious integer sequences in the source code that could decode to forbidden paths.
/// Handles decimal, hex (0xFF), octal (0o77), and binary (0b1010) notation.
fn has_suspicious_integer_sequence(code: &str) -> bool {
    let chars: Vec<char> = code.chars().collect();
    let len = chars.len();
    let mut numbers: Vec<u8> = Vec::new();
    let mut i = 0;

    while i < len {
        let ch = chars[i];

        // Try to parse hex/octal/binary prefixed numbers: 0xFF, 0o77, 0b1010
        if ch == '0' && i + 1 < len {
            match chars[i + 1] {
                'x' | 'X' => {
                    i += 2;
                    let start = i;
                    while i < len && chars[i].is_ascii_hexdigit() {
                        i += 1;
                    }
                    if i > start {
                        let hex_str: String = chars[start..i].iter().collect();
                        if let Ok(val) = u32::from_str_radix(&hex_str, 16) {
                            if val <= 255 {
                                numbers.push(val as u8);
                            } else {
                                check_and_reset_sequence(&mut numbers);
                            }
                        }
                    }
                    continue;
                }
                'o' | 'O' => {
                    i += 2;
                    let start = i;
                    while i < len && chars[i] >= '0' && chars[i] <= '7' {
                        i += 1;
                    }
                    if i > start {
                        let oct_str: String = chars[start..i].iter().collect();
                        if let Ok(val) = u32::from_str_radix(&oct_str, 8) {
                            if val <= 255 {
                                numbers.push(val as u8);
                            } else {
                                check_and_reset_sequence(&mut numbers);
                            }
                        }
                    }
                    continue;
                }
                'b' | 'B' => {
                    i += 2;
                    let start = i;
                    while i < len && (chars[i] == '0' || chars[i] == '1') {
                        i += 1;
                    }
                    if i > start {
                        let bin_str: String = chars[start..i].iter().collect();
                        if let Ok(val) = u32::from_str_radix(&bin_str, 2) {
                            if val <= 255 {
                                numbers.push(val as u8);
                            } else {
                                check_and_reset_sequence(&mut numbers);
                            }
                        }
                    }
                    continue;
                }
                _ => {} // Fall through to decimal parsing
            }
        }

        if ch.is_ascii_digit() {
            // Decimal number
            let mut num: u32 = ch as u32 - '0' as u32;
            i += 1;
            while i < len && chars[i].is_ascii_digit() {
                num = num * 10 + (chars[i] as u32 - '0' as u32);
                i += 1;
            }
            if num <= 255 {
                numbers.push(num as u8);
            } else {
                check_and_reset_sequence(&mut numbers);
            }
            continue;
        }

        // Separators that can appear between numbers in a list/binary
        if ch == ',' || ch == ' ' || ch == '\n' || ch == '\r' || ch == '\t'
            || ch == '[' || ch == '<' || ch == '_'
        {
            i += 1;
            continue;
        }

        // Non-separator, non-digit — check and reset
        if check_sequence_match(&numbers) {
            return true;
        }
        numbers.clear();
        i += 1;
    }

    // Check final sequence
    check_sequence_match(&numbers)
}

/// Helper: check if collected bytes match any forbidden segment, then clear
fn check_and_reset_sequence(numbers: &mut Vec<u8>) {
    // Don't check here — just clear (over-255 value breaks the sequence)
    numbers.clear();
}

/// Helper: check if a byte sequence contains any immutable segment
fn check_sequence_match(numbers: &[u8]) -> bool {
    if numbers.len() > 3 {
        let binary = String::from_utf8_lossy(numbers);
        if IMMUTABLE_SEGMENTS.iter().any(|seg| binary.contains(seg)) {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser;

    fn parse_elixir(code: &str) -> Tree {
        match parser::parse(code, "elixir") {
            Ok(tree) => tree,
            Err(_) => {
                // For malformed code, we still need a tree
                let mut p = tree_sitter::Parser::new();
                p.set_language(&tree_sitter_elixir::LANGUAGE.into()).ok();
                p.parse(code, None).expect("test: parse code")
            }
        }
    }

    // --- Task 13: Bounds-check safety ---

    #[test]
    fn empty_code_no_panic() {
        let tree = parse_elixir("");
        assert!(check_all("", &tree, "elixir").is_none());
    }

    #[test]
    fn malformed_code_no_panic() {
        let code = "defmodule do end";
        let tree = parse_elixir(code);
        // Should not panic, result doesn't matter
        let _ = check_all(code, &tree, "elixir");
    }

    #[test]
    fn krait_alw_code_eval_string() {
        let code = r#"Code.eval_string("1 + 1")"#;
        let tree = parse_elixir(code);
        let v = check_all(code, &tree, "elixir");
        assert!(v.is_some());
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    // --- Task 14: KRAIT-006 evasion detection ---

    #[test]
    fn krait_alw_file_write_immutable_path() {
        let code = r#"File.write!("native/krait_analyzer/src/lib.rs", evil)"#;
        let tree = parse_elixir(code);
        let v = check_all(code, &tree, "elixir");
        assert!(v.is_some());
        // File module is not on the allowlist — KRAIT-ALW fires before KRAIT-006
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    #[test]
    fn krait_006_binary_concat_evasion() {
        let code = r#"path = "native/" <> "krait_analyzer""#;
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some());
        assert!(v.expect("test: violation expected").explanation.contains("evasion"));
    }

    #[test]
    fn krait_006_path_join_evasion() {
        let code = r#"Path.join(["native", "krait_analyzer"])"#;
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some());
        assert!(v.expect("test: violation expected").explanation.contains("evasion"));
    }

    #[test]
    fn krait_006_enum_join_evasion() {
        let code = r#"Enum.join(["native/", "krait_analyzer"], "")"#;
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some());
        assert!(v.expect("test: violation expected").explanation.contains("evasion"));
    }

    #[test]
    fn krait_006_clean_code_passes() {
        let code = r#"
defmodule MySkill do
  def execute(args) do
    path = Path.join(["lib", "skills", "my_skill.ex"])
    File.write!(path, "hello")
  end
end
"#;
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_none());
    }

    // --- Task 25: String interpolation evasion ---

    #[test]
    fn krait_006_interpolation_evasion_native() {
        let code = r#"path = "native/#{var}""#;
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some());
        assert!(v.expect("test: violation expected").explanation.contains("interpolation"));
    }

    #[test]
    fn krait_006_charlist_evasion() {
        let code = r#"path = 'native/krait_analyzer'"#;
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some(), "charlist should be detected by KRAIT-006");
    }

    #[test]
    fn krait_006_sigil_evasion() {
        let code = r#"path = ~s(native/krait_analyzer)"#;
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some(), "sigil ~s should be detected by KRAIT-006");
    }

    #[test]
    fn krait_006_interpolation_evasion_krait_analyzer() {
        let code = r#"File.write!("krait_analyzer/#{file}", data)"#;
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some());
        assert!(v.expect("test: violation expected").explanation.contains("interpolation"));
    }

    // --- Integer sequence detection ---

    #[test]
    fn krait_006_binary_literal_integer_sequence() {
        let code = r#"path = <<110, 97, 116, 105, 118, 101, 47, 107, 114, 97, 105, 116, 95, 97, 110, 97, 108, 121, 122, 101, 114>>"#;
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some(), "Binary integer sequence should be detected by KRAIT-006");
    }

    #[test]
    fn krait_006_integer_list_sequence() {
        let code = r#"path = [107, 114, 97, 105, 116, 95, 97, 110, 97, 108, 121, 122, 101, 114]"#;
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some(), "Integer list decoding to krait_analyzer should be detected by KRAIT-006");
    }

    #[test]
    fn krait_006_binary_list_to_bin_evasion() {
        let code = r#":binary.list_to_bin([110, 97, 116, 105, 118, 101])"#;
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some(), ":binary.list_to_bin should be detected by KRAIT-006");
    }

    #[test]
    fn krait_006_io_chardata_to_string_evasion() {
        let code = r#"IO.chardata_to_string([110, 97, 116, 105, 118, 101])"#;
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some(), "IO.chardata_to_string should be detected by KRAIT-006");
    }

    #[test]
    fn krait_006_innocent_integer_list_passes() {
        let code = r#"result = [72, 101, 108, 108, 111]"#;
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_none(), "Innocent integer list should pass KRAIT-006");
    }

    // --- F-4: Integer list construction bypass ---

    #[test]
    fn krait_006_list_to_string_evasion() {
        let code = r#"path = List.to_string([110, 97, 116, 105, 118, 101])"#;
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some(), "List.to_string should be detected by KRAIT-006");
        assert!(v.expect("test: violation expected").explanation.contains("runtime string construction"));
    }

    #[test]
    fn krait_006_erlang_list_to_binary_evasion() {
        let code = r#"path = :erlang.list_to_binary([110, 97, 116])"#;
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some(), ":erlang.list_to_binary should be detected by KRAIT-006");
    }

    #[test]
    fn krait_006_base_decode64_evasion() {
        let code = r#"path = Base.decode64!("bmF0aXZl")"#;
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some(), "Base.decode64! should be detected by KRAIT-006");
    }

    // --- Phase 7: v8 security hardening tests ---

    #[test]
    fn apply_with_quoted_elixir_system() {
        let code = r#"apply(:"Elixir.System", :cmd, ["whoami", []])"#;
        let tree = parse_elixir(code);
        let v = check_all(code, &tree, "elixir");
        assert!(v.is_some(), r#"apply(:"Elixir.System", ...) should be detected"#);
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    #[test]
    fn apply_with_quoted_elixir_code() {
        let code = r#"apply(:"Elixir.Code", :eval_string, ["1+1"])"#;
        let tree = parse_elixir(code);
        let v = check_all(code, &tree, "elixir");
        assert!(v.is_some(), r#"apply(:"Elixir.Code", ...) should be detected"#);
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    #[test]
    fn mix_shell_detected() {
        let code = r#"Mix.shell().cmd("whoami")"#;
        let tree = parse_elixir(code);
        let v = check_all(code, &tree, "elixir");
        assert!(v.is_some(), "Mix.shell() should be detected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    #[test]
    fn enum_map_join_evasion_detected() {
        let code = r#"Enum.map_join(["native", "krait_analyzer"], "/", & &1)"#;
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some(), "Enum.map_join evasion should be detected by KRAIT-006");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-006");
    }

    // --- Phase 1 (C1): Elixir.* prefix bypass detection ---

    #[test]
    fn elixir_prefix_system_cmd() {
        let code = r#"Elixir.System.cmd("whoami", [])"#;
        let tree = parse_elixir(code);
        let v = check_all(code, &tree, "elixir");
        assert!(v.is_some(), "Elixir.System.cmd should be detected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    #[test]
    fn elixir_prefix_code_eval() {
        let code = r#"Elixir.Code.eval_string("1+1")"#;
        let tree = parse_elixir(code);
        let v = check_all(code, &tree, "elixir");
        assert!(v.is_some(), "Elixir.Code.eval_string should be detected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    #[test]
    fn elixir_prefix_krait_internals() {
        let code = r#"Elixir.Krait.Analyzer.Quick.quick_validate("x", "elixir")"#;
        let tree = parse_elixir(code);
        let v = check_krait_007(code, &tree);
        assert!(v.is_some(), "Elixir.Krait.Analyzer should be detected by KRAIT-007");
    }

    #[test]
    fn elixir_prefix_string_upcase_passes() {
        let code = r#"Elixir.String.upcase("hello")"#;
        let tree = parse_elixir(code);
        let v = check_all(code, &tree, "elixir");
        assert!(v.is_none(), "Elixir.String.upcase should pass clean");
    }

    // --- Phase 5 (H7): Unicode escape bypass ---

    #[test]
    fn quoted_atom_unicode_escape() {
        let code = r#"apply(:"Elixir\u{002E}System", :cmd, ["whoami", []])"#;
        let tree = parse_elixir(code);
        let v = check_all(code, &tree, "elixir");
        assert!(v.is_some(), r#"Unicode escape in quoted atom should be detected"#);
    }

    #[test]
    fn quoted_atom_hex_escape() {
        let code = r#"apply(:"Elixir\x2ESystem", :cmd, ["whoami", []])"#;
        let tree = parse_elixir(code);
        let v = check_all(code, &tree, "elixir");
        assert!(v.is_some(), r#"Hex escape in quoted atom should be detected"#);
    }

    // --- Phase 7 (M2): Function.capture + String.Chars.to_string ---

    #[test]
    fn string_chars_to_string_detected() {
        let code = r#"String.Chars.to_string([110, 97, 116, 105, 118, 101])"#;
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some(), "String.Chars.to_string should be detected by KRAIT-006");
    }

    // --- resolve_unicode_escapes unit tests ---

    #[test]
    fn resolve_unicode_basic() {
        assert_eq!(resolve_unicode_escapes(r#"\u{002E}"#), ".");
        assert_eq!(resolve_unicode_escapes(r#"\x2E"#), ".");
        assert_eq!(
            resolve_unicode_escapes(r#"Elixir\u{002E}System"#),
            "Elixir.System"
        );
    }

    // --- M1: \x{XX} brace-form hex escape ---

    #[test]
    fn resolve_hex_brace_form() {
        assert_eq!(resolve_unicode_escapes(r#"\x{2E}"#), ".");
        assert_eq!(
            resolve_unicode_escapes(r#"Elixir\x{2E}System"#),
            "Elixir.System"
        );
    }

    // --- M3: Hex/octal integer sequences ---

    #[test]
    fn krait_006_hex_integer_sequence() {
        // "krait_analyzer" in hex: 0x6b=k, 0x72=r, 0x61=a, 0x69=i, 0x74=t, 0x5f=_,
        // 0x61=a, 0x6e=n, 0x61=a, 0x6c=l, 0x79=y, 0x7a=z, 0x65=e, 0x72=r
        let code =
            r#"path = <<0x6B, 0x72, 0x61, 0x69, 0x74, 0x5F, 0x61, 0x6E, 0x61, 0x6C, 0x79, 0x7A, 0x65, 0x72>>"#;
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(
            v.is_some(),
            "Hex integer sequence decoding to krait_analyzer should be detected"
        );
    }

    #[test]
    fn krait_006_octal_integer_sequence() {
        // "native" in octal: 0o156=n, 0o141=a, 0o164=t, 0o151=i, 0o166=v, 0o145=e
        // followed by 0o57=/, then krait_analyzer
        let code =
            r#"[0o156, 0o141, 0o164, 0o151, 0o166, 0o145, 0o57, 0o153, 0o162, 0o141, 0o151, 0o164, 0o137, 0o141, 0o156, 0o141, 0o154, 0o171, 0o172, 0o145, 0o162]"#;
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(
            v.is_some(),
            "Octal integer sequence decoding to native/krait_analyzer should be detected"
        );
    }

    // --- C1 parity: import/alias/use detection ---

    #[test]
    fn import_string_passes_clean() {
        let code = r#"import String"#;
        let tree = parse_elixir(code);
        let v = check_all(code, &tree, "elixir");
        assert!(v.is_none(), "import String should pass clean");
    }

    // --- C4 parity: sigil atom detection ---

    #[test]
    fn sigil_lists_passes_clean() {
        let code = r#"~w[lists reverse]a"#;
        let tree = parse_elixir(code);
        let v = check_all(code, &tree, "elixir");
        assert!(v.is_none(), "~w[lists]a should pass clean");
    }

    // --- H3 parity: Function.capture with atoms + &apply/3 ---

    #[test]
    fn function_capture_non_allowlisted() {
        // Function module is not on the allowlist — KRAIT-ALW fires
        let code = r#"Function.capture(String, :upcase, 1)"#;
        let tree = parse_elixir(code);
        let v = check_all(code, &tree, "elixir");
        assert!(
            v.is_some(),
            "Function module is not allowlisted"
        );
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    // --- H8 + C5 parity: expanded KRAIT-007 prefixes + quoted atoms ---

    #[test]
    fn krait_007_llm_prefix() {
        let code = r#"Krait.LLM.Claude.chat(msg)"#;
        let tree = parse_elixir(code);
        let v = check_krait_007(code, &tree);
        assert!(
            v.is_some(),
            "Krait.LLM should be detected by KRAIT-007"
        );
    }

    #[test]
    fn krait_007_krait_web() {
        let code = r#"KraitWeb.Endpoint.start()"#;
        let tree = parse_elixir(code);
        let v = check_krait_007(code, &tree);
        assert!(
            v.is_some(),
            "KraitWeb should be detected by KRAIT-007"
        );
    }

    #[test]
    fn krait_007_github() {
        let code = r#"Krait.GitHub.Client.create_pr()"#;
        let tree = parse_elixir(code);
        let v = check_krait_007(code, &tree);
        assert!(
            v.is_some(),
            "Krait.GitHub should be detected by KRAIT-007"
        );
    }

    #[test]
    fn krait_007_repo() {
        let code = r#"Krait.Repo.all(query)"#;
        let tree = parse_elixir(code);
        let v = check_krait_007(code, &tree);
        assert!(
            v.is_some(),
            "Krait.Repo should be detected by KRAIT-007"
        );
    }

    #[test]
    fn krait_007_quoted_atom_evolution() {
        let code = r#"apply(:"Elixir.Krait.Evolution.Workspace", :setup, [])"#;
        let tree = parse_elixir(code);
        let v = check_krait_007(code, &tree);
        assert!(
            v.is_some(),
            "quoted atom Krait.Evolution should be detected by KRAIT-007"
        );
    }

    #[test]
    fn krait_007_quoted_atom_analyzer() {
        let code = r#"mod = :"Elixir.Krait.Analyzer.Quick""#;
        let tree = parse_elixir(code);
        let v = check_krait_007(code, &tree);
        assert!(
            v.is_some(),
            "quoted atom Krait.Analyzer should be detected by KRAIT-007"
        );
    }

    #[test]
    fn krait_007_quoted_atom_string_passes() {
        let code = r#"mod = :"Elixir.String""#;
        let tree = parse_elixir(code);
        let v = check_krait_007(code, &tree);
        assert!(
            v.is_none(),
            "quoted atom String should pass KRAIT-007"
        );
    }

    // -----------------------------------------------------------------------
    // v10 Phase 1 (C1): NIF Hex Escape Atom Bypass
    // -----------------------------------------------------------------------

    #[test]
    fn v10_c1_no_escape_clean_passes() {
        // :lists should not be detected
        let code = r#"m = :lists"#;
        let tree = parse_elixir(code);
        let v = check_all(code, &tree, "elixir");
        assert!(v.is_none(), ":lists should pass clean");
    }

    // -----------------------------------------------------------------------
    // v10 Phase 2 (H1): ~W Uppercase Sigil Bypass
    // -----------------------------------------------------------------------
    // v10 Phase 3 (H2+H3): ETS/DETS/Mnesia + :application
    // -----------------------------------------------------------------------
    // v10 Phase 4 (H4): /proc/self/environ
    // -----------------------------------------------------------------------
    // v10 Phase 5 (M1): Credential Path Splitting
    // -----------------------------------------------------------------------
    // v10 Phase 6 (M4+M5): Node.spawn + Process inspection
    // -----------------------------------------------------------------------
    // v10 Phase 7 (L1): require directive gap
    // -----------------------------------------------------------------------
    // v12 Phase 1: strip_zero_width infrastructure
    // -----------------------------------------------------------------------

    #[test]
    fn v12_strip_zero_width_removes_chars() {
        assert_eq!(strip_zero_width("o\u{200B}s\u{200C}"), "os");
    }

    #[test]
    fn v12_strip_zero_width_noop_clean() {
        assert_eq!(strip_zero_width("os"), "os");
    }

    #[test]
    fn v12_utf8_text_strict_none_check() {
        // Verify the helper compiles and returns Some for valid nodes
        let code = "x = 1";
        let tree = parse_elixir(code);
        let root = tree.root_node();
        // root node should have valid UTF-8
        assert!(utf8_text_strict(root, code.as_bytes()).is_some());
    }

    // -----------------------------------------------------------------------
    // v12 Phase 2: Expanded File operations for KRAIT-003
    // -----------------------------------------------------------------------
    // v12 Phase 3: Forbidden Erlang modules
    // -----------------------------------------------------------------------

    #[test]
    fn v12_filename_join() {
        let code = r#":filename.join("native", "krait_analyzer")"#;
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some(), ":filename.join with immutable segment should be detected by KRAIT-006");
    }

    #[test]
    fn v12_string_concat() {
        let code = r#":string.concat("krait_analyzer", "/src")"#;
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some(), ":string.concat with immutable segment should be detected by KRAIT-006");
    }

    // -----------------------------------------------------------------------
    // v12 Phase 4: Mint submodule gaps
    // -----------------------------------------------------------------------
    // v12 Phase 5: KRAIT-005 module_attrs wiring
    // -----------------------------------------------------------------------
    // v12 Phase 6: String.replace / Regex.replace evasion
    // -----------------------------------------------------------------------

    #[test]
    fn v12_string_replace_evasion() {
        let code = r#"String.replace("safe", "safe", "krait_analyzer")"#;
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some(), "String.replace with immutable segment should be detected by KRAIT-006");
    }

    #[test]
    fn v12_regex_replace_evasion() {
        let code = r#"Regex.replace(~r/x/, "x", "krait_analyzer")"#;
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some(), "Regex.replace with immutable segment should be detected by KRAIT-006");
    }

    #[test]
    fn v12_enum_reduce_evasion() {
        let code = r#"Enum.reduce(["krait_analyzer"], "", fn c, acc -> acc <> c end)"#;
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some(), "Enum.reduce with immutable segment should be detected by KRAIT-006");
    }

    #[test]
    fn v12_filename_join_evasion() {
        let code = r#":filename.join(~c"native", ~c"krait_analyzer")"#;
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some(), ":filename.join with immutable segment should be detected");
    }

    // -----------------------------------------------------------------------
    // v12 Phase 7: KRAIT-003 interpolation evasion
    // -----------------------------------------------------------------------
    // v12 Phase 8: Case-insensitive KRAIT-006 evasion
    // -----------------------------------------------------------------------

    #[test]
    fn v12_downcase_evasion() {
        let code = r#"String.downcase("KRAIT_ANALYZER")"#;
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some(), "String.downcase with uppercase immutable should be detected");
    }

    #[test]
    fn v12_string_lowercase_evasion() {
        let code = r#":string.lowercase("KRAIT_ANALYZER")"#;
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some(), ":string.lowercase with uppercase immutable should be detected");
    }

    #[test]
    fn v12_downcase_clean_pass() {
        let code = r#"String.downcase("Hello World")"#;
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_none(), "String.downcase with safe string should pass");
    }

    // -----------------------------------------------------------------------
    // v12 Phase 9: Sigil delimiters + zero-width Unicode
    // -----------------------------------------------------------------------
    // v13 Phase 1: NIF apply/defdelegate rewrite tests (H9, M2)
    // -----------------------------------------------------------------------
    // v13 Phase 2: Dangerous Erlang module expansion (C1-C5)
    // -----------------------------------------------------------------------

    // KRAIT-001 modules

    // KRAIT-002 modules

    // KRAIT-004 modules

    // KRAIT-005 modules

    // -----------------------------------------------------------------------
    // v13 Phase 3: Tesla + Mojito HTTP client detection (H5)
    // -----------------------------------------------------------------------
    // v13 Phase 4: _build/ path + case-insensitive match (H1, M1)
    // -----------------------------------------------------------------------

    #[test]
    fn v13_build_dir_string_literal() {
        let code = r#"File.write!("_build/prod/lib/krait/ebin/mod.beam", payload)"#;
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some(), "_build/ in string literal should be detected by KRAIT-006");
    }

    #[test]
    fn v13_build_dir_dev_path() {
        let code = r#"File.write!("_build/dev/lib/krait/ebin/Elixir.Krait.beam", evil)"#;
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some(), "_build/dev path should be detected by KRAIT-006");
    }

    #[test]
    fn v13_uppercase_native() {
        let code = r#"File.write!("NATIVE/KRAIT_ANALYZER/src/evil.rs", payload)"#;
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some(), "NATIVE/KRAIT_ANALYZER uppercase should be detected by KRAIT-006");
    }

    #[test]
    fn v13_mixed_case_native() {
        let code = r#"File.write!("Native/Krait_Analyzer/src/evil.rs", payload)"#;
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some(), "Native/Krait_Analyzer mixed case should be detected by KRAIT-006");
    }

    // -----------------------------------------------------------------------
    // v13 Phase 5: Charlist credential/immutable path detection (H2)
    // -----------------------------------------------------------------------

    #[test]
    fn v13_charlist_immutable_path() {
        let code = r#"path = ~c"native/krait_analyzer""#;
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some(), "charlist ~c\"native/krait_analyzer\" should be detected by KRAIT-006");
    }

    // -----------------------------------------------------------------------
    // v13 Phase 6: NIF KRAIT-007 hex/unicode escape bypass (H3)
    // -----------------------------------------------------------------------

    #[test]
    fn v13_krait007_hex_escape() {
        let code = r#":"Elixir.\x4b\x72\x61\x69\x74.Evolution""#;
        let tree = parse_elixir(code);
        let v = check_krait_007(code, &tree);
        assert!(v.is_some(), "hex-escaped Krait in quoted atom should be detected by KRAIT-007");
    }

    #[test]
    fn v13_krait007_unicode_escape() {
        let code = r#":"Elixir.\u{004b}\u{0072}\u{0061}\u{0069}\u{0074}.Evolution""#;
        let tree = parse_elixir(code);
        let v = check_krait_007(code, &tree);
        assert!(v.is_some(), "unicode-escaped Krait in quoted atom should be detected by KRAIT-007");
    }

    #[test]
    fn v13_krait007_escape_clean() {
        // \x53\x74\x72\x69\x6e\x67 = "String" — not a Krait module
        let code = r#":"Elixir.\x53\x74\x72\x69\x6e\x67""#;
        let tree = parse_elixir(code);
        let v = check_krait_007(code, &tree);
        assert!(v.is_none(), "hex-escaped String should pass clean");
    }

    // -----------------------------------------------------------------------
    // v13 Phase 7: NIF KRAIT-005 Function.capture + @attr parity (H7, H8)
    // -----------------------------------------------------------------------
    // v13 Phase 8: Metaprogramming escape hatches (H4)
    // -----------------------------------------------------------------------

    #[test]
    fn v13_external_resource_immutable() {
        let code = "@external_resource \"native/krait_analyzer/src/rules.rs\"\ndef attack, do: File.read!(@external_resource)";
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some(), "@external_resource with immutable path should be detected by KRAIT-006");
    }

    // -----------------------------------------------------------------------
    // v13 Phase 9: KRAIT-006 advanced path evasion (H6)
    // -----------------------------------------------------------------------

    #[test]
    fn v13_atom_to_string_evasion() {
        let code = "path = Atom.to_string(:native) <> \"/\" <> Atom.to_string(:krait_analyzer)\nFile.write!(path, \"hacked\")";
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some(), "Atom.to_string path construction should be detected by KRAIT-006");
    }

    #[test]
    fn v13_string_reverse_evasion() {
        let code = "path = String.reverse(\"rezylana_tiark/evitan\")\nFile.write!(path, \"hacked\")";
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some(), "String.reverse of immutable path should be detected by KRAIT-006");
    }

    #[test]
    fn v13_flat_map_join_evasion() {
        let code = "parts = Enum.flat_map([:krait_analyzer], fn a -> [Atom.to_string(a)] end)\npath = Enum.join(parts, \"/\")\nFile.write!(path, \"hacked\")";
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some(), "Enum.flat_map + join evasion should be detected by KRAIT-006");
    }

    #[test]
    fn v13_atom_safe_passes() {
        let code = "name = Atom.to_string(:hello)\nIO.puts(name)";
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_none(), "Atom.to_string(:hello) should pass clean");
    }

    // --- v14: Security hardening tests ---

    #[test]
    fn v14_unicode_characters_to_binary_detected() {
        let code = r#":unicode.characters_to_binary([110, 97, 116])"#;
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some(), ":unicode.characters_to_binary should be detected by KRAIT-006");
    }

    // ===========================================================================
    // v15 security hardening tests
    // --- Phase 6: M-1 String.graphemes evasion → KRAIT-006 ---

    #[test]
    fn v15_string_graphemes_evasion() {
        let code = r#"chars = String.graphemes("krait_analyzer"); Enum.join(chars)"#;
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some(), "String.graphemes with immutable segment should be detected by KRAIT-006");
    }

    #[test]
    fn v15_enum_flat_map_reduce_evasion() {
        let code = r#"Enum.flat_map_reduce(["krait_analyzer"], "", fn x, acc -> {[x], acc} end)"#;
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some(), "Enum.flat_map_reduce with immutable segment should be detected by KRAIT-006");
    }

    // =========================================================================
    // v16 security hardening tests
    // --- Phase 1: KRAIT-006 immutable path expansion ---

    #[test]
    fn v16_krait_006_mix_exs() {
        let code = r#"File.write("mix.exs", evil)"#;
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some(), "mix.exs should be detected by KRAIT-006");
    }

    #[test]
    fn v16_krait_006_config_dir() {
        let code = r#"File.read("config/prod.exs")"#;
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some(), "config/ should be detected by KRAIT-006");
    }

    #[test]
    fn v16_krait_006_dockerfile() {
        let code = r#"File.write("Dockerfile", payload)"#;
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some(), "Dockerfile should be detected by KRAIT-006");
    }

    #[test]
    fn v16_krait_006_github_dir() {
        let code = r#"File.read(".github/workflows/ci.yml")"#;
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some(), ".github/ should be detected by KRAIT-006");
    }

    #[test]
    fn v16_krait_006_deps_dir() {
        let code = r#"File.rm_rf("deps/")"#;
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some(), "deps/ should be detected by KRAIT-006");
    }

    #[test]
    fn v16_krait_006_git_dir() {
        let code = r#"File.read(".git/config")"#;
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some(), ".git/ should be detected by KRAIT-006");
    }

    #[test]
    fn v16_krait_006_priv_dir() {
        let code = r#"File.write("priv/static/evil.js", data)"#;
        let tree = parse_elixir(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some(), "priv/ should be detected by KRAIT-006");
    }

    // --- Phase 7: NIF comment stripping fix ---

    // --- v17: H-1 KRAIT-003 in NIF ---

    #[test]
    fn krait_003_file_read_credential() {
        let code = r#"File.read!("~/.ssh/id_rsa")"#;
        let tree = parse_elixir(code);
        // File is not on the allowlist → KRAIT-ALW fires before KRAIT-003
        let v = check_all(code, &tree, "elixir");
        assert!(v.is_some());
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

    #[test]
    fn krait_003_credential_path_detection() {
        // Test KRAIT-003 directly (bypassing KRAIT-ALW)
        let code = r#"File.read!("~/.ssh/id_rsa")"#;
        let tree = parse_elixir(code);
        let v = check_krait_003(code, &tree);
        assert!(v.is_some(), "File.read with credential path should trigger KRAIT-003");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-003");
    }

    #[test]
    fn krait_003_safe_path_passes() {
        let code = r#"File.read!("/tmp/safe.txt")"#;
        let tree = parse_elixir(code);
        let v = check_krait_003(code, &tree);
        assert!(v.is_none(), "File.read with safe path should pass KRAIT-003");
    }

    #[test]
    fn v16_apply_after_string_with_hash() {
        // H-6: apply(:os, :cmd, ...) after a string containing #
        // The naive stripping would strip the # and lose the apply call
        let code = r#""string with # inside" <> apply(:os, :cmd, [~c"pwd"])"#;
        let tree = parse_elixir(code);
        let v = check_all(code, &tree, "elixir");
        assert!(v.is_some(), "apply after string with # should still be detected");
        assert_eq!(v.expect("test: violation expected").rule, "KRAIT-ALW");
    }

}
