//! KRAIT security rules for Rust code.
//!
//! Enforces KRAIT-001 through KRAIT-007 using tree-sitter-rust AST queries.
//! Note: Rust is compiled, so KRAIT-001 (eval) and KRAIT-005 (hot loading)
//! are largely N/A but we still check for unsafe patterns.

use tree_sitter::Tree;
use crate::rules::Violation;
use super::{LanguageRules, collect_strings_with_query, strings_match_immutable,
            strings_match_credentials, strings_match_krait_internals};

pub struct RustRules;

impl LanguageRules for RustRules {
    fn check_all(&self, code: &str, tree: &Tree) -> Option<Violation> {
        check_krait_002(code, tree)
            .or_else(|| check_krait_003(code, tree))
            .or_else(|| check_krait_004(code, tree))
            .or_else(|| check_krait_006(code, tree))
            .or_else(|| check_krait_007(code, tree))
            .or_else(|| check_forbidden_uses(code, tree))
    }

    fn language_id(&self) -> &'static str {
        "rust"
    }
}

fn lang() -> tree_sitter::Language {
    tree_sitter_rust::LANGUAGE.into()
}

fn collect_strings(code: &str, tree: &Tree) -> Vec<String> {
    let mut strings = collect_strings_with_query(
        code, tree, &lang(),
        r#"(string_literal (string_content) @s)"#,
    );
    // Also capture raw strings: r"..." and r#"..."#
    let raw_strings = collect_strings_with_query(
        code, tree, &lang(),
        r#"(raw_string_literal) @s"#,
    );
    strings.extend(raw_strings.iter().map(|s| {
        // Strip r" prefix and " suffix, or r#" and "#
        let trimmed = s.trim_start_matches('r').trim_start_matches('#').trim_start_matches('"');
        trimmed.trim_end_matches('"').trim_end_matches('#').to_string()
    }));
    strings
}

fn collect_use_paths(code: &str, tree: &Tree) -> Vec<String> {
    collect_strings_with_query(
        code, tree, &lang(),
        r#"(use_declaration argument: (scoped_identifier) @path)"#,
    )
}

// ---------------------------------------------------------------------------
// KRAIT-002: No raw shell (std::process::Command)
// ---------------------------------------------------------------------------

fn check_krait_002(code: &str, tree: &Tree) -> Option<Violation> {
    // std::process::Command
    if code.contains("std::process::Command") || code.contains("Command::new(") {
        return Some(Violation {
            rule: "KRAIT-002".into(),
            explanation: "Shell execution detected (std::process::Command)".into(),
        });
    }

    // process::exit
    if code.contains("process::exit") || code.contains("std::process::exit") {
        return Some(Violation {
            rule: "KRAIT-002".into(),
            explanation: "Process control detected (process::exit)".into(),
        });
    }

    let uses = collect_use_paths(code, tree);
    if uses.iter().any(|u| u.contains("std::process")) {
        return Some(Violation {
            rule: "KRAIT-002".into(),
            explanation: "Shell execution module imported (std::process)".into(),
        });
    }

    None
}

// ---------------------------------------------------------------------------
// KRAIT-003: No credential path access
// ---------------------------------------------------------------------------

fn check_krait_003(code: &str, tree: &Tree) -> Option<Violation> {
    let has_file_op = code.contains("std::fs::") || code.contains("fs::read")
        || code.contains("fs::write") || code.contains("fs::File")
        || code.contains("File::open") || code.contains("File::create");

    if !has_file_op {
        return None;
    }

    let strings = collect_strings(code, tree);
    if strings_match_credentials(&strings) {
        return Some(Violation {
            rule: "KRAIT-003".into(),
            explanation: "Credential path access detected".into(),
        });
    }
    None
}

// ---------------------------------------------------------------------------
// KRAIT-004: No network exfil
// ---------------------------------------------------------------------------

fn check_krait_004(code: &str, tree: &Tree) -> Option<Violation> {
    let uses = collect_use_paths(code, tree);

    // std::net
    if uses.iter().any(|u| u.contains("std::net")) || code.contains("std::net::") {
        return Some(Violation {
            rule: "KRAIT-004".into(),
            explanation: "Network module imported (std::net)".into(),
        });
    }

    // Common HTTP client crates
    let network_crates = ["reqwest", "hyper", "surf", "actix_web", "rocket", "warp", "axum"];
    for crate_name in &network_crates {
        if code.contains(&format!("{}::", crate_name)) || uses.iter().any(|u| u.starts_with(crate_name)) {
            return Some(Violation {
                rule: "KRAIT-004".into(),
                explanation: format!("Network crate used: {}", crate_name),
            });
        }
    }

    // tokio::net
    if code.contains("tokio::net") || uses.iter().any(|u| u.contains("tokio::net")) {
        return Some(Violation {
            rule: "KRAIT-004".into(),
            explanation: "Async network module imported (tokio::net)".into(),
        });
    }

    None
}

// ---------------------------------------------------------------------------
// KRAIT-006: No immutable path targeting
// ---------------------------------------------------------------------------

fn check_krait_006(code: &str, tree: &Tree) -> Option<Violation> {
    let strings = collect_strings(code, tree);

    if strings_match_immutable(&strings) {
        return Some(Violation {
            rule: "KRAIT-006".into(),
            explanation: "Immutable path targeting detected".into(),
        });
    }

    // format! evasion
    if (code.contains("format!(") || code.contains("Path::new(") || code.contains("PathBuf::from("))
        && strings.iter().any(|s| {
            super::IMMUTABLE_SEGMENTS.iter().any(|seg| s.contains(seg))
        })
    {
        return Some(Violation {
            rule: "KRAIT-006".into(),
            explanation: "Immutable path targeting detected (format/path evasion)".into(),
        });
    }

    None
}

// ---------------------------------------------------------------------------
// KRAIT-007: No recursive self-modification
// ---------------------------------------------------------------------------

fn check_krait_007(code: &str, tree: &Tree) -> Option<Violation> {
    let uses = collect_use_paths(code, tree);
    let strings = collect_strings(code, tree);

    // Check use paths for krait::* modules
    if uses.iter().any(|u| {
        let lower = u.to_lowercase();
        lower.starts_with("krait::") || lower.starts_with("krait_web::")
    }) {
        return Some(Violation {
            rule: "KRAIT-007".into(),
            explanation: "KRAIT internals import detected".into(),
        });
    }

    if strings_match_krait_internals(&strings) {
        return Some(Violation {
            rule: "KRAIT-007".into(),
            explanation: "KRAIT internals reference detected in string".into(),
        });
    }

    None
}

// ---------------------------------------------------------------------------
// Forbidden uses (allowlist)
// ---------------------------------------------------------------------------

const FORBIDDEN_MODULES: &[&str] = &[
    "std::process", "std::net", "std::fs", "std::env",
    "tokio::net", "tokio::process", "tokio::fs",
    "reqwest", "hyper", "nix", "libc",
];

fn check_forbidden_uses(code: &str, tree: &Tree) -> Option<Violation> {
    let uses = collect_use_paths(code, tree);

    for module in FORBIDDEN_MODULES {
        if uses.iter().any(|u| u.starts_with(module) || u == module) {
            return Some(Violation {
                rule: "KRAIT-ALW".into(),
                explanation: format!("Forbidden module imported: {}", module),
            });
        }
    }

    // Also check direct usage without use statement
    for module in FORBIDDEN_MODULES {
        if code.contains(&format!("{}::", module)) {
            return Some(Violation {
                rule: "KRAIT-ALW".into(),
                explanation: format!("Forbidden module used: {}", module),
            });
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_rust(code: &str) -> Tree {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&lang()).expect("test: set Rust language");
        parser.parse(code, None).expect("test: parse Rust code")
    }

    // --- KRAIT-002 ---

    #[test]
    fn rust_002_command_new() {
        let code = r#"use std::process::Command;
fn attack() { Command::new("ls").output(); }"#;
        let tree = parse_rust(code);
        let v = RustRules.check_all(code, &tree);
        assert!(v.is_some());
        assert_eq!(v.expect("test").rule, "KRAIT-002");
    }

    #[test]
    fn rust_002_safe_passes() {
        let code = "fn hello() -> String { String::from(\"hello\") }";
        let tree = parse_rust(code);
        assert!(RustRules.check_all(code, &tree).is_none());
    }

    // --- KRAIT-003 ---

    #[test]
    fn rust_003_credential_read() {
        let code = r#"fn steal() { std::fs::read_to_string("~/.ssh/id_rsa"); }"#;
        let tree = parse_rust(code);
        let v = check_krait_003(code, &tree);
        assert!(v.is_some());
        assert_eq!(v.expect("test").rule, "KRAIT-003");
    }

    // --- KRAIT-004 ---

    #[test]
    fn rust_004_std_net() {
        let code = "use std::net::TcpStream;";
        let tree = parse_rust(code);
        let v = check_krait_004(code, &tree);
        assert!(v.is_some());
        assert_eq!(v.expect("test").rule, "KRAIT-004");
    }

    #[test]
    fn rust_004_reqwest() {
        let code = "use reqwest::Client;";
        let tree = parse_rust(code);
        let v = check_krait_004(code, &tree);
        assert!(v.is_some());
        assert_eq!(v.expect("test").rule, "KRAIT-004");
    }

    // --- KRAIT-006 ---

    #[test]
    fn rust_006_immutable_path() {
        let code = r#"fn attack() { let p = "native/krait_analyzer/src/lib.rs"; }"#;
        let tree = parse_rust(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some());
        assert_eq!(v.expect("test").rule, "KRAIT-006");
    }

    #[test]
    fn rust_006_safe_path_passes() {
        let code = r#"fn safe() { let p = "lib/skills/tool.rs"; }"#;
        let tree = parse_rust(code);
        assert!(check_krait_006(code, &tree).is_none());
    }

    // --- KRAIT-007 ---

    #[test]
    fn rust_007_krait_import() {
        let code = "use krait::evolution::workspace;";
        let tree = parse_rust(code);
        let v = check_krait_007(code, &tree);
        assert!(v.is_some());
        assert_eq!(v.expect("test").rule, "KRAIT-007");
    }

    // --- Allowlist ---

    #[test]
    fn rust_alw_std_fs() {
        let code = "fn evil() { std::fs::read_to_string(\"file.txt\"); }";
        let tree = parse_rust(code);
        let v = check_forbidden_uses(code, &tree);
        assert!(v.is_some());
        assert_eq!(v.expect("test").rule, "KRAIT-ALW");
    }

    #[test]
    fn rust_alw_safe_passes() {
        let code = "use std::collections::HashMap;\nfn safe() { let m = HashMap::new(); }";
        let tree = parse_rust(code);
        assert!(check_forbidden_uses(code, &tree).is_none());
    }
}
