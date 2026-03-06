//! KRAIT security rules for Go code.
//!
//! Enforces KRAIT-001 through KRAIT-007 using tree-sitter-go AST queries.

use tree_sitter::Tree;
use crate::rules::Violation;
use super::{LanguageRules, collect_strings_with_query, strings_match_immutable,
            strings_match_credentials, strings_match_krait_internals};

pub struct GoRules;

impl LanguageRules for GoRules {
    fn check_all(&self, code: &str, tree: &Tree) -> Option<Violation> {
        check_krait_001(code, tree)
            .or_else(|| check_krait_002(code, tree))
            .or_else(|| check_krait_003(code, tree))
            .or_else(|| check_krait_004(code, tree))
            .or_else(|| check_krait_005(code, tree))
            .or_else(|| check_krait_006(code, tree))
            .or_else(|| check_krait_007(code, tree))
            .or_else(|| check_forbidden_imports(code, tree))
    }

    fn language_id(&self) -> &'static str {
        "go"
    }
}

fn lang() -> tree_sitter::Language {
    tree_sitter_go::LANGUAGE.into()
}

fn collect_strings(code: &str, tree: &Tree) -> Vec<String> {
    // Go string literals: "..." and `...` (raw strings)
    let mut strings = collect_strings_with_query(
        code, tree, &lang(),
        r#"(interpreted_string_literal) @s"#,
    );
    // Strip quotes from interpreted strings
    strings = strings.iter().map(|s| {
        s.trim_matches('"').to_string()
    }).collect();

    let raw_strings = collect_strings_with_query(
        code, tree, &lang(),
        r#"(raw_string_literal) @s"#,
    );
    strings.extend(raw_strings.iter().map(|s| {
        s.trim_matches('`').to_string()
    }));

    strings
}

fn collect_imports(code: &str, tree: &Tree) -> Vec<String> {
    let mut imports = collect_strings_with_query(
        code, tree, &lang(),
        r#"(import_spec path: (interpreted_string_literal) @path)"#,
    );
    // Strip quotes
    imports = imports.iter().map(|s| s.trim_matches('"').to_string()).collect();
    imports
}

// ---------------------------------------------------------------------------
// KRAIT-001: No code eval
// ---------------------------------------------------------------------------

fn check_krait_001(code: &str, tree: &Tree) -> Option<Violation> {
    let imports = collect_imports(code, tree);

    // reflect package — can be used for code eval via reflect.Call
    if imports.iter().any(|i| i == "reflect") {
        return Some(Violation {
            rule: "KRAIT-001".into(),
            explanation: "Reflection package imported (reflect)".into(),
        });
    }

    // plugin package — loads shared objects at runtime
    if imports.iter().any(|i| i == "plugin") {
        return Some(Violation {
            rule: "KRAIT-001".into(),
            explanation: "Plugin loading package imported (plugin)".into(),
        });
    }

    None
}

// ---------------------------------------------------------------------------
// KRAIT-002: No raw shell
// ---------------------------------------------------------------------------

fn check_krait_002(code: &str, tree: &Tree) -> Option<Violation> {
    let imports = collect_imports(code, tree);

    // os/exec package
    if imports.iter().any(|i| i == "os/exec") {
        return Some(Violation {
            rule: "KRAIT-002".into(),
            explanation: "Shell execution package imported (os/exec)".into(),
        });
    }

    // exec.Command usage
    if code.contains("exec.Command(") || code.contains("exec.CommandContext(") {
        return Some(Violation {
            rule: "KRAIT-002".into(),
            explanation: "Shell execution detected (exec.Command)".into(),
        });
    }

    // syscall package
    if imports.iter().any(|i| i == "syscall" || i == "golang.org/x/sys/unix") {
        return Some(Violation {
            rule: "KRAIT-002".into(),
            explanation: "Syscall package imported".into(),
        });
    }

    None
}

// ---------------------------------------------------------------------------
// KRAIT-003: No credential path access
// ---------------------------------------------------------------------------

fn check_krait_003(code: &str, tree: &Tree) -> Option<Violation> {
    let has_file_op = code.contains("os.Open") || code.contains("os.ReadFile")
        || code.contains("os.WriteFile") || code.contains("os.Create")
        || code.contains("ioutil.ReadFile") || code.contains("ioutil.WriteFile");

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

const NETWORK_PACKAGES: &[&str] = &[
    "net", "net/http", "net/rpc", "net/smtp", "net/url",
    "crypto/tls", "net/http/httputil",
];

fn check_krait_004(code: &str, tree: &Tree) -> Option<Violation> {
    let imports = collect_imports(code, tree);

    for pkg in NETWORK_PACKAGES {
        if imports.iter().any(|i| i == pkg) {
            return Some(Violation {
                rule: "KRAIT-004".into(),
                explanation: format!("Network package imported: {}", pkg),
            });
        }
    }

    // Common HTTP client libraries
    if imports.iter().any(|i| {
        i.contains("github.com/go-resty/resty")
            || i.contains("github.com/valyala/fasthttp")
            || i.contains("github.com/parnurzeal/gorequest")
    }) {
        return Some(Violation {
            rule: "KRAIT-004".into(),
            explanation: "Third-party HTTP client imported".into(),
        });
    }

    None
}

// ---------------------------------------------------------------------------
// KRAIT-005: No hot code loading
// ---------------------------------------------------------------------------

fn check_krait_005(code: &str, tree: &Tree) -> Option<Violation> {
    let imports = collect_imports(code, tree);

    if imports.iter().any(|i| i == "plugin") {
        return Some(Violation {
            rule: "KRAIT-005".into(),
            explanation: "Dynamic code loading detected (plugin)".into(),
        });
    }

    // go/ast, go/parser — AST manipulation
    if imports.iter().any(|i| i == "go/ast" || i == "go/parser") {
        return Some(Violation {
            rule: "KRAIT-005".into(),
            explanation: "AST manipulation package imported".into(),
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

    // fmt.Sprintf evasion
    if (code.contains("fmt.Sprintf") || code.contains("filepath.Join") || code.contains("path.Join"))
        && strings.iter().any(|s| {
            super::IMMUTABLE_SEGMENTS.iter().any(|seg| s.contains(seg))
        })
    {
        return Some(Violation {
            rule: "KRAIT-006".into(),
            explanation: "Immutable path targeting detected (path join/sprintf evasion)".into(),
        });
    }

    None
}

// ---------------------------------------------------------------------------
// KRAIT-007: No recursive self-modification
// ---------------------------------------------------------------------------

fn check_krait_007(code: &str, tree: &Tree) -> Option<Violation> {
    let imports = collect_imports(code, tree);
    let strings = collect_strings(code, tree);

    // Check imports for krait/* packages
    if imports.iter().any(|i| {
        let lower = i.to_lowercase();
        lower.contains("krait/") || lower.contains("krait_web")
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
// Forbidden imports (allowlist)
// ---------------------------------------------------------------------------

const FORBIDDEN_PACKAGES: &[&str] = &[
    "os", "os/exec", "syscall", "unsafe", "reflect", "plugin",
    "net", "net/http", "net/rpc", "net/smtp", "crypto/tls",
    "debug/elf", "debug/macho", "debug/pe", "debug/plan9obj",
    "runtime", "runtime/debug", "internal",
];

fn check_forbidden_imports(code: &str, tree: &Tree) -> Option<Violation> {
    let imports = collect_imports(code, tree);

    for pkg in FORBIDDEN_PACKAGES {
        if imports.iter().any(|i| i == pkg) {
            return Some(Violation {
                rule: "KRAIT-ALW".into(),
                explanation: format!("Forbidden package imported: {}", pkg),
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

    fn parse_go(code: &str) -> Tree {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&lang()).ok();
        parser.parse(code, None).expect("test: parse Go code")
    }

    // --- KRAIT-001 ---

    #[test]
    fn go_001_reflect_import() {
        let code = "package main\nimport \"reflect\"";
        let tree = parse_go(code);
        let v = GoRules.check_all(code, &tree);
        assert!(v.is_some());
        assert_eq!(v.expect("test").rule, "KRAIT-001");
    }

    #[test]
    fn go_001_safe_passes() {
        let code = "package main\nimport \"fmt\"\nfunc main() { fmt.Println(\"hello\") }";
        let tree = parse_go(code);
        assert!(GoRules.check_all(code, &tree).is_none());
    }

    // --- KRAIT-002 ---

    #[test]
    fn go_002_os_exec_import() {
        let code = "package main\nimport \"os/exec\"";
        let tree = parse_go(code);
        let v = GoRules.check_all(code, &tree);
        assert!(v.is_some());
        assert_eq!(v.expect("test").rule, "KRAIT-002");
    }

    #[test]
    fn go_002_exec_command() {
        let code = "package main\nimport \"os/exec\"\nfunc run() { exec.Command(\"ls\") }";
        let tree = parse_go(code);
        let v = check_krait_002(code, &tree);
        assert!(v.is_some());
        assert_eq!(v.expect("test").rule, "KRAIT-002");
    }

    // --- KRAIT-003 ---

    #[test]
    fn go_003_read_credential() {
        let code = r#"package main
import "os"
func steal() { os.ReadFile("~/.ssh/id_rsa") }"#;
        let tree = parse_go(code);
        let v = check_krait_003(code, &tree);
        assert!(v.is_some());
        assert_eq!(v.expect("test").rule, "KRAIT-003");
    }

    // --- KRAIT-004 ---

    #[test]
    fn go_004_net_http_import() {
        let code = "package main\nimport \"net/http\"";
        let tree = parse_go(code);
        let v = check_krait_004(code, &tree);
        assert!(v.is_some());
        assert_eq!(v.expect("test").rule, "KRAIT-004");
    }

    // --- KRAIT-006 ---

    #[test]
    fn go_006_immutable_path() {
        let code = r#"package main
func attack() { path := "native/krait_analyzer" }"#;
        let tree = parse_go(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some());
        assert_eq!(v.expect("test").rule, "KRAIT-006");
    }

    #[test]
    fn go_006_safe_path_passes() {
        let code = r#"package main
func safe() { path := "lib/skills/tool.go" }"#;
        let tree = parse_go(code);
        assert!(check_krait_006(code, &tree).is_none());
    }

    // --- KRAIT-007 ---

    #[test]
    fn go_007_krait_import() {
        let code = r#"package main
import "github.com/krait/evolution""#;
        let tree = parse_go(code);
        let v = check_krait_007(code, &tree);
        assert!(v.is_some());
        assert_eq!(v.expect("test").rule, "KRAIT-007");
    }

    // --- Allowlist ---

    #[test]
    fn go_alw_os_import() {
        let code = "package main\nimport \"os\"";
        let tree = parse_go(code);
        let v = check_forbidden_imports(code, &tree);
        assert!(v.is_some());
        assert_eq!(v.expect("test").rule, "KRAIT-ALW");
    }

    #[test]
    fn go_alw_safe_import_passes() {
        let code = "package main\nimport (\n\"fmt\"\n\"strings\"\n\"math\"\n)";
        let tree = parse_go(code);
        assert!(check_forbidden_imports(code, &tree).is_none());
    }
}
