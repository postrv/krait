//! KRAIT security rules for Python code.
//!
//! Enforces KRAIT-001 through KRAIT-007 using tree-sitter-python AST queries.

use tree_sitter::Tree;
use crate::rules::Violation;
use super::{LanguageRules, collect_strings_with_query, strings_match_immutable,
            strings_match_credentials, strings_match_krait_internals};

pub struct PythonRules;

impl LanguageRules for PythonRules {
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
        "python"
    }
}

fn lang() -> tree_sitter::Language {
    tree_sitter_python::LANGUAGE.into()
}

fn collect_strings(code: &str, tree: &Tree) -> Vec<String> {
    // Python string literals: "..." and '...'
    let mut strings = collect_strings_with_query(
        code, tree, &lang(),
        r#"(string (string_content) @s)"#,
    );
    // Also capture f-string content
    let fstrings = collect_strings_with_query(
        code, tree, &lang(),
        r#"(interpolation) @s"#,
    );
    strings.extend(fstrings);
    strings
}

/// Collect all import targets: `import X`, `from X import Y`
fn collect_imports(code: &str, tree: &Tree) -> Vec<String> {
    let mut imports = Vec::new();

    // `import X` and `import X.Y`
    let import_stmts = collect_strings_with_query(
        code, tree, &lang(),
        r#"(import_statement name: (dotted_name) @name)"#,
    );
    imports.extend(import_stmts);

    // `from X import Y`
    let from_stmts = collect_strings_with_query(
        code, tree, &lang(),
        r#"(import_from_statement module_name: (dotted_name) @name)"#,
    );
    imports.extend(from_stmts);

    // Also match relative imports: `from . import X`
    let rel_imports = collect_strings_with_query(
        code, tree, &lang(),
        r#"(import_from_statement module_name: (relative_import) @name)"#,
    );
    imports.extend(rel_imports);

    imports
}

// ---------------------------------------------------------------------------
// KRAIT-001: No code eval
// ---------------------------------------------------------------------------

const EVAL_FUNCTIONS: &[&str] = &["eval", "exec", "compile", "execfile"];

fn check_krait_001(code: &str, tree: &Tree) -> Option<Violation> {
    // Check for direct calls: eval(), exec(), compile()
    if has_call(code, tree, EVAL_FUNCTIONS) {
        return Some(Violation {
            rule: "KRAIT-001".into(),
            explanation: "Code evaluation detected (eval/exec/compile)".into(),
        });
    }
    None
}

// ---------------------------------------------------------------------------
// KRAIT-002: No raw shell
// ---------------------------------------------------------------------------

const SHELL_MODULES: &[&str] = &["subprocess", "os"];
const SHELL_FUNCTIONS: &[&str] = &["system", "popen", "popen2", "popen3", "popen4"];
const SHELL_SUBPROCESS_FNS: &[&str] = &["call", "run", "Popen", "check_call", "check_output", "getoutput", "getstatusoutput"];

fn check_krait_002(code: &str, tree: &Tree) -> Option<Violation> {
    let imports = collect_imports(code, tree);

    // Check `import subprocess` or `import os`
    if imports.iter().any(|i| SHELL_MODULES.contains(&i.as_str())) {
        return Some(Violation {
            rule: "KRAIT-002".into(),
            explanation: "Shell execution module imported (subprocess/os)".into(),
        });
    }

    // Check for os.system(), os.popen(), subprocess.call(), etc.
    for module in SHELL_MODULES {
        for func in SHELL_FUNCTIONS.iter().chain(SHELL_SUBPROCESS_FNS.iter()) {
            let pattern = format!("{}.{}", module, func);
            if code.contains(&pattern) {
                return Some(Violation {
                    rule: "KRAIT-002".into(),
                    explanation: format!("Shell execution detected: {}", pattern),
                });
            }
        }
    }

    // Check for commands module (deprecated but still dangerous)
    if imports.iter().any(|i| i == "commands") || code.contains("commands.") {
        return Some(Violation {
            rule: "KRAIT-002".into(),
            explanation: "Shell execution module imported (commands)".into(),
        });
    }

    None
}

// ---------------------------------------------------------------------------
// KRAIT-003: No credential path access
// ---------------------------------------------------------------------------

fn check_krait_003(code: &str, tree: &Tree) -> Option<Violation> {
    let has_file_op = code.contains("open(")
        || code.contains("Path(")
        || code.contains("pathlib.")
        || code.contains("shutil.")
        || code.contains("os.path.");

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

const NETWORK_MODULES: &[&str] = &[
    "requests", "urllib", "urllib2", "urllib3", "httpx", "aiohttp",
    "socket", "http.client", "http.server", "xmlrpc", "ftplib",
    "smtplib", "poplib", "imaplib", "telnetlib", "paramiko",
];

fn check_krait_004(code: &str, tree: &Tree) -> Option<Violation> {
    let imports = collect_imports(code, tree);

    for module in NETWORK_MODULES {
        // Check direct import
        if imports.iter().any(|i| i == module || i.starts_with(&format!("{}.", module))) {
            return Some(Violation {
                rule: "KRAIT-004".into(),
                explanation: format!("Network module imported: {}", module),
            });
        }
    }

    // Check for socket usage
    if code.contains("socket.socket(") || code.contains("socket.create_connection(") {
        return Some(Violation {
            rule: "KRAIT-004".into(),
            explanation: "Raw socket creation detected".into(),
        });
    }

    None
}

// ---------------------------------------------------------------------------
// KRAIT-005: No hot code loading
// ---------------------------------------------------------------------------

fn check_krait_005(code: &str, tree: &Tree) -> Option<Violation> {
    let imports = collect_imports(code, tree);

    if imports.iter().any(|i| i == "importlib") {
        return Some(Violation {
            rule: "KRAIT-005".into(),
            explanation: "Dynamic import module (importlib) detected".into(),
        });
    }

    // __import__() built-in
    if has_call(code, tree, &["__import__"]) {
        return Some(Violation {
            rule: "KRAIT-005".into(),
            explanation: "Dynamic import (__import__) detected".into(),
        });
    }

    // importlib.reload, importlib.import_module
    if code.contains("importlib.reload") || code.contains("importlib.import_module") {
        return Some(Violation {
            rule: "KRAIT-005".into(),
            explanation: "Dynamic code loading detected (importlib)".into(),
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

    // f-string evasion: f"native/{var}"
    if code.contains("f\"") || code.contains("f'") {
        let partial_segments = ["native/", "krait_analyzer", ".krait-immutable",
            "krait-rules", "config/", "priv/", ".github/", "deps/", ".git/"];
        if strings.iter().any(|s| {
            partial_segments.iter().any(|seg| s.contains(seg))
        }) {
            return Some(Violation {
                rule: "KRAIT-006".into(),
                explanation: "Immutable path targeting detected (f-string evasion)".into(),
            });
        }
    }

    // os.path.join / pathlib evasion
    if (code.contains("os.path.join") || code.contains("Path(") || code.contains("PurePath("))
        && strings.iter().any(|s| {
            super::IMMUTABLE_SEGMENTS.iter().any(|seg| s.contains(seg))
        })
    {
        return Some(Violation {
            rule: "KRAIT-006".into(),
            explanation: "Immutable path targeting detected (path join evasion)".into(),
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

    // Check imports for krait.* modules
    if imports.iter().any(|i| {
        let lower = i.to_lowercase();
        lower.starts_with("krait.") || lower.starts_with("krait_web")
    }) {
        return Some(Violation {
            rule: "KRAIT-007".into(),
            explanation: "KRAIT internals import detected".into(),
        });
    }

    // Check string literals for krait internal references
    if strings_match_krait_internals(&strings) {
        return Some(Violation {
            rule: "KRAIT-007".into(),
            explanation: "KRAIT internals reference detected in string literal".into(),
        });
    }

    None
}

// ---------------------------------------------------------------------------
// Forbidden import allowlist
// ---------------------------------------------------------------------------

const FORBIDDEN_MODULES: &[&str] = &[
    "os", "sys", "subprocess", "socket", "http", "ctypes", "pickle",
    "shelve", "marshal", "multiprocessing", "threading", "signal",
    "resource", "pty", "fcntl", "termios", "readline", "code",
    "codeop", "compileall", "py_compile", "zipimport", "pkgutil",
];

fn check_forbidden_imports(code: &str, tree: &Tree) -> Option<Violation> {
    let imports = collect_imports(code, tree);

    for module in FORBIDDEN_MODULES {
        if imports.iter().any(|i| i == module || i.starts_with(&format!("{}.", module))) {
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

/// Check if any of the given function names are called at the top level
fn has_call(code: &str, tree: &Tree, function_names: &[&str]) -> bool {
    let query_str = r#"(call function: (identifier) @fn)"#;
    if let Ok(query) = tree_sitter::Query::new(&lang(), query_str) {
        let mut cursor = tree_sitter::QueryCursor::new();
        let bytes = code.as_bytes();
        use streaming_iterator::StreamingIterator;
        let mut matches = cursor.matches(&query, tree.root_node(), bytes);
        while let Some(m) = matches.next() {
            if let Some(cap) = m.captures.first() {
                if let Ok(fn_name) = cap.node.utf8_text(bytes) {
                    if function_names.contains(&fn_name) {
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

    fn parse_python(code: &str) -> Tree {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&lang()).ok();
        parser.parse(code, None).expect("test: parse python code")
    }

    // --- KRAIT-001: eval/exec ---

    #[test]
    fn python_001_eval_detected() {
        let tree = parse_python("result = eval('1 + 1')");
        let v = PythonRules.check_all("result = eval('1 + 1')", &tree);
        assert!(v.is_some());
        assert_eq!(v.expect("test").rule, "KRAIT-001");
    }

    #[test]
    fn python_001_exec_detected() {
        let tree = parse_python("exec('import os')");
        let v = PythonRules.check_all("exec('import os')", &tree);
        assert!(v.is_some());
        assert_eq!(v.expect("test").rule, "KRAIT-001");
    }

    #[test]
    fn python_001_compile_detected() {
        let code = "compile('print(1)', '<string>', 'exec')";
        let tree = parse_python(code);
        let v = PythonRules.check_all(code, &tree);
        assert!(v.is_some());
        assert_eq!(v.expect("test").rule, "KRAIT-001");
    }

    #[test]
    fn python_001_safe_passes() {
        let code = "x = len([1, 2, 3])";
        let tree = parse_python(code);
        assert!(PythonRules.check_all(code, &tree).is_none());
    }

    // --- KRAIT-002: subprocess/os.system ---

    #[test]
    fn python_002_import_subprocess() {
        let code = "import subprocess";
        let tree = parse_python(code);
        let v = PythonRules.check_all(code, &tree);
        assert!(v.is_some());
        assert_eq!(v.expect("test").rule, "KRAIT-002");
    }

    #[test]
    fn python_002_import_os() {
        let code = "import os";
        let tree = parse_python(code);
        let v = PythonRules.check_all(code, &tree);
        assert!(v.is_some());
        // os triggers KRAIT-002 (shell) before KRAIT-ALW (allowlist)
        assert_eq!(v.expect("test").rule, "KRAIT-002");
    }

    #[test]
    fn python_002_os_system_call() {
        let code = "os.system('ls -la')";
        let tree = parse_python(code);
        let v = check_krait_002(code, &tree);
        assert!(v.is_some());
        assert_eq!(v.expect("test").rule, "KRAIT-002");
    }

    #[test]
    fn python_002_subprocess_run() {
        let code = "subprocess.run(['ls', '-la'])";
        let tree = parse_python(code);
        let v = check_krait_002(code, &tree);
        assert!(v.is_some());
        assert_eq!(v.expect("test").rule, "KRAIT-002");
    }

    // --- KRAIT-003: credential paths ---

    #[test]
    fn python_003_ssh_key_read() {
        let code = "f = open('~/.ssh/id_rsa', 'r')";
        let tree = parse_python(code);
        let v = check_krait_003(code, &tree);
        assert!(v.is_some());
        assert_eq!(v.expect("test").rule, "KRAIT-003");
    }

    #[test]
    fn python_003_safe_path_passes() {
        let code = "f = open('/tmp/safe.txt', 'r')";
        let tree = parse_python(code);
        assert!(check_krait_003(code, &tree).is_none());
    }

    // --- KRAIT-004: network ---

    #[test]
    fn python_004_import_requests() {
        let code = "import requests";
        let tree = parse_python(code);
        let v = check_krait_004(code, &tree);
        assert!(v.is_some());
        assert_eq!(v.expect("test").rule, "KRAIT-004");
    }

    #[test]
    fn python_004_from_urllib() {
        let code = "from urllib.request import urlopen";
        let tree = parse_python(code);
        let v = check_krait_004(code, &tree);
        assert!(v.is_some());
        assert_eq!(v.expect("test").rule, "KRAIT-004");
    }

    #[test]
    fn python_004_socket_creation() {
        let code = "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)";
        let tree = parse_python(code);
        let v = check_krait_004(code, &tree);
        assert!(v.is_some());
        assert_eq!(v.expect("test").rule, "KRAIT-004");
    }

    // --- KRAIT-005: hot loading ---

    #[test]
    fn python_005_import_importlib() {
        let code = "import importlib";
        let tree = parse_python(code);
        let v = check_krait_005(code, &tree);
        assert!(v.is_some());
        assert_eq!(v.expect("test").rule, "KRAIT-005");
    }

    #[test]
    fn python_005_dunder_import() {
        let code = "mod = __import__('os')";
        let tree = parse_python(code);
        let v = check_krait_005(code, &tree);
        assert!(v.is_some());
        assert_eq!(v.expect("test").rule, "KRAIT-005");
    }

    // --- KRAIT-006: immutable paths ---

    #[test]
    fn python_006_direct_path() {
        let code = r#"path = "native/krait_analyzer/src/lib.rs""#;
        let tree = parse_python(code);
        let v = check_krait_006(code, &tree);
        assert!(v.is_some());
        assert_eq!(v.expect("test").rule, "KRAIT-006");
    }

    #[test]
    fn python_006_safe_path_passes() {
        let code = r#"path = "lib/skills/my_skill.py""#;
        let tree = parse_python(code);
        assert!(check_krait_006(code, &tree).is_none());
    }

    // --- KRAIT-007: self-modification ---

    #[test]
    fn python_007_import_krait_internal() {
        let code = "from krait.evolution import workspace";
        let tree = parse_python(code);
        let v = check_krait_007(code, &tree);
        assert!(v.is_some());
        assert_eq!(v.expect("test").rule, "KRAIT-007");
    }

    #[test]
    fn python_007_safe_import_passes() {
        let code = "import json";
        let tree = parse_python(code);
        assert!(check_krait_007(code, &tree).is_none());
    }

    // --- Allowlist ---

    #[test]
    fn python_alw_forbidden_module() {
        let code = "import ctypes";
        let tree = parse_python(code);
        let v = check_forbidden_imports(code, &tree);
        assert!(v.is_some());
        assert_eq!(v.expect("test").rule, "KRAIT-ALW");
    }

    #[test]
    fn python_alw_safe_module_passes() {
        let code = "import json\nimport re\nimport math";
        let tree = parse_python(code);
        assert!(check_forbidden_imports(code, &tree).is_none());
    }
}
