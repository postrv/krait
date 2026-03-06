//! Per-language KRAIT rule implementations.
//!
//! Each language module implements security checks for KRAIT-001 through KRAIT-007,
//! adapted to that language's AST structure and dangerous patterns.

pub mod python;
pub mod javascript;
pub mod go;
pub mod rust_lang;

use crate::rules::Violation;
use tree_sitter::Tree;

/// Trait for per-language security rule checking.
/// Each language implements all 7 KRAIT rules with language-appropriate patterns.
pub trait LanguageRules {
    /// Run all KRAIT security rules for this language.
    /// Returns the first violation found, or None if the code is clean.
    fn check_all(&self, code: &str, tree: &Tree) -> Option<Violation>;

    /// Language identifier (e.g., "python", "javascript").
    fn language_id(&self) -> &'static str;
}

/// Get the appropriate LanguageRules implementation for a language string.
/// Returns None for unknown languages (fail-closed: caller must handle).
pub fn get_rules(language: &str) -> Option<Box<dyn LanguageRules>> {
    match language {
        "python" => Some(Box::new(python::PythonRules)),
        "javascript" | "jsx" => Some(Box::new(javascript::JavaScriptRules { typescript: false })),
        "typescript" | "tsx" => Some(Box::new(javascript::JavaScriptRules { typescript: true })),
        "go" => Some(Box::new(go::GoRules)),
        "rust" => Some(Box::new(rust_lang::RustRules)),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Shared constants used across language modules
// ---------------------------------------------------------------------------

/// Credential path prefixes/patterns — shared across all languages
pub const CREDENTIAL_PATHS: &[&str] = &[
    "~/.ssh", "~/.aws", "~/.config/gcloud", "~/.gnupg", ".env",
    "credentials", "secrets", "~/.kube/config", "~/.docker/config.json",
    "~/.netrc", "~/.git-credentials", "/etc/shadow", "/proc/self/environ",
    "/proc/self/cmdline", "/proc/self/maps", "/proc/self/exe", "/proc/self/fd",
    "~/.npmrc", "~/.pypirc", "~/.m2/settings.xml", "~/.vault-token",
    "~/.gradle/gradle.properties", "/etc/passwd", "~/.bash_history",
    "~/.zsh_history", "terraform.tfstate", ".pgpass",
];

/// Immutable path segments — shared across all languages
pub const IMMUTABLE_SEGMENTS: &[&str] = &[
    "native/krait_analyzer", ".krait-immutable", "krait-rules.yaml",
    "krait-rules", "krait_analyzer", "_build", "mix.exs", ".iex.exs",
    "config", "priv", ".github", "Dockerfile", "Makefile", "deps",
    ".tool-versions", "rel/",
];

/// Full immutable path patterns for case-insensitive matching
pub const IMMUTABLE_FULL_PATTERNS: &[&str] = &[
    "native/krait_analyzer", ".krait-immutable", "krait-rules.yaml", "_build/",
    "mix.exs", ".iex.exs", "config/", "priv/", ".github/",
    "dockerfile", "makefile", "deps/", ".git/", "rel/", ".gitignore", ".tool-versions",
];

/// KRAIT-007 forbidden module prefixes
pub const KRAIT_INTERNAL_PREFIXES: &[&str] = &[
    "krait.evolution", "krait.analyzer", "krait.sandbox", "krait.brain",
    "krait.gateway", "krait.memory", "krait.llm", "krait.skills",
    "krait_web", "krait.github", "krait.repo",
];

/// Collect all string literals from a tree-sitter AST using a language-specific query.
/// Returns the content of each string literal found.
pub fn collect_strings_with_query(
    code: &str,
    tree: &Tree,
    lang: &tree_sitter::Language,
    query_str: &str,
) -> Vec<String> {
    let mut strings = Vec::new();
    if let Ok(query) = tree_sitter::Query::new(lang, query_str) {
        let mut cursor = tree_sitter::QueryCursor::new();
        let bytes = code.as_bytes();
        use streaming_iterator::StreamingIterator;
        let mut matches = cursor.matches(&query, tree.root_node(), bytes);
        while let Some(m) = matches.next() {
            if let Some(cap) = m.captures.first() {
                if let Ok(s) = cap.node.utf8_text(bytes) {
                    strings.push(s.to_string());
                }
            }
        }
    }
    strings
}

/// Check if any string in a list matches immutable path patterns (case-insensitive).
pub fn strings_match_immutable(strings: &[String]) -> bool {
    strings.iter().any(|s| {
        let lower = s.to_lowercase();
        IMMUTABLE_FULL_PATTERNS.iter().any(|p| lower.contains(p))
    })
}

/// Check if any string in a list contains credential paths.
pub fn strings_match_credentials(strings: &[String]) -> bool {
    strings.iter().any(|s| {
        CREDENTIAL_PATHS.iter().any(|p| s.contains(p))
    })
}

/// Check if any string matches KRAIT internal module references.
pub fn strings_match_krait_internals(strings: &[String]) -> bool {
    strings.iter().any(|s| {
        let lower = s.to_lowercase();
        KRAIT_INTERNAL_PREFIXES.iter().any(|p| lower.contains(p))
    })
}
