use std::sync::{Mutex, OnceLock};
use tree_sitter::{Parser, Tree};

pub struct SyntaxError {
    pub line: usize,
    pub message: String,
}

// Per-language parser statics — one Parser per language, initialized lazily.
static ELIXIR_PARSER: OnceLock<Mutex<Parser>> = OnceLock::new();
static PYTHON_PARSER: OnceLock<Mutex<Parser>> = OnceLock::new();
static JS_PARSER: OnceLock<Mutex<Parser>> = OnceLock::new();
static TS_PARSER: OnceLock<Mutex<Parser>> = OnceLock::new();
static GO_PARSER: OnceLock<Mutex<Parser>> = OnceLock::new();
static RUST_PARSER: OnceLock<Mutex<Parser>> = OnceLock::new();

/// 5-second parse timeout for DoS protection (v14: M-7)
const PARSE_TIMEOUT_MICROS: u64 = 5_000_000;

fn init_parser(lang: tree_sitter::Language) -> Mutex<Parser> {
    let mut parser = Parser::new();
    if let Err(e) = parser.set_language(&lang) {
        eprintln!("Warning: Failed to load grammar: {e}");
    }
    parser.set_timeout_micros(PARSE_TIMEOUT_MICROS);
    Mutex::new(parser)
}

fn get_elixir_parser() -> &'static Mutex<Parser> {
    ELIXIR_PARSER.get_or_init(|| init_parser(tree_sitter_elixir::LANGUAGE.into()))
}

fn get_python_parser() -> &'static Mutex<Parser> {
    PYTHON_PARSER.get_or_init(|| init_parser(tree_sitter_python::LANGUAGE.into()))
}

fn get_js_parser() -> &'static Mutex<Parser> {
    JS_PARSER.get_or_init(|| init_parser(tree_sitter_javascript::LANGUAGE.into()))
}

fn get_ts_parser() -> &'static Mutex<Parser> {
    TS_PARSER.get_or_init(|| init_parser(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()))
}

fn get_go_parser() -> &'static Mutex<Parser> {
    GO_PARSER.get_or_init(|| init_parser(tree_sitter_go::LANGUAGE.into()))
}

fn get_rust_parser() -> &'static Mutex<Parser> {
    RUST_PARSER.get_or_init(|| init_parser(tree_sitter_rust::LANGUAGE.into()))
}

/// Parse code in the given language. Returns a tree-sitter Tree on success,
/// or a list of syntax errors on failure.
/// Unknown languages return an error (fail-closed, not fallback).
pub fn parse(code: &str, language: &str) -> Result<Tree, Vec<SyntaxError>> {
    match language {
        "elixir" => parse_with_errors(code, get_elixir_parser()),
        "python" => parse_lenient(code, get_python_parser()),
        "javascript" | "jsx" => parse_lenient(code, get_js_parser()),
        "typescript" | "tsx" => parse_lenient(code, get_ts_parser()),
        "go" => parse_lenient(code, get_go_parser()),
        "rust" => parse_lenient(code, get_rust_parser()),
        _ => Err(vec![SyntaxError {
            line: 1,
            message: format!("Unsupported language: {}", language),
        }]),
    }
}

/// Parse Elixir code with strict error checking (existing behavior).
/// Reports syntax errors as failures since Elixir code must be valid.
fn parse_with_errors(code: &str, parser_lock: &Mutex<Parser>) -> Result<Tree, Vec<SyntaxError>> {
    let mut parser = parser_lock.lock().map_err(|_| {
        vec![SyntaxError {
            line: 1,
            message: "Parser lock poisoned".to_string(),
        }]
    })?;

    match parser.parse(code, None) {
        Some(tree) => {
            let root = tree.root_node();
            if root.has_error() {
                let mut errors = Vec::new();
                collect_errors(&root, code, &mut errors);
                if errors.is_empty() {
                    errors.push(SyntaxError {
                        line: 1,
                        message: "Syntax error detected".to_string(),
                    });
                }
                Err(errors)
            } else {
                Ok(tree)
            }
        }
        None => Err(vec![SyntaxError {
            line: 1,
            message: "Parser timeout".to_string(),
        }]),
    }
}

/// Parse non-Elixir code leniently — return the tree even if it has errors.
/// For security analysis, we want to analyze as much as possible even with
/// minor parse errors. The security rules will still catch dangerous patterns.
fn parse_lenient(code: &str, parser_lock: &Mutex<Parser>) -> Result<Tree, Vec<SyntaxError>> {
    let mut parser = parser_lock.lock().map_err(|_| {
        vec![SyntaxError {
            line: 1,
            message: "Parser lock poisoned".to_string(),
        }]
    })?;

    match parser.parse(code, None) {
        Some(tree) => Ok(tree),
        None => Err(vec![SyntaxError {
            line: 1,
            message: "Parse timeout".to_string(),
        }]),
    }
}

fn collect_errors(node: &tree_sitter::Node, source: &str, errors: &mut Vec<SyntaxError>) {
    if node.is_error() || node.is_missing() {
        let start = node.start_position();
        let text = node.utf8_text(source.as_bytes()).unwrap_or("unknown");
        errors.push(SyntaxError {
            line: start.row + 1, // 1-based line numbers
            message: format!("Unexpected: {}", text),
        });
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_errors(&child, source, errors);
    }
}
