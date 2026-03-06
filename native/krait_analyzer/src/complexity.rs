use std::sync::LazyLock;
use tree_sitter::Tree;

static COMPLEXITY_REGEXES: LazyLock<Vec<regex::Regex>> = LazyLock::new(|| {
    let patterns = [
        r"\bif\b",
        r"\bcase\b",
        r"\bcond\b",
        r"\bwith\b",
        r"\btry\b",
        r"\brescue\b",
        r"\bcatch\b",
        r"\bfn\b",
        r"\breceive\b",
        r"\bfor\b",
        r"\bunless\b",
    ];
    patterns
        .iter()
        .filter_map(|p| regex::Regex::new(p).ok())
        .collect()
});

static ARROW_RE: LazyLock<Option<regex::Regex>> = LazyLock::new(|| {
    regex::Regex::new(r"\s->\s").ok()
});

/// Compute cyclomatic complexity by counting branching constructs.
///
/// Starts at 1 (base complexity) and adds 1 for each decision point found
/// in the source text. This is a text-based heuristic; future versions may
/// walk the AST for more precise results.
pub fn score(code: &str, _tree: &Tree) -> usize {
    let mut score: usize = 1;

    for re in COMPLEXITY_REGEXES.iter() {
        score += re.find_iter(code).count();
    }

    // Count arrow clauses (pattern match branches)
    if let Some(ref arrow_re) = *ARROW_RE {
        score += arrow_re.find_iter(code).count();
    }

    score
}
