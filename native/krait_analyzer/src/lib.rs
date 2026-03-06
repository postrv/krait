#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

mod allowlist;
mod parser;
mod rules;
mod complexity;
mod hash;
pub mod lang;

use rustler::{Encoder, Env, NifResult, Term};

mod atoms {
    rustler::atoms! {
        ok,
        syntax_error,
        policy_violation,
        error,
        complexity,
        hash,
        rule,
        location,
        explanation,
        line,
        message,
    }
}

#[rustler::nif(schedule = "DirtyCpu")]
fn quick_validate<'a>(env: Env<'a>, code: &str, language: &str) -> NifResult<Term<'a>> {
    // 1. Parse & check syntax
    match parser::parse(code, language) {
        Err(errors) => {
            let error_terms: Vec<Term<'a>> = errors
                .iter()
                .map(|e| {
                    let mut map = Term::map_new(env);
                    if let Ok(m) = map.map_put(atoms::line().encode(env), e.line.encode(env)) {
                        map = m;
                    }
                    if let Ok(m) = map.map_put(
                        atoms::message().encode(env),
                        e.message.as_str().encode(env),
                    ) {
                        map = m;
                    }
                    map
                })
                .collect();
            Ok((atoms::syntax_error(), error_terms).encode(env))
        }
        Ok(tree) => {
            // 2. Check KRAIT rules against AST + text (language-aware dispatch)
            if let Some(violation) = rules::check_all(code, &tree, language) {
                let mut map = Term::map_new(env);
                if let Ok(m) = map.map_put(
                    atoms::rule().encode(env),
                    violation.rule.as_str().encode(env),
                ) {
                    map = m;
                }
                if let Ok(m) = map.map_put(atoms::location().encode(env), Term::map_new(env)) {
                    map = m;
                }
                if let Ok(m) = map.map_put(
                    atoms::explanation().encode(env),
                    violation.explanation.as_str().encode(env),
                ) {
                    map = m;
                }
                Ok((atoms::policy_violation(), map).encode(env))
            } else {
                // 3. Compute complexity and hash
                let comp = complexity::score(code, &tree);
                let h = hash::blake3_hex(code);

                let mut map = Term::map_new(env);
                if let Ok(m) = map.map_put(atoms::complexity().encode(env), comp.encode(env)) {
                    map = m;
                }
                if let Ok(m) = map.map_put(atoms::hash().encode(env), h.as_str().encode(env)) {
                    map = m;
                }
                Ok((atoms::ok(), map).encode(env))
            }
        }
    }
}

rustler::init!("Elixir.Krait.Analyzer.Nif");
