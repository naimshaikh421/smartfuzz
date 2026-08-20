//! Multi-keyword FUZZ template engine (FUZZ, FUZZ2, FUZZ3, FUZZ4).

pub const FUZZ_KEYWORDS: &[&str] = &["FUZZ", "FUZZ2", "FUZZ3", "FUZZ4"];

/// Replace all known FUZZ keywords in `template` using `values[0]` → FUZZ, etc.
/// Longer keywords (FUZZ4…) are replaced first so FUZZ does not corrupt FUZZ2.
pub fn apply_fuzz(template: &str, values: &[&str]) -> String {
    let mut out = template.to_string();
    for (i, kw) in FUZZ_KEYWORDS.iter().enumerate().rev() {
        if out.contains(kw) {
            let val = values.get(i).or_else(|| values.first()).unwrap_or(&"");
            out = out.replace(kw, val);
        }
    }
    out
}

/// Returns which FUZZ keywords appear in the template (in order).
pub fn keywords_in(template: &str) -> Vec<&'static str> {
    FUZZ_KEYWORDS
        .iter()
        .filter(|k| template.contains(*k))
        .copied()
        .collect()
}

/// Whether any FUZZ keyword is present.
pub fn has_fuzz(template: &str) -> bool {
    FUZZ_KEYWORDS.iter().any(|k| template.contains(k))
}

/// Maximum number of FUZZ keywords across multiple templates (URL, body, raw request).
pub fn max_keyword_count(templates: &[&str]) -> usize {
    templates
        .iter()
        .map(|t| keywords_in(t).len())
        .max()
        .unwrap_or(0)
}

/// Build replacement slice for a single primary entry (path fuzz mode).
#[cfg(test)]
pub fn single_entry_values(entry: &str) -> Vec<String> {
    vec![entry.trim_start_matches('/').to_string()]
}

/// Combine multiple wordlists for multi-FUZZ templates (capped cartesian).
pub fn combine_wordlists(lists: &[Vec<String>], cap: usize) -> Vec<Vec<String>> {
    if lists.is_empty() {
        return Vec::new();
    }
    let mut result: Vec<Vec<String>> = vec![vec![]];
    for list in lists {
        if list.is_empty() {
            continue;
        }
        let mut next = Vec::new();
        for prefix in &result {
            for item in list {
                let mut row = prefix.clone();
                row.push(item.clone());
                next.push(row);
                if next.len() >= cap {
                    return next;
                }
            }
        }
        result = next;
        if result.is_empty() {
            break;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_single_fuzz() {
        assert_eq!(
            apply_fuzz("https://t.com/FUZZ", &["admin"]),
            "https://t.com/admin"
        );
    }

    #[test]
    fn apply_multi_fuzz() {
        assert_eq!(
            apply_fuzz("/api/FUZZ/FUZZ2", &["v1", "users"]),
            "/api/v1/users"
        );
    }

    #[test]
    fn single_entry_strips_slash() {
        assert_eq!(single_entry_values("/admin"), vec!["admin"]);
    }

    #[test]
    fn keywords_detected() {
        assert_eq!(keywords_in("/FUZZ/x"), vec!["FUZZ"]);
        assert_eq!(keywords_in("/FUZZ/FUZZ2"), vec!["FUZZ", "FUZZ2"]);
    }
}
