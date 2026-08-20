//! Select wordlists based on detected technology profile.

use crate::cli::ScanMode;
use crate::fingerprint::{unique_techs, TargetProfile};
use crate::wordlist::catalog::{self, CatalogEntry};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WordlistRecommendation {
    pub id: String,
    pub name: String,
    pub reason: String,
    pub priority: u8,
    pub seclists_path: String,
    pub url: String,
    pub tech_triggered: Vec<String>,
}

/// Collect normalized tech tags from a target profile.
pub fn profile_tech_tags(profile: &TargetProfile) -> Vec<String> {
    let mut tags = Vec::new();
    for t in unique_techs(profile) {
        tags.push(t.to_ascii_lowercase());
    }
    if let Some(s) = &profile.server {
        tags.push(s.to_ascii_lowercase());
    }
    if let Some(p) = &profile.powered_by {
        tags.push(p.to_ascii_lowercase());
    }
    for t in &profile.favicon_tech {
        tags.push(t.to_ascii_lowercase());
    }
    if profile.graphql_detected {
        tags.push("graphql".into());
    }
    tags.sort();
    tags.dedup();
    tags
}

fn tag_matches(entry: &CatalogEntry, tags: &[String]) -> bool {
    if entry.tech_tags.is_empty() {
        return true; // universal — mode filter applies separately
    }
    tags.iter().any(|tag| {
        entry.tech_tags.iter().any(|needle| {
            tag.contains(&needle.to_ascii_lowercase())
                || needle.to_ascii_lowercase().contains(tag.as_str())
        })
    })
}

fn mode_matches(entry: &CatalogEntry, mode: ScanMode) -> bool {
    entry.modes.contains(&mode)
}

/// Recommend wordlists for a profile + scan mode.
pub fn recommend(profile: &TargetProfile, mode: ScanMode) -> Vec<WordlistRecommendation> {
    let tags = profile_tech_tags(profile);
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Technology-specific lists
    for entry in catalog::TECH {
        if !mode_matches(entry, mode) {
            continue;
        }
        // Deep-only extras (e.g. git.txt) with no tech requirement
        if entry.tech_tags.is_empty() {
            if !seen.insert(entry.id) {
                continue;
            }
            out.push(to_recommendation(entry, vec!["deep-scan".into()]));
            continue;
        }
        if !tag_matches(entry, &tags) {
            continue;
        }
        if !seen.insert(entry.id) {
            continue;
        }
        let triggered: Vec<_> = entry
            .tech_tags
            .iter()
            .filter(|t| tags.iter().any(|tag| tag.contains(**t)))
            .map(|s| s.to_string())
            .collect();
        out.push(to_recommendation(entry, triggered));
    }

    // Universal lists — include common always; big only deep; quickhits fast
    for entry in catalog::UNIVERSAL {
        if !mode_matches(entry, mode) {
            continue;
        }
        // API list: only if api-related tag OR no strong tech (still useful)
        if entry.id == "api-endpoints" {
            let api_hit = tags.iter().any(|t| {
                t.contains("api")
                    || t.contains("graphql")
                    || t.contains("swagger")
                    || t.contains("spring")
                    || t.contains("node")
            });
            if !api_hit && !tags.is_empty() {
                // skip generic api list when unrelated tech-only target
                continue;
            }
        }
        if entry.id == "git" {
            continue; // git is in TECH with empty tags but deep only - handled in TECH
        }
        if !seen.insert(entry.id) {
            continue;
        }
        out.push(to_recommendation(entry, vec!["baseline".into()]));
    }

    out.sort_by_key(|b| std::cmp::Reverse(b.priority));
    out
}

fn to_recommendation(entry: &CatalogEntry, tech_triggered: Vec<String>) -> WordlistRecommendation {
    let reason = if tech_triggered.is_empty() || tech_triggered == ["baseline"] {
        format!("Recommended for {} mode", "scan")
    } else {
        format!("Matched tech: {}", tech_triggered.join(", "))
    };
    WordlistRecommendation {
        id: entry.id.to_string(),
        name: entry.name.to_string(),
        reason,
        priority: entry.priority,
        seclists_path: entry.seclists_path.to_string(),
        url: catalog::seclists_url(entry.seclists_path),
        tech_triggered,
    }
}

/// When tech-specific lists are selected, skip heavy embedded generic paths.
pub fn should_use_tech_focus(
    profile: &TargetProfile,
    recommendations: &[WordlistRecommendation],
) -> bool {
    recommendations
        .iter()
        .any(|r| r.priority >= 88 && r.tech_triggered != vec!["baseline".to_string()])
        || !profile.frameworks.is_empty()
        || !profile.cms.is_empty()
}

/// Suggest file extensions based on detected technology (merged with `-e`).
pub fn extensions_for_tech(profile: &TargetProfile) -> Vec<String> {
    let tags = profile_tech_tags(profile);
    let mut exts = Vec::new();

    let push = |exts: &mut Vec<String>, list: &[&str]| {
        for e in list {
            if !exts.iter().any(|x| x.eq_ignore_ascii_case(e)) {
                exts.push(e.to_string());
            }
        }
    };

    for tag in &tags {
        if tag.contains("php") || tag.contains("laravel") || tag.contains("wordpress") {
            push(
                &mut exts,
                &["php", "bak", "old", "txt", "swp", "inc", "dist"],
            );
        }
        if tag.contains("asp") || tag.contains("iis") {
            push(&mut exts, &["asp", "aspx", "ashx", "asmx", "config", "bak"]);
        }
        if tag.contains("java") || tag.contains("spring") || tag.contains("tomcat") {
            push(&mut exts, &["jsp", "war", "jar", "class", "do", "action"]);
        }
        if tag.contains("django") || tag.contains("flask") || tag.contains("python") {
            push(&mut exts, &["py", "pyc", "pyo", "env", "cfg"]);
        }
        if tag.contains("node") || tag.contains("express") || tag.contains("next") {
            push(&mut exts, &["js", "json", "map", "env", "bak"]);
        }
        if tag.contains("rails") || tag.contains("ruby") {
            push(&mut exts, &["rb", "erb", "yml", "yaml", "env"]);
        }
        if tag.contains("nginx") || tag.contains("apache") {
            push(&mut exts, &["conf", "bak", "old", "save"]);
        }
    }

    // Always useful backup / config extensions when any tech detected
    if !tags.is_empty() {
        push(&mut exts, &["bak", "old", "backup", "zip", "tar", "gz"]);
    }

    exts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordpress_gets_wp_list() {
        let mut p = TargetProfile::default();
        p.cms.push("WordPress".into());
        let recs = recommend(&p, ScanMode::Balanced);
        assert!(recs.iter().any(|r| r.id == "wordpress"));
        assert!(recs.iter().any(|r| r.id == "common"));
    }

    #[test]
    fn spring_gets_actuator() {
        let mut p = TargetProfile::default();
        p.frameworks.push("Spring Boot".into());
        let recs = recommend(&p, ScanMode::Balanced);
        assert!(recs.iter().any(|r| r.id == "spring"));
    }
}
