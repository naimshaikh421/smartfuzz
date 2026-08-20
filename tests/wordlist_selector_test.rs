use smartfuzz::cli::ScanMode;
use smartfuzz::fingerprint::TargetProfile;
use smartfuzz::wordlist::{profile_tech_tags, recommend};

#[test]
fn balanced_includes_common_and_tech() {
    let mut p = TargetProfile::default();
    p.cms.push("WordPress".into());
    p.languages.push("PHP".into());
    let tags = profile_tech_tags(&p);
    assert!(tags.iter().any(|t| t.contains("wordpress")));
    let recs = recommend(&p, ScanMode::Balanced);
    assert!(recs.iter().any(|r| r.id == "wordpress"));
    assert!(recs.iter().any(|r| r.id == "php"));
    assert!(recs.iter().any(|r| r.id == "common"));
}

#[test]
fn fast_mode_uses_quickhits() {
    let p = TargetProfile::default();
    let recs = recommend(&p, ScanMode::Fast);
    assert!(recs.iter().any(|r| r.id == "quickhits"));
}

#[test]
fn deep_adds_big() {
    let p = TargetProfile::default();
    let recs = recommend(&p, ScanMode::Deep);
    assert!(recs.iter().any(|r| r.id == "big"));
}
