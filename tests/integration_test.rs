use smartfuzz::http::{apply_fuzz, combine_wordlists, RawRequestTemplate};

#[test]
fn raw_request_parses_fuzz_host() {
    let raw = "GET / HTTP/1.1\nHost: FUZZ.example.com\n\n";
    let req = RawRequestTemplate::parse(raw).unwrap();
    let h = req.headers_for(&["admin"]);
    assert!(h
        .iter()
        .any(|(k, v)| k == "Host" && v == "admin.example.com"));
}

#[test]
fn multi_fuzz_combine() {
    let lists = vec![vec!["a".into(), "b".into()], vec!["1".into(), "2".into()]];
    let combos = combine_wordlists(&lists, 10);
    assert_eq!(combos.len(), 4);
    assert_eq!(
        apply_fuzz("/x/FUZZ/FUZZ2", &[&combos[0][0], &combos[0][1]]),
        "/x/a/1"
    );
}
