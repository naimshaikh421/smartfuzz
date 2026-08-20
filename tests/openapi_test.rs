use smartfuzz::api::parse_openapi;

#[test]
fn openapi_json_paths() {
    let spec = r#"{"openapi":"3.0.0","paths":{"/api/users":{},"/api/admin":{}}}"#;
    let paths = parse_openapi(spec);
    assert!(paths.contains(&"/api/users".to_string()));
    assert!(paths.contains(&"/api/admin".to_string()));
}

#[test]
fn openapi_yaml_paths() {
    let spec = r#"
openapi: 3.0.0
paths:
  /v1/health:
    get: {}
  /v1/users:
    get: {}
"#;
    let paths = parse_openapi(spec);
    assert!(paths.contains(&"/v1/health".to_string()));
    assert!(paths.contains(&"/v1/users".to_string()));
}

#[test]
fn openapi_swagger_basepath() {
    let spec = r#"{"swagger":"2.0","basePath":"/api","paths":{"/users":{}}}"#;
    let paths = parse_openapi(spec);
    assert!(paths.iter().any(|p| p.contains("users")));
}
