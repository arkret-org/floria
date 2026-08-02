use super::{parse_kdl_to_json, *};

#[test]
fn parses_default_config_values() {
    let config: Config = serde_saphyr::from_str(
        r#"
apps: {}
"#,
    )
    .unwrap();

    assert_eq!(config.http.port, 5000);
    assert_eq!(config.http.bind_addresses, vec!["127.0.0.1"]);
    assert_eq!(config.http.notify_dedup_ttl_seconds, 0);
    assert_eq!(config.http.notify_dedup.backend_kind(), "memory");
    assert_eq!(config.audit.backend_kind(), "disabled");
    assert!(!config.storage.postgres_enabled());
    assert_eq!(
        config.storage.deactivation_queue_table(),
        "floria_push_delivery_queue"
    );
    assert!(!config.http.notify_rate_limits.enabled());
    assert!(!config.http.internal_auth.enabled());
    assert!(!config.metrics.prometheus.enabled);
    assert_eq!(config.metrics.prometheus.address, "127.0.0.1");
    assert_eq!(config.metrics.prometheus.port, 8000);
    assert!(!config.log.access.x_forwarded_for);
}

#[test]
fn formats_prometheus_ipv6_listen_address() {
    let config = PrometheusConfig {
        enabled: true,
        address: "::1".to_owned(),
        port: 9000,
        extra: Map::new(),
    };

    assert_eq!(config.listen_addr().unwrap(), "[::1]:9000");
}

#[test]
fn keeps_explicit_http_ports() {
    let config = HttpConfig {
        port: 5000,
        bind_addresses: vec!["127.0.0.1:7000".to_owned(), "example.com:7100".to_owned()],
        notify_dedup_ttl_seconds: 0,
        notify_dedup: NotifyDedupConfig::default(),
        notify_auth: NotifyAuthConfig::default(),
        internal_auth: InternalAuthConfig::default(),
        notify_rate_limits: NotifyRateLimitConfig::default(),
        notify_retry_queue: NotifyRetryQueueConfig::default(),
        metrics_detailed_circle_labels: false,
        circle_rate_limits: CircleRateLimitConfig::default(),
        extra: Map::new(),
    };

    assert_eq!(
        config.listen_addrs().unwrap(),
        vec!["127.0.0.1:7000", "example.com:7100"]
    );
}

#[test]
fn supports_bracketed_ipv6_without_explicit_port() {
    let config = HttpConfig {
        port: 5000,
        bind_addresses: vec!["[::1]".to_owned()],
        notify_dedup_ttl_seconds: 0,
        notify_dedup: NotifyDedupConfig::default(),
        notify_auth: NotifyAuthConfig::default(),
        internal_auth: InternalAuthConfig::default(),
        notify_rate_limits: NotifyRateLimitConfig::default(),
        notify_retry_queue: NotifyRetryQueueConfig::default(),
        metrics_detailed_circle_labels: false,
        circle_rate_limits: CircleRateLimitConfig::default(),
        extra: Map::new(),
    };

    assert_eq!(config.listen_addrs().unwrap(), vec!["[::1]:5000"]);
}

#[test]
fn parses_kdl_config() {
    let kdl_input = r#"
http {
    port 8080
    bind_addresses "0.0.0.0"
    notify_rate_limits {
        window_seconds 30
        per_origin_service 10
        per_app_id 20
    }
}
apps {
    com.example.test {
        type "apns"
        keyfile "./test.p8"
    }
}
"#;
    let json_value = parse_kdl_to_json(kdl_input).unwrap();
    let config: Config = serde_json::from_value(json_value).unwrap();
    assert_eq!(config.http.port, 8080);
    assert_eq!(config.http.bind_addresses, vec!["0.0.0.0"]);
    assert_eq!(config.http.notify_dedup_ttl_seconds, 0);
    assert_eq!(config.http.notify_rate_limits.window_seconds, 30);
    assert_eq!(config.http.notify_rate_limits.per_origin_service, Some(10));
    assert_eq!(config.http.notify_rate_limits.per_app_id, Some(20));
    assert_eq!(config.apps.len(), 1);
    let app = config.apps.get("com.example.test").unwrap();
    assert_eq!(app.kind, "apns");
    assert_eq!(
        app.get_string("keyfile").unwrap(),
        Some("./test.p8".to_owned())
    );
}

#[test]
fn kdl_array_from_multiple_arguments() {
    let kdl_input = r#"
http {
    bind_addresses "127.0.0.1" "0.0.0.0"
    port 5000
}
apps {}
"#;
    let json_value = parse_kdl_to_json(kdl_input).unwrap();
    let config: Config = serde_json::from_value(json_value).unwrap();
    assert_eq!(config.http.bind_addresses, vec!["127.0.0.1", "0.0.0.0"]);
}

#[test]
fn kdl_array_from_dash_children() {
    let kdl_input = r#"
http {
    bind_addresses {
        - "127.0.0.1"
        - "0.0.0.0"
    }
    port 5000
}
apps {}
"#;
    let json_value = parse_kdl_to_json(kdl_input).unwrap();
    let config: Config = serde_json::from_value(json_value).unwrap();
    assert_eq!(config.http.bind_addresses, vec!["127.0.0.1", "0.0.0.0"]);
}

#[test]
fn kdl_nested_objects() {
    let kdl_input = r#"
apps {
    com.example.jpush {
        type "jpush"
        app_key "test-key"
        master_secret "test-secret"
        third_party_channel {
            xiaomi {
                distribution "jpush"
            }
            huawei {
                distribution "first_ospush"
            }
        }
    }
}
"#;
    let json_value = parse_kdl_to_json(kdl_input).unwrap();
    let config: Config = serde_json::from_value(json_value).unwrap();
    let app = config.apps.get("com.example.jpush").unwrap();
    assert_eq!(app.kind, "jpush");
    let channel = app.get_object("third_party_channel").unwrap().unwrap();
    let xiaomi = channel.get("xiaomi").unwrap().as_object().unwrap();
    assert_eq!(xiaomi.get("distribution").unwrap(), "jpush");
}

#[test]
fn kdl_defaults_for_missing_sections() {
    let json_value = parse_kdl_to_json("apps {}").unwrap();
    let config: Config = serde_json::from_value(json_value).unwrap();
    assert_eq!(config.http.port, 5000);
    assert_eq!(config.http.bind_addresses, vec!["127.0.0.1"]);
    assert_eq!(config.http.notify_dedup_ttl_seconds, 0);
    assert!(!config.http.notify_rate_limits.enabled());
    assert!(!config.metrics.prometheus.enabled);
}

#[test]
fn validate_rejects_unknown_notify_dedup_backend() {
    let mut config = Config::default();
    config.http.notify_dedup.backend = "sqlite".to_owned();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("http.notify_dedup.backend must be one of"));
}

#[test]
fn validate_requires_redis_url_for_redis_notify_dedup_backend() {
    let mut config = Config::default();
    config.http.notify_dedup_ttl_seconds = 60;
    config.http.notify_dedup.backend = "redis".to_owned();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("http.notify_dedup.redis_url is required"));
}

#[test]
fn validate_requires_file_path_for_file_audit_backend() {
    let mut config = Config::default();
    config.audit.backend = "file".to_owned();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("audit.file_path is required"));
}

#[test]
fn validate_requires_http_url_for_http_audit_backend() {
    let mut config = Config::default();
    config.audit.backend = "http".to_owned();
    config.audit.endpoint = Some("mailto:audit@example.com".to_owned());

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("audit.endpoint must use http or https"));
}

#[test]
fn validate_rejects_unsafe_storage_table_names() {
    let mut config = Config::default();
    config.storage.deactivation_queue_table = "floria.queue;drop".to_owned();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("storage.deactivation_queue_table"));
}

#[test]
fn validate_requires_service_principals_for_required_signatures() {
    let mut config = Config::default();
    config.http.notify_auth.require_message_signatures = true;

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("require_message_signatures requires at least one service_principal"));
}

#[test]
fn parses_plaintext_metadata_service_ids_and_endpoint_rate_limit() {
    let config: Config = serde_saphyr::from_str(
        r#"
http:
  notify_auth:
    plaintext_metadata_service_ids: did:web:sync.example.com
  notify_rate_limits:
    per_endpoint: 10
apps: {}
"#,
    )
    .unwrap();

    assert_eq!(
        config.http.notify_auth.plaintext_metadata_service_ids,
        vec!["did:web:sync.example.com"]
    );
    assert_eq!(config.http.notify_rate_limits.per_endpoint, Some(10));
}

#[test]
fn validate_rejects_malformed_bearer_token_hash() {
    let mut config = Config::default();
    config.http.notify_auth.bearer_token_hashes = vec!["not-hex".to_owned()];

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("bearer_token_hashes"));
}

#[test]
fn validate_rejects_malformed_internal_bearer_token_hash() {
    let mut config = Config::default();
    config.http.internal_auth.bearer_token_hashes = vec!["not-hex".to_owned()];

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("http.internal_auth.bearer_token_hashes"));
}

#[test]
fn parses_internal_auth_hashes() {
    let config: Config = serde_saphyr::from_str(
        r#"
http:
  internal_auth:
    bearer_token_hashes: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
apps: {}
"#,
    )
    .unwrap();

    assert!(config.http.internal_auth.enabled());
    assert_eq!(
        config.http.internal_auth.bearer_token_hashes,
        vec!["sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
    );
}

#[test]
fn production_mode_requires_signed_or_mtls_principal() {
    let mut config = Config::default();
    config.http.notify_auth.production_mode = true;
    config.http.notify_auth.gateway_service_id = Some("did:web:push.example.com".to_owned());
    let principal = NotifyServicePrincipalConfig {
        bearer_tokens: vec!["principal-token".to_owned()],
        ..Default::default()
    };
    config
        .http
        .notify_auth
        .service_principals
        .insert("did:web:sync.example.com".to_owned(), principal);

    let error = config.validate().unwrap_err().to_string();
    assert!(
        error.contains("HTTP Message Signature or require_mtls"),
        "unexpected error: {error}"
    );
}

#[test]
fn production_mode_rejects_gateway_wide_bearer_tokens() {
    let mut config = Config::default();
    config.http.notify_auth.production_mode = true;
    config.http.notify_auth.gateway_service_id = Some("did:web:push.example.com".to_owned());
    config.http.notify_auth.bearer_tokens = vec!["gateway-token".to_owned()];
    let principal = NotifyServicePrincipalConfig {
        signature_key_id: Some("did:web:sync.example.com#push".to_owned()),
        signature_public_key_hex: Some("a".repeat(64)),
        ..Default::default()
    };
    config
        .http
        .notify_auth
        .service_principals
        .insert("did:web:sync.example.com".to_owned(), principal);

    let error = config.validate().unwrap_err().to_string();
    assert!(
        error.contains("rejects gateway-wide bearer_tokens"),
        "unexpected error: {error}"
    );
}

#[test]
fn production_mode_rejects_plaintext_service_principal_bearer_tokens() {
    let mut config = Config::default();
    config.http.notify_auth.production_mode = true;
    config.http.notify_auth.gateway_service_id = Some("did:web:push.example.com".to_owned());
    let principal = NotifyServicePrincipalConfig {
        bearer_tokens: vec!["principal-token".to_owned()],
        signature_key_id: Some("did:web:sync.example.com#push".to_owned()),
        signature_public_key_hex: Some("d".repeat(64)),
        ..Default::default()
    };
    config
        .http
        .notify_auth
        .service_principals
        .insert("did:web:sync.example.com".to_owned(), principal);

    let error = config.validate().unwrap_err().to_string();
    assert!(
        error.contains(
            "rejects plaintext bearer_tokens on service_principals.did:web:sync.example.com"
        ),
        "unexpected error: {error}"
    );
}

#[test]
fn production_mode_rejects_plaintext_for_non_eligible_kind() {
    let mut config = Config::default();
    config.http.notify_auth.production_mode = true;
    config.http.notify_auth.gateway_service_id = Some("did:web:push.example.com".to_owned());
    let principal = NotifyServicePrincipalConfig {
        signature_key_id: Some("did:web:sync.example.com#push".to_owned()),
        signature_public_key_hex: Some("b".repeat(64)),
        allow_plaintext_metadata: true,
        service_kind: Some("external_pusher".to_owned()),
        ..Default::default()
    };
    config
        .http
        .notify_auth
        .service_principals
        .insert("did:web:sync.example.com".to_owned(), principal);

    let error = config.validate().unwrap_err().to_string();
    assert!(
        error.contains("rejects allow_plaintext_metadata for service_kind"),
        "unexpected error: {error}"
    );
}

#[test]
fn production_mode_accepts_signed_eligible_principal() {
    let mut config = Config::default();
    config.http.notify_auth.production_mode = true;
    config.http.notify_auth.gateway_service_id = Some("did:web:push.example.com".to_owned());
    let principal = NotifyServicePrincipalConfig {
        signature_key_id: Some("did:web:sync.example.com#push".to_owned()),
        signature_public_key_hex: Some("c".repeat(64)),
        allow_plaintext_metadata: true,
        service_kind: Some("sync".to_owned()),
        ..Default::default()
    };
    config
        .http
        .notify_auth
        .service_principals
        .insert("did:web:sync.example.com".to_owned(), principal);

    config
        .validate()
        .expect("eligible production principal must validate");
}

#[test]
fn yaml_and_kdl_produce_equivalent_configs() {
    let yaml = r#"
http:
  port: 8080
  bind_addresses:
    - "0.0.0.0"
  notify_dedup_ttl_seconds: 30
  notify_dedup:
    backend: memory
    key_prefix: floria
  notify_rate_limits:
    window_seconds: 30
    per_origin_service: 10
    per_app_id: 20
metrics:
  prometheus:
    enabled: true
    address: "127.0.0.1"
    port: 9000
log:
  access:
    x_forwarded_for: true
apps:
  com.example.test:
    type: apns
    keyfile: "./test.p8"
    inflight_request_limit: 256
"#;
    let kdl = r#"
http {
    port 8080
    bind_addresses "0.0.0.0"
    notify_dedup_ttl_seconds 30
    notify_dedup {
        backend "memory"
        key_prefix "floria"
    }
    notify_rate_limits {
        window_seconds 30
        per_origin_service 10
        per_app_id 20
    }
}
metrics {
    prometheus {
        enabled #true
        address "127.0.0.1"
        port 9000
    }
}
log {
    access {
        x_forwarded_for #true
    }
}
apps {
    com.example.test {
        type "apns"
        keyfile "./test.p8"
        inflight_request_limit 256
    }
}
"#;

    let yaml_config: Config = serde_saphyr::from_str(yaml).unwrap();
    let kdl_json = parse_kdl_to_json(kdl).unwrap();
    let kdl_config: Config = serde_json::from_value(kdl_json).unwrap();

    // Compare via the public-shaped projection — both must produce
    // the same observable configuration.
    assert_eq!(yaml_config.http.port, kdl_config.http.port);
    assert_eq!(
        yaml_config.http.bind_addresses,
        kdl_config.http.bind_addresses
    );
    assert_eq!(
        yaml_config.http.notify_dedup_ttl_seconds,
        kdl_config.http.notify_dedup_ttl_seconds
    );
    assert_eq!(
        yaml_config.http.notify_dedup.backend_kind(),
        kdl_config.http.notify_dedup.backend_kind()
    );
    assert_eq!(
        yaml_config.http.notify_rate_limits.window_seconds,
        kdl_config.http.notify_rate_limits.window_seconds
    );
    assert_eq!(
        yaml_config.http.notify_rate_limits.per_origin_service,
        kdl_config.http.notify_rate_limits.per_origin_service
    );
    assert_eq!(
        yaml_config.http.notify_rate_limits.per_app_id,
        kdl_config.http.notify_rate_limits.per_app_id
    );
    assert_eq!(
        yaml_config.metrics.prometheus.enabled,
        kdl_config.metrics.prometheus.enabled
    );
    assert_eq!(
        yaml_config.metrics.prometheus.port,
        kdl_config.metrics.prometheus.port
    );
    assert_eq!(
        yaml_config.log.access.x_forwarded_for,
        kdl_config.log.access.x_forwarded_for
    );
    assert_eq!(yaml_config.apps.len(), kdl_config.apps.len());
    let yaml_app = yaml_config.apps.get("com.example.test").unwrap();
    let kdl_app = kdl_config.apps.get("com.example.test").unwrap();
    assert_eq!(yaml_app.kind, kdl_app.kind);
    assert_eq!(
        yaml_app.get_string("keyfile").unwrap(),
        kdl_app.get_string("keyfile").unwrap()
    );
    assert_eq!(
        yaml_app.get_u64("inflight_request_limit").unwrap(),
        kdl_app.get_u64("inflight_request_limit").unwrap()
    );
}

#[test]
fn kdl_to_json_round_trip_preserves_nested_structure() {
    let kdl = r#"
apps {
    com.example.jpush {
        type "jpush"
        app_key "test-key"
        master_secret "test-secret"
        third_party_channel {
            xiaomi {
                distribution "jpush"
            }
            huawei {
                distribution "first_ospush"
            }
        }
    }
}
"#;
    let parsed = parse_kdl_to_json(kdl).unwrap();
    let serialized = serde_json::to_string(&parsed).unwrap();
    let reparsed: Value = serde_json::from_str(&serialized).unwrap();
    assert_eq!(parsed, reparsed);

    // Round-tripping through Config preserves the nested provider config.
    let config: Config = serde_json::from_value(parsed).unwrap();
    let app = config.apps.get("com.example.jpush").unwrap();
    let channel = app.get_object("third_party_channel").unwrap().unwrap();
    assert_eq!(
        channel
            .get("xiaomi")
            .and_then(|value| value.get("distribution"))
            .and_then(Value::as_str),
        Some("jpush"),
    );
    assert_eq!(
        channel
            .get("huawei")
            .and_then(|value| value.get("distribution"))
            .and_then(Value::as_str),
        Some("first_ospush"),
    );
}
