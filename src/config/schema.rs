use serde_json::Value;

use super::Config;

// --- Schema artifact ---

/// Returns the JSON schema for `floria.{kdl,yaml}` configuration.
///
/// Both YAML and KDL deserialize through the same `Config` struct, so a
/// single schema document covers both formats. Consumers (ops tooling,
/// editor tooling, soland config drift detection) should refresh when
/// `Config::SCHEMA_VERSION` changes.
pub fn config_json_schema() -> Value {
    serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://arkret.dev/schema/floria/2026-06-03.1/floria.config.schema.json",
        "title": "floria gateway configuration",
        "description": "Schema for floria.kdl / floria.yaml; KDL is parsed to JSON via the same shape before deserialization.",
        "type": "object",
        "x-floria-schema-version": Config::SCHEMA_VERSION,
        "additionalProperties": false,
        "properties": {
            "http": http_schema(),
            "audit": audit_schema(),
            "storage": storage_schema(),
            "log": log_schema(),
            "metrics": metrics_schema(),
            "proxy": {"type": ["string", "null"], "description": "Outbound proxy URL for APNs/FCM/WebPush. Falls back to HTTPS_PROXY env."},
            "apps": {
                "type": "object",
                "additionalProperties": app_config_schema(),
                "description": "Map of app identifiers to provider configuration."
            }
        }
    })
}

fn storage_schema() -> Value {
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "description": "Optional PostgreSQL storage for deactivation queue draining.",
        "properties": {
            "postgres_url": {
                "type": ["string", "null"],
                "description": "PostgreSQL connection URL. When unset, deactivation bookkeeping is in-memory only."
            },
            "deactivation_queue_table": {
                "type": "string",
                "default": "floria_push_delivery_queue",
                "description": "Table drained by account_deactivate_fanout. Must be `table` or `schema.table` with simple SQL identifiers."
            }
        }
    })
}

fn audit_schema() -> Value {
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "description": "Audit sink for policy-access and rejected-device events. disabled keeps audit events unavailable; file writes local JSONL; http POSTs JSON to the soland audit endpoint.",
        "properties": {
            "backend": {"type": "string", "enum": ["disabled", "file", "http"], "default": "disabled"},
            "file_path": {
                "type": ["string", "null"],
                "description": "JSONL file path used when backend=file. Relative paths resolve against the config file directory."
            },
            "endpoint": {
                "type": ["string", "null"],
                "format": "uri",
                "description": "HTTP(S) endpoint used when backend=http. floria POSTs the audit event JSON body to this URL."
            },
            "bearer_token": {
                "type": ["string", "null"],
                "description": "Optional bearer token for backend=http."
            }
        }
    })
}

fn http_schema() -> Value {
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "port": {"type": "integer", "minimum": 1, "maximum": 65535, "default": 5000},
            "bind_addresses": {
                "oneOf": [
                    {"type": "string"},
                    {"type": "array", "items": {"type": "string"}, "minItems": 1}
                ],
                "default": "127.0.0.1"
            },
            "notify_dedup_ttl_seconds": {"type": "integer", "minimum": 0, "default": 0},
            "notify_dedup": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "backend": {"type": "string", "enum": ["memory", "redis"], "default": "memory"},
                    "redis_url": {"type": ["string", "null"]},
                    "key_prefix": {"type": "string", "default": "floria"}
                }
            },
            "notify_auth": notify_auth_schema(),
            "internal_auth": internal_auth_schema(),
            "notify_rate_limits": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "window_seconds": {"type": "integer", "minimum": 1, "default": 60},
                    "per_origin_service": {"type": ["integer", "null"], "minimum": 0},
                    "per_app_id": {"type": ["integer", "null"], "minimum": 0},
                    "per_provider": {"type": ["integer", "null"], "minimum": 0},
                    "per_push_key_hash": {"type": ["integer", "null"], "minimum": 0},
                    "per_endpoint": {"type": ["integer", "null"], "minimum": 0},
                    "backend": {"type": "string", "enum": ["memory", "redis"], "default": "memory"},
                    "redis_url": {"type": ["string", "null"]},
                    "key_prefix": {"type": "string", "default": "floria"},
                    "redis_failure_policy": {"type": "string", "enum": ["strict", "permissive"], "default": "strict"}
                }
            },
            "notify_retry_queue": {
                "type": "object",
                "additionalProperties": false,
                "description": "Retry / dead-letter queue for transient pushkin failures.",
                "properties": {
                    "enabled": {"type": "boolean", "default": false},
                    "backend": {"type": "string", "enum": ["memory", "redis"], "default": "memory"},
                    "redis_url": {"type": ["string", "null"]},
                    "key_prefix": {"type": "string", "default": "floria"},
                    "max_attempts": {"type": "integer", "minimum": 1, "default": 5},
                    "default_backoff_seconds": {"type": "integer", "minimum": 1, "default": 30},
                    "max_backoff_seconds": {"type": "integer", "minimum": 1, "default": 900},
                    "dead_letter_capacity": {"type": "integer", "minimum": 1, "default": 1024},
                    "poll_interval_ms": {"type": "integer", "minimum": 100, "default": 1000},
                    "batch_item_count": {"type": "integer", "minimum": 1, "default": 32},
                    "encryption_key": {"type": "string", "default": ""},
                    "encryption_key_file": {"type": ["string", "null"]},
                    "grace_period_secs": {"type": "integer", "minimum": 1, "default": 30},
                    "deadletter_pg_url": {
                        "type": ["string", "null"],
                        "description": "Optional PostgreSQL URL for the dead-letter overlay. When set, every dead-lettered envelope is also persisted to `deadletter_pg_table` so it survives a process restart."
                    },
                    "deadletter_pg_table": {
                        "type": "string",
                        "default": "floria_retry_dead_letter",
                        "description": "Table the deadletter overlay writes into. Must be `table` or `schema.table` with simple SQL identifiers."
                    }
                }
            },
            "metrics_detailed_circle_labels": {
                "type": "boolean",
                "default": false,
                "description": "AKP-0007 Circle primitive. When true, the per-(provider, scope) delivery counter (floria_notify_delivery_total) labels scope_id with the circle_id instead of the parent realm_id. Default false bounds label cardinality by realm count."
            }
        }
    })
}

fn internal_auth_schema() -> Value {
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "description": "Bearer/shared-secret authentication for internal and operator-only endpoints. When no token or hash is configured, those endpoints fail closed.",
        "properties": {
            "bearer_tokens": string_or_string_list_schema(),
            "bearer_token_hashes": {
                "description": "Plain or `sha256:`-prefixed 32-byte hex digests of internal bearer tokens.",
                "oneOf": [
                    {"type": "string"},
                    {"type": "array", "items": {"type": "string"}}
                ]
            }
        }
    })
}

fn notify_auth_schema() -> Value {
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "bearer_tokens": string_or_string_list_schema(),
            "bearer_token_hashes": {
                "description": "Plain or `sha256:`-prefixed 32-byte hex digests of bearer tokens.",
                "oneOf": [
                    {"type": "string"},
                    {"type": "array", "items": {"type": "string"}}
                ]
            },
            "trusted_service_ids": {
                "description": "Allowlisted stable service core ids carried by Source-Service-ID.",
                "oneOf": [
                    {"type": "string"},
                    {"type": "array", "items": {"type": "string"}}
                ]
            },
            "plaintext_metadata_service_ids": {
                "description": "Stable service core ids allowed to send visible notification metadata.",
                "oneOf": [
                    {"type": "string"},
                    {"type": "array", "items": {"type": "string"}}
                ]
            },
            "gateway_service_id": {
                "type": ["string", "null"],
                "description": "Resolvable full DID for this gateway; its stable core is derived for service_id and transport headers."
            },
            "gateway_service_method_history_head": {"type": ["string", "null"], "minLength": 1},
            "gateway_service_version_id": {"type": ["string", "null"], "minLength": 1},
            "require_message_signatures": {"type": "boolean", "default": false},
            "signature_max_skew_seconds": {"type": "integer", "minimum": 1, "default": 300},
            "mtls_verified_header": {"type": "string", "default": "x-client-certificate-verified"},
            "mtls_fingerprint_header": {"type": "string", "default": "x-client-certificate-sha256"},
            "mtls_subject_dn_header": {"type": "string", "default": "x-client-certificate-subject"},
            "mtls_subject_alt_names_header": {"type": "string", "default": "x-client-certificate-san"},
            "production_mode": {
                "type": "boolean",
                "default": false,
                "description": "When true, refuses to start in profiles that allow anonymous or bearer-only auth without HTTP Message Signature/mTLS."
            },
            "bind_bearer_to_origin_did": {
                "type": "boolean",
                "default": false,
                "description": "When true, gateway-wide bearer tokens are rejected; the bearer must match a per-principal token for the declared origin_service_id."
            },
            "service_principals": {
                "type": "object",
                "description": "Per-service authentication profiles keyed by stable service core id.",
                "additionalProperties": service_principal_schema()
            },
            "nonce_store": {
                "type": "object",
                "additionalProperties": false,
                "description": "HTTP Message Signature replay-protection nonce store. Memory backend is single-instance; redis backend shares state across replicas.",
                "properties": {
                    "backend": {"type": "string", "enum": ["memory", "redis"], "default": "memory"},
                    "redis_url": {"type": ["string", "null"]},
                    "key_prefix": {"type": "string", "default": "floria"},
                    "redis_failure_policy": {"type": "string", "enum": ["strict", "permissive"], "default": "strict"}
                }
            },
            "replay_window_seconds": {
                "type": "integer",
                "minimum": 0,
                "default": 0,
                "description": "How long to remember a verified Signature fingerprint for replay rejection. Must be >0 when require_message_signatures is true or nonce_store.backend=redis."
            }
        }
    })
}

fn service_principal_schema() -> Value {
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "service_kind": {"type": ["string", "null"]},
            "allow_plaintext_metadata": {"type": "boolean", "default": false},
            "bearer_tokens": string_or_string_list_schema(),
            "bearer_token_hashes": string_or_string_list_schema(),
            "signature_key_id": {"type": ["string", "null"]},
            "signature_public_key_hex": {"type": ["string", "null"], "pattern": "^[0-9a-fA-F]{64}$"},
            "require_mtls": {"type": "boolean", "default": false},
            "mtls_cert_fingerprints": string_or_string_list_schema(),
            "mtls_subject_dn": {"type": ["string", "null"]},
            "mtls_subject_alt_names": string_or_string_list_schema(),
            "service_endpoint": {"type": ["string", "null"]}
        }
    })
}

fn log_schema() -> Value {
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "access": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "x_forwarded_for": {"type": "boolean", "default": false}
                }
            },
            "setup": {
                "type": "object",
                "additionalProperties": false,
                "description": "tracing-subscriber setup. Controls the global subscriber installed at startup.",
                "properties": {
                    "level": {
                        "type": "string",
                        "enum": ["trace", "debug", "info", "warn", "error"],
                        "default": "info"
                    },
                    "format": {
                        "type": "string",
                        "enum": ["text", "json"],
                        "default": "text"
                    },
                    "filter": {
                        "type": ["string", "null"],
                        "description": "Optional EnvFilter directive (e.g. `floria=debug,tower_http=info`). Falls back to RUST_LOG, then `level`."
                    }
                }
            }
        }
    })
}

fn metrics_schema() -> Value {
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "prometheus": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "enabled": {"type": "boolean", "default": false},
                    "address": {"type": "string", "default": "127.0.0.1"},
                    "port": {"type": "integer", "minimum": 1, "maximum": 65535, "default": 8000}
                }
            },
            "opentracing": {
                "type": "object",
                "additionalProperties": false,
                "description": "OpenTelemetry / OTLP span exporter (gRPC).",
                "properties": {
                    "enabled": {"type": "boolean", "default": false},
                    "endpoint": {
                        "type": ["string", "null"],
                        "description": "OTLP gRPC endpoint (e.g. http://otel-collector:4317). Required when enabled."
                    },
                    "service_name": {"type": "string", "default": "floria"},
                    "sample_rate": {"type": "number", "minimum": 0, "maximum": 1, "default": 1.0},
                    "timeout_seconds": {"type": "integer", "minimum": 1, "default": 10},
                    "implementation": {
                        "type": ["string", "null"],
                        "description": "Reserved for future tracer back-ends; currently OTLP/gRPC is the only supported implementation. Existing values like `jaeger` are accepted but ignored."
                    }
                }
            },
            "sentry": {
                "type": "object",
                "additionalProperties": false,
                "description": "Sentry error capture via the tracing subscriber.",
                "properties": {
                    "enabled": {"type": "boolean", "default": false},
                    "dsn": {"type": ["string", "null"], "description": "Sentry DSN. Required when enabled."},
                    "environment": {"type": ["string", "null"]},
                    "release": {"type": ["string", "null"]},
                    "sample_rate": {"type": "number", "minimum": 0, "maximum": 1, "default": 1.0},
                    "traces_sample_rate": {"type": "number", "minimum": 0, "maximum": 1, "default": 0.0}
                }
            }
        }
    })
}

fn app_config_schema() -> Value {
    serde_json::json!({
        "type": "object",
        "required": ["type"],
        "properties": {
            "type": {
                "type": "string",
                "enum": [
                    "apns",
                    "custom",
                    "fcm",
                    "honor",
                    "huawei",
                    "jpush",
                    "oneplus",
                    "oppo",
                    "vivo",
                    "webpush",
                    "xiaomi"
                ]
            },
            "inflight_request_limit": {"type": "integer", "minimum": 1, "default": 512},
            "max_connections": {"type": "integer", "minimum": 1, "default": 20}
        },
        "additionalProperties": true,
        "description": "Per-provider keys are passed through; required fields differ per `type` and are validated at startup."
    })
}

fn string_or_string_list_schema() -> Value {
    serde_json::json!({
        "oneOf": [
            {"type": "string"},
            {"type": "array", "items": {"type": "string"}}
        ]
    })
}
