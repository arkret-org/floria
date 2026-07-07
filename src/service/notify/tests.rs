use serde_json::json;

#[test]
fn e2ee_late_recovery_access_kind_matches_sdk_wire_repr() {
    let sdk_wire = serde_json::to_value(cokret::AccessKind::E2EELateRecovery).unwrap();

    assert_eq!(sdk_wire, json!("e2ee_late_recovery"));
}

fn notify_request_with_wakeup_kind(kind: &str) -> cokret::PushNotifyRequestBody {
    cokret::PushNotifyRequestBody {
        notification: cokret::PushNotificationEnvelope {
            push_target_id: Some("ck:pseudonym:push:01HYZ8Z000000000000000".to_owned()),
            wakeup_kind: Some(kind.to_owned()),
            ..cokret::PushNotificationEnvelope::default()
        },
        event_kind: None,
        reason_code: None,
        audit_envelope: None,
    }
}

#[test]
fn targeted_and_productivity_wakeup_kinds_match_sdk_allow_list() {
    for kind in [
        "assignment",
        "schedule",
        "reminder",
        "scheduled_send",
        "expiry_invalidation",
    ] {
        cokret::validate_push_notify_contract_shape(&notify_request_with_wakeup_kind(kind))
            .unwrap();
    }

    let err = cokret::validate_push_notify_contract_shape(&notify_request_with_wakeup_kind(
        "custom_kind",
    ))
    .unwrap_err();
    assert!(err.contains("assignment"));
    assert!(err.contains("schedule"));
    assert!(err.contains("reminder"));
    assert!(err.contains("scheduled_send"));
    assert!(err.contains("expiry_invalidation"));
}
