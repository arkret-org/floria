use serde_json::json;

#[test]
fn e2ee_late_recovery_access_kind_matches_sdk_wire_repr() {
    let sdk_wire = serde_json::to_value(arkret::AccessKind::E2EELateRecovery).unwrap();

    assert_eq!(sdk_wire, json!("e2ee_late_recovery"));
}

fn notify_request_with_wakeup_kind(kind: &str) -> arkret::PushNotifyRequestBody {
    arkret::PushNotifyRequestBody {
        notification: arkret::PushNotificationEnvelope {
            push_target_id: Some("ak:pseudonym:push:01HYZ8Z000000000000000".to_owned()),
            wakeup_kind: Some(kind.to_owned()),
            timing_profile_hint: Some(arkret::PushTimingProfileHint::Default),
            ..arkret::PushNotificationEnvelope::default()
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
        arkret::validate_push_notify_contract_shape(&notify_request_with_wakeup_kind(kind))
            .unwrap();
    }

    let err = arkret::validate_push_notify_contract_shape(&notify_request_with_wakeup_kind(
        "custom_kind",
    ))
    .unwrap_err();
    assert!(err.contains("assignment"));
    assert!(err.contains("schedule"));
    assert!(err.contains("reminder"));
    assert!(err.contains("scheduled_send"));
    assert!(err.contains("expiry_invalidation"));
}

#[test]
fn notify_ingress_accepts_hardened_timing_profile_hint() {
    let request = serde_json::from_value::<arkret::PushNotifyRequestBody>(json!({
            "notification": {
                "push_target_id": "ak:pseudonym:push:01HYZ8Z000000000000000",
                "wakeup_kind": "message",
                "timing_profile_hint": "traffic_metadata_hardened",
                "devices": []
            }
    }))
    .unwrap();
    arkret::validate_push_notify_contract_shape(&request).unwrap();

    assert_eq!(
        request.notification.timing_profile_hint,
        Some(arkret::PushTimingProfileHint::TrafficMetadataHardened)
    );
    assert_eq!(
        request.notification.push_target_id.as_deref(),
        Some("ak:pseudonym:push:01HYZ8Z000000000000000")
    );
}

#[test]
fn notify_ingress_rejects_unknown_timing_profile_hint() {
    let err = serde_json::from_value::<arkret::PushNotifyRequestBody>(json!({
            "notification": {
                "push_target_id": "ak:pseudonym:push:01HYZ8Z000000000000000",
                "wakeup_kind": "message",
                "timing_profile_hint": "minimal_metadata",
                "devices": []
            }
    }))
    .unwrap_err();

    assert!(err.to_string().contains("traffic_metadata_hardened"));
}
