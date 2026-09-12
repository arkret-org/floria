use serde_json::json;

#[test]
fn e2ee_late_recovery_access_kind_matches_push_wire_repr() {
    let metadata =
        serde_json::from_value::<arkret_models_integration::PushAuditEnvelopeMetadata>(json!({
            "access_kind": "e2ee_late_recovery",
            "late_recovery_original_event_id":
                "ak:event:AYf05kF8z4cSo8r6qmqXgu4KPuv2YtKBlsE00FOmblaz"
        }))
        .unwrap();

    assert_eq!(metadata.access_kind, "e2ee_late_recovery");
}

fn notify_request_with_wakeup_kind(kind: &str) -> arkret_models_integration::PushNotifyRequestBody {
    arkret_models_integration::PushNotifyRequestBody {
        notification: arkret_models_integration::PushNotificationEnvelope {
            push_target_id: Some(
                arkret_wire::PushTargetId::new(
                    "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
                )
                .unwrap(),
            ),
            wakeup_kind: Some(kind.to_owned()),

            devices: vec![arkret_models_integration::PushDeviceRoute {
                device_id: arkret_wire::DeviceId::new(
                    "ak:device:0196419b-0000-7000-8000-000000000001",
                )
                .unwrap(),
            }],
            ..arkret_models_integration::PushNotificationEnvelope::default()
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
        arkret_models_integration::validate_push_notify_contract_shape(
            &notify_request_with_wakeup_kind(kind),
        )
        .unwrap();
    }

    let err = arkret_models_integration::validate_push_notify_contract_shape(
        &notify_request_with_wakeup_kind("custom_kind"),
    )
    .unwrap_err();
    assert!(err.contains("assignment"));
    assert!(err.contains("schedule"));
    assert!(err.contains("reminder"));
    assert!(err.contains("scheduled_send"));
    assert!(err.contains("expiry_invalidation"));
}

#[test]
fn notify_ingress_rejects_removed_timing_hint() {
    let mut raw = serde_json::to_value(notify_request_with_wakeup_kind("message")).unwrap();
    raw["notification"]["timing_profile_hint"] = json!("default");
    assert!(
        serde_json::from_value::<arkret_models_integration::PushNotifyRequestBody>(raw).is_err()
    );
}
