use serde_json::json;

use super::validation::validate_wakeup_kind;

#[test]
fn e2ee_late_recovery_access_kind_matches_sdk_wire_repr() {
    let sdk_wire = serde_json::to_value(cokret::AccessKind::E2EELateRecovery).unwrap();

    assert_eq!(sdk_wire, json!("e2ee_late_recovery"));
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
        validate_wakeup_kind(Some(&json!(kind))).unwrap();
    }

    let err = validate_wakeup_kind(Some(&json!("custom_kind"))).unwrap_err();
    assert!(err.contains("assignment"));
    assert!(err.contains("schedule"));
    assert!(err.contains("reminder"));
    assert!(err.contains("scheduled_send"));
    assert!(err.contains("expiry_invalidation"));
}
