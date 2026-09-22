use std::collections::HashSet;
use std::time::{Duration, Instant};

use super::response::DispatchSummary;
use super::*;

pub(super) async fn dispatch_notification_devices(
    state: &Arc<AppState>,
    notification: &PushNotificationEnvelope,
    registrations: &[Option<arkret_models_integration::PushRegistrationRecord>],
    source: &arkret_wire::DidCoreId,
    context: &NotificationContext,
    dedup_key: &str,
) -> DispatchSummary {
    let mut rejected = Vec::new();
    let mut outcomes = Vec::with_capacity(notification.devices.len());
    let mut delivered_now = 0usize;
    let mut skipped_delivered = 0usize;
    let mut delivery_receipts = Vec::new();
    let mut taken_over_this_request = HashSet::new();
    let mut first_remote_error: Option<String> = None;
    let mut first_temporary_error: Option<(String, Option<Duration>)> = None;
    let mut first_internal_error: Option<String> = None;
    let mut provider_timing_bucket_applied = false;
    let provider_timing_bucket = state.provider_timing_bucket;

    for (requested, registration) in notification.devices.iter().zip(registrations) {
        let Some(device) = registration.as_ref() else {
            outcomes.push(PushNotifyDeviceOutcome::rejected(
                requested.device_id.clone(),
                PushNotifyReasonCode::PushTargetUnknown,
                None,
            ));
            continue;
        };
        let app_id = device.app_id().unwrap_or_default();
        let push_key = device.push_key().unwrap_or_default();
        if app_id.is_empty() || push_key.is_empty() {
            tracing::warn!(
                request_id = %context.request_id,
                app_id,
                push_key_hash = %device.redacted_push_key(),
                "rejecting device with empty app_id or push_key"
            );
            rejected.push(rejected_device(device, device.push_key()));
            outcomes.push(PushNotifyDeviceOutcome::rejected(
                device.device_id.clone(),
                PushNotifyReasonCode::PushTokenInvalid,
                None,
            ));
            delivery_receipts.push(delivery_receipt(
                None,
                push_key,
                "rejected",
                None,
                &context.request_id,
            ));
            continue;
        }

        app_metrics::device_push_received();
        let pushkins = state.registry.find_pushkins(app_id);
        match pushkins.as_slice() {
            [] => {
                tracing::warn!(request_id = %context.request_id, app_id, push_key_hash = %device.redacted_push_key(), "unknown app id");
                rejected.push(rejected_device(device, device.push_key()));
                outcomes.push(PushNotifyDeviceOutcome::rejected(
                    device.device_id.clone(),
                    PushNotifyReasonCode::UnsupportedProfile,
                    None,
                ));
                delivery_receipts.push(delivery_receipt(
                    None,
                    push_key,
                    "rejected",
                    None,
                    &context.request_id,
                ));
                continue;
            }
            [pushkin] => {
                let delivered_before = if taken_over_this_request
                    .contains(&(app_id.to_owned(), push_key.to_owned()))
                {
                    false
                } else if let Some(deduplicator) = state.notify_deduplicator.as_ref() {
                    deduplicator
                        .contains_delivered_device_async(dedup_key, app_id, push_key)
                        .await
                } else {
                    false
                };
                if delivered_before {
                    skipped_delivered += 1;
                    outcomes.push(PushNotifyDeviceOutcome::duplicate(device.device_id.clone()));
                    app_metrics::notify_device_skip_hit(1);
                    app_metrics::notify_device_skip_by_pushkin(pushkin.name(), 1);
                    delivery_receipts.push(delivery_receipt(
                        Some(pushkin.name()),
                        push_key,
                        "accepted_cached",
                        None,
                        &context.request_id,
                    ));
                    tracing::info!(
                        request_id = %context.request_id,
                        app_id,
                        push_key_hash = %device.redacted_push_key(),
                        pushkin = %pushkin.name(),
                        "skipping device already delivered within dedup ttl"
                    );
                    continue;
                }

                app_metrics::pushkin_selected(pushkin.name());
                let dispatch_targets = pushkin.dispatch_targets(notification, device);
                let breaker_key = circuit_breaker_key(pushkin.name(), notification);
                let (breaker_scope_kind, breaker_scope_id) = circuit_breaker_scope(notification);
                if let Some(breaker) = state.circuit_breaker.as_ref()
                    && breaker.is_open(&breaker_key)
                {
                    app_metrics::set_circuit_breaker_state(
                        pushkin.name(),
                        breaker_scope_kind,
                        breaker_scope_id,
                        2,
                    );
                    tracing::warn!(
                        request_id = %context.request_id,
                        app_id,
                        pushkin = %pushkin.name(),
                        realm_id = ?notification.realm_id(),
                        has_scope_route_token = notification.scope_route_token().is_some(),
                        "short-circuiting dispatch because circuit breaker is open"
                    );
                    for target in &dispatch_targets {
                        delivery_receipts.push(delivery_receipt(
                            Some(pushkin.name()),
                            &target.push_key,
                            "retryable",
                            Some(CIRCUIT_BREAKER_RETRY_AFTER),
                            &context.request_id,
                        ));
                    }
                    first_temporary_error.get_or_insert_with(|| {
                        (
                            "push provider circuit breaker is open".to_owned(),
                            Some(CIRCUIT_BREAKER_RETRY_AFTER),
                        )
                    });
                    outcomes.push(PushNotifyDeviceOutcome::rejected(
                        device.device_id.clone(),
                        PushNotifyReasonCode::PushGatewayUnreachable,
                        Some(duration_millis(CIRCUIT_BREAKER_RETRY_AFTER)),
                    ));
                    app_metrics::notify_delivery_outcome_by_app(app_id, "retryable", 1);
                    continue;
                }
                if !provider_timing_bucket_applied {
                    wait_for_provider_timing_bucket(&context.request_id, provider_timing_bucket)
                        .await;
                    provider_timing_bucket_applied = true;
                }
                let dispatch_started = Instant::now();
                // Timing buckets may outlive a token rotation or user opt-out.
                // Recheck the durable registration immediately before provider I/O.
                let current = state
                    .resolve_registration(source, &push_target_id(notification), &device.device_id)
                    .await;
                match current {
                    Ok(Some(current))
                        if current.account_id == device.account_id
                            && current.push_key == device.push_key
                            && current.app_id == device.app_id
                            && current.platform == device.platform
                            && current.visible_notification_opt_in
                                == device.visible_notification_opt_in => {}
                    Ok(_) => {
                        outcomes.push(PushNotifyDeviceOutcome::rejected(
                            device.device_id.clone(),
                            PushNotifyReasonCode::PushTargetUnknown,
                            None,
                        ));
                        continue;
                    }
                    Err(error) => {
                        tracing::warn!(%error, "registration recheck failed before dispatch");
                        outcomes.push(PushNotifyDeviceOutcome::rejected(
                            device.device_id.clone(),
                            PushNotifyReasonCode::PushGatewayUnreachable,
                            Some(1000),
                        ));
                        continue;
                    }
                }
                let dispatch_result = pushkin
                    .dispatch_notification(notification, device, context)
                    .await;
                if let Some(breaker) = state.circuit_breaker.as_ref() {
                    match &dispatch_result {
                        Ok(_) => {
                            breaker.record_success(&breaker_key);
                            app_metrics::set_circuit_breaker_state(
                                pushkin.name(),
                                breaker_scope_kind,
                                breaker_scope_id,
                                0,
                            );
                        }
                        Err(error) => {
                            let opened = breaker.record_failure(&breaker_key);
                            app_metrics::set_circuit_breaker_state(
                                pushkin.name(),
                                breaker_scope_kind,
                                breaker_scope_id,
                                if opened { 2 } else { 0 },
                            );
                            if opened {
                                tracing::warn!(
                                    error = error.safe_summary(),
                                    request_id = %context.request_id,
                                    app_id,
                                    pushkin = %pushkin.name(),
                                    realm_id = ?notification.realm_id(),
                                    has_scope_route_token = notification.scope_route_token().is_some(),
                                    "opened push provider circuit breaker"
                                );
                            }
                        }
                    }
                }
                let dispatch_outcome = match &dispatch_result {
                    Ok(rejected) if rejected.is_empty() => "accepted",
                    Ok(_) => "partial",
                    Err(error) if error.is_temporary() => "retryable",
                    Err(error) if error.is_remote() => "remote_error",
                    Err(_) => "internal_error",
                };
                app_metrics::observe_pushkin_dispatch(
                    pushkin.name(),
                    dispatch_outcome,
                    dispatch_started.elapsed(),
                );
                app_metrics::notify_delivery_outcome_by_app(app_id, dispatch_outcome, 1);
                match dispatch_result {
                    Ok(mut pushkin_rejected) => {
                        let rejected_set = pushkin_rejected
                            .iter()
                            .cloned()
                            .collect::<HashSet<String>>();
                        if rejected_set.contains(push_key)
                            && let Some(store) = state.registration_handoff.as_ref()
                            && let Err(error) = store
                                .terminalize_provider_invalidation(source, device)
                                .await
                        {
                            tracing::warn!(
                                %error,
                                request_id = %context.request_id,
                                registration_id = %device.registration_id,
                                "failed to durably tombstone provider-invalid registration"
                            );
                            first_internal_error.get_or_insert_with(|| {
                                "failed to persist provider registration invalidation".to_owned()
                            });
                            outcomes.push(PushNotifyDeviceOutcome::rejected(
                                device.device_id.clone(),
                                PushNotifyReasonCode::PushGatewayUnreachable,
                                Some(1000),
                            ));
                            continue;
                        }
                        let delivered_targets = dispatch_targets
                            .iter()
                            .filter(|target| !rejected_set.contains(target.push_key.as_str()))
                            .cloned()
                            .collect::<Vec<_>>();
                        if delivered_targets.is_empty() && !pushkin_rejected.is_empty() {
                            outcomes.push(PushNotifyDeviceOutcome::rejected(
                                device.device_id.clone(),
                                PushNotifyReasonCode::PushTokenUnknown,
                                None,
                            ));
                        } else {
                            outcomes
                                .push(PushNotifyDeviceOutcome::accepted(device.device_id.clone()));
                        }
                        if !delivered_targets.is_empty() {
                            delivered_now += delivered_targets.len();
                            for target in &delivered_targets {
                                delivery_receipts.push(delivery_receipt(
                                    Some(pushkin.name()),
                                    &target.push_key,
                                    "accepted",
                                    None,
                                    &context.request_id,
                                ));
                            }
                            mark_delivered_devices(state, dedup_key, delivered_targets).await;
                            taken_over_this_request
                                .insert((app_id.to_owned(), push_key.to_owned()));
                        }
                        rejected.extend(pushkin_rejected.drain(..).map(|push_key| {
                            delivery_receipts.push(delivery_receipt(
                                Some(pushkin.name()),
                                &push_key,
                                "rejected",
                                None,
                                &context.request_id,
                            ));
                            rejected_device(device, Some(&push_key))
                        }));
                    }
                    Err(error) if error.is_temporary() => {
                        let retry_after = error.retry_after();
                        tracing::warn!(
                            error = error.safe_summary(),
                            request_id = %context.request_id,
                            app_id,
                            push_key_hash = %device.redacted_push_key(),
                            "temporary dispatch failure"
                        );
                        for target in &dispatch_targets {
                            delivery_receipts.push(delivery_receipt(
                                Some(pushkin.name()),
                                &target.push_key,
                                "retryable",
                                retry_after,
                                &context.request_id,
                            ));
                            enqueue_retry(
                                state,
                                &context.request_id,
                                pushkin.name(),
                                source,
                                notification,
                                device,
                                retry_after,
                                &error,
                            )
                            .await;
                        }
                        if state.notify_retry_queue.is_some() {
                            outcomes
                                .push(PushNotifyDeviceOutcome::accepted(device.device_id.clone()));
                        } else {
                            outcomes.push(PushNotifyDeviceOutcome::rejected(
                                device.device_id.clone(),
                                PushNotifyReasonCode::PushGatewayUnreachable,
                                Some(duration_millis(
                                    retry_after.unwrap_or(CIRCUIT_BREAKER_RETRY_AFTER),
                                )),
                            ));
                        }
                        first_temporary_error
                            .get_or_insert_with(|| (error.safe_summary().to_owned(), retry_after));
                    }
                    Err(error) if error.is_remote() => {
                        outcomes.push(PushNotifyDeviceOutcome::rejected(
                            device.device_id.clone(),
                            PushNotifyReasonCode::PushGatewayUnreachable,
                            Some(duration_millis(CIRCUIT_BREAKER_RETRY_AFTER)),
                        ));
                        tracing::warn!(
                            error = error.safe_summary(),
                            request_id = %context.request_id,
                            app_id,
                            push_key_hash = %device.redacted_push_key(),
                            "remote dispatch failure"
                        );
                        for target in &dispatch_targets {
                            delivery_receipts.push(delivery_receipt(
                                Some(pushkin.name()),
                                &target.push_key,
                                "failed",
                                None,
                                &context.request_id,
                            ));
                        }
                        first_remote_error.get_or_insert_with(|| error.safe_summary().to_owned());
                    }
                    Err(error) => {
                        outcomes.push(PushNotifyDeviceOutcome::rejected(
                            device.device_id.clone(),
                            PushNotifyReasonCode::PushGatewayUnreachable,
                            Some(duration_millis(CIRCUIT_BREAKER_RETRY_AFTER)),
                        ));
                        tracing::error!(
                            error = error.safe_summary(),
                            request_id = %context.request_id,
                            app_id,
                            push_key_hash = %device.redacted_push_key(),
                            "internal dispatch failure"
                        );
                        for target in &dispatch_targets {
                            delivery_receipts.push(delivery_receipt(
                                Some(pushkin.name()),
                                &target.push_key,
                                "failed",
                                None,
                                &context.request_id,
                            ));
                        }
                        first_internal_error.get_or_insert_with(|| error.safe_summary().to_owned());
                    }
                }
            }
            _ => {
                tracing::warn!(request_id = %context.request_id, app_id, push_key_hash = %device.redacted_push_key(), "ambiguous app id");
                rejected.push(rejected_device(device, device.push_key()));
                outcomes.push(PushNotifyDeviceOutcome::rejected(
                    device.device_id.clone(),
                    PushNotifyReasonCode::UnsupportedProfile,
                    None,
                ));
                delivery_receipts.push(delivery_receipt(
                    None,
                    push_key,
                    "rejected",
                    None,
                    &context.request_id,
                ));
            }
        }
    }

    DispatchSummary {
        rejected,
        outcomes,
        delivered_now,
        skipped_delivered,
        delivery_receipts,
        first_remote_error,
        first_temporary_error,
        first_internal_error,
    }
}
