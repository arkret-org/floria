use std::sync::Arc;
use std::time::Instant;

use arkret_models_integration::PushRegistrationHandoffRequestBody;
use salvo::http::{ParseError, StatusCode};
use salvo::prelude::*;
use uuid::Uuid;

use super::MAX_REQUEST_SIZE;
use super::metrics::finish_error;
use crate::AppState;
use crate::auth::authenticate_registration_handoff_request;
use crate::registration_handoff::ApplyRegistrationError;

#[handler]
pub(super) async fn apply(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let started = Instant::now();
    let request_id = Uuid::new_v4().to_string();
    let state = match depot.get_typed::<Arc<AppState>>() {
        Ok(state) => state.clone(),
        Err(_) => {
            reject(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                arkret_wire::error_codes::ErrorCode::INTERNAL_ERROR,
                "application state missing",
                &request_id,
                started,
            );
            return;
        }
    };
    let body = match req.payload_with_max_size(MAX_REQUEST_SIZE).await {
        Ok(body) => body.to_vec(),
        Err(ParseError::PayloadTooLarge) => {
            reject(
                res,
                StatusCode::PAYLOAD_TOO_LARGE,
                arkret_wire::error_codes::ErrorCode::PAYLOAD_TOO_LARGE,
                "request body exceeds 512 KiB",
                &request_id,
                started,
            );
            return;
        }
        Err(_) => {
            reject(
                res,
                StatusCode::BAD_REQUEST,
                arkret_wire::error_codes::ErrorCode::SCHEMA_VIOLATION,
                "failed to read request body",
                &request_id,
                started,
            );
            return;
        }
    };
    let caller = match authenticate_registration_handoff_request(
        req,
        &body,
        &state.notify_auth,
        state.notify_nonce_store.as_ref(),
        &request_id,
    )
    .await
    {
        Ok(caller) => caller,
        Err(error) => {
            reject(
                res,
                error.status,
                error.code,
                &error.message,
                &request_id,
                started,
            );
            return;
        }
    };
    let request = match serde_json::from_slice::<PushRegistrationHandoffRequestBody>(&body) {
        Ok(request) if request.validate().is_ok() => request,
        Ok(_) | Err(_) => {
            reject(
                res,
                StatusCode::BAD_REQUEST,
                arkret_wire::error_codes::ErrorCode::SCHEMA_VIOLATION,
                "expected a valid closed push registration handoff body",
                &request_id,
                started,
            );
            return;
        }
    };
    let Some(store) = state.registration_handoff.as_ref() else {
        reject(
            res,
            StatusCode::SERVICE_UNAVAILABLE,
            arkret_wire::error_codes::ErrorCode::SERVICE_UNAVAILABLE,
            "public registration handoff is not configured",
            &request_id,
            started,
        );
        return;
    };
    let source = caller.origin_id.expect("handoff auth requires source");
    let destination = caller
        .destination_id
        .expect("handoff auth requires destination");
    match store.apply(source, destination, request).await {
        Ok(outcome) => {
            res.status_code(StatusCode::OK);
            res.render(Json(outcome));
        }
        Err(ApplyRegistrationError::Conflict) => reject(
            res,
            StatusCode::CONFLICT,
            arkret_wire::error_codes::ErrorCode::DUPLICATE_CONFLICT,
            "registration handoff conflicts with durable state",
            &request_id,
            started,
        ),
        Err(ApplyRegistrationError::Storage(error)) => {
            tracing::error!(request_id, error = %error, "registration handoff failed");
            reject(
                res,
                StatusCode::SERVICE_UNAVAILABLE,
                arkret_wire::error_codes::ErrorCode::SERVICE_UNAVAILABLE,
                "registration handoff storage is unavailable",
                &request_id,
                started,
            );
        }
    }
}

fn reject(
    res: &mut Response,
    status: StatusCode,
    code: &str,
    message: &str,
    request_id: &str,
    started: Instant,
) {
    finish_error(res, status, code, message, None, Some(request_id), started);
}
