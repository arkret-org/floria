use std::sync::Arc;

use salvo::http::StatusCode;
use salvo::prelude::*;

use crate::AppState;

/// Publish the exact method-native evidence validated at startup.  This route
/// is only a transport locator: consumers still verify the evidence against
/// the current DID method state before accepting its service endpoint.
#[handler]
pub(super) async fn publish(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Ok(state) = depot.get_typed::<Arc<AppState>>() else {
        res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
        return;
    };
    let Some(evidence) = state.gateway_service_resolution.as_deref() else {
        res.status_code(StatusCode::NOT_FOUND);
        return;
    };
    let Some(requested) = req.param::<String>("service_id") else {
        res.status_code(StatusCode::NOT_FOUND);
        return;
    };
    if requested != evidence.service_id.as_str()
        || req.uri().path()
            != arkret_models_identity::canonical_service_resolution_path(&evidence.service_id)
    {
        res.status_code(StatusCode::NOT_FOUND);
        return;
    }

    res.status_code(StatusCode::OK);
    res.render(Json(evidence));
}
