use std::sync::Arc;

use salvo::http::StatusCode;
use salvo::prelude::*;

use crate::AppState;

#[handler]
pub(super) async fn health(res: &mut Response) {
    res.status_code(StatusCode::OK);
    res.render(Text::Plain(""));
}

#[handler]
pub(super) async fn ready(depot: &mut Depot, res: &mut Response) {
    let Ok(state) = depot.obtain::<Arc<AppState>>() else {
        res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
        res.render(Text::Plain("application state missing"));
        return;
    };

    if let Some(deduplicator) = state.notify_deduplicator.as_ref() {
        if let Err(error) = deduplicator.ready() {
            tracing::warn!(error = %error, "readiness check failed");
            res.status_code(StatusCode::SERVICE_UNAVAILABLE);
            res.render(Text::Plain(format!("not ready: {error}")));
            return;
        }
    }
    if let Err(error) = state.notify_auth.validate() {
        tracing::warn!(error = %error, "readiness auth config check failed");
        res.status_code(StatusCode::SERVICE_UNAVAILABLE);
        res.render(Text::Plain(format!("not ready: {error}")));
        return;
    }

    res.status_code(StatusCode::OK);
    res.render(Text::Plain("ok"));
}
