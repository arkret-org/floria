use arkret_wire::error_codes::ErrorCode;
use arkret_wire::{Problem, ServiceOperationId};
use salvo::http::StatusCode;
use salvo::prelude::*;

use super::metrics::render_problem;

const ARKRET_OPERATION_HEADER: &str = "arkret-operation";

/// Require an exact versioned operation selector for every registered Arkret
/// HTTP route before authentication or body parsing runs.
#[derive(Clone, Copy, Debug)]
pub(super) struct OperationSelectorMiddleware;

#[async_trait]
impl Handler for OperationSelectorMiddleware {
    async fn handle(
        &self,
        req: &mut Request,
        _depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        if req.method() == salvo::http::Method::OPTIONS {
            ctrl.call_next(req, _depot, res).await;
            return;
        }

        let method = req.method().as_str();
        let path = req.uri().path();
        let registered_family = arkret_wire::SERVICE_OPERATION_DESCRIPTORS
            .iter()
            .any(|descriptor| descriptor.id.matches_http_request(method, path));
        if !registered_family {
            ctrl.call_next(req, _depot, res).await;
            return;
        }

        let Some(raw) = req
            .headers()
            .get(ARKRET_OPERATION_HEADER)
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.trim().is_empty())
        else {
            reject(
                res,
                StatusCode::BAD_REQUEST,
                ErrorCode::OPERATION_SELECTOR_REQUIRED,
                "Arkret-Operation is required for this request",
            );
            ctrl.skip_rest();
            return;
        };

        let selected = ServiceOperationId::from_wire(raw.trim());
        if !selected.is_some_and(|operation| operation.matches_http_request(method, path)) {
            reject(
                res,
                StatusCode::UNPROCESSABLE_ENTITY,
                ErrorCode::UNSUPPORTED_OPERATION_VERSION,
                "Arkret-Operation is unknown or does not belong to this route family",
            );
            ctrl.skip_rest();
            return;
        }

        ctrl.call_next(req, _depot, res).await;
    }
}

fn reject(res: &mut Response, status: StatusCode, code: &str, message: &str) {
    render_problem(
        res,
        status,
        Problem::from_code(code, message)
            .with_instance(arkret_wire::new_prefixed_uuid7("ak:request:")),
    );
}
