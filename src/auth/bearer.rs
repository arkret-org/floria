use salvo::prelude::Request;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BearerState {
    Missing,
    Invalid,
    Valid,
}

pub(super) fn bearer_matches(
    req: &Request,
    candidates: &[String],
    candidate_hashes: &[String],
) -> bool {
    matches!(
        bearer_state(req, candidates, candidate_hashes),
        BearerState::Valid
    )
}

pub(crate) fn bearer_state(
    req: &Request,
    candidates: &[String],
    candidate_hashes: &[String],
) -> BearerState {
    let Some(raw) = req.header::<String>("authorization") else {
        return BearerState::Missing;
    };
    let Some(token) = parse_bearer_token(&raw) else {
        return BearerState::Invalid;
    };
    let token_digest = bearer_token_sha256(token);
    if candidates
        .iter()
        .any(|candidate| token_digest.ct_eq(&bearer_token_sha256(candidate)).into())
        || candidate_hashes
            .iter()
            .any(|candidate| bearer_token_hash_matches(&token_digest, candidate))
    {
        BearerState::Valid
    } else {
        BearerState::Invalid
    }
}

fn parse_bearer_token(value: &str) -> Option<&str> {
    arkret_server::authorization_credential(
        value.trim(),
        arkret_server::AuthorizationScheme::Bearer,
    )
}

/// Compares a pre-computed SHA-256 of the presented bearer token against
/// a configured hash candidate in constant time. The candidate is parsed
/// from its `sha256:`-prefixed hex form into raw bytes; a length / decode
/// mismatch is a non-match (no early-return timing signal that depends on
/// the secret).
fn bearer_token_hash_matches(token_digest: &[u8; 32], candidate: &str) -> bool {
    let candidate = candidate
        .trim()
        .strip_prefix("sha256:")
        .unwrap_or_else(|| candidate.trim());
    let Ok(candidate_bytes) = hex::decode(candidate) else {
        return false;
    };
    candidate_bytes.len() == token_digest.len() && token_digest.ct_eq(&candidate_bytes).into()
}

fn bearer_token_sha256(token: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher.finalize().into()
}

pub fn bearer_token_sha256_hex(token: &str) -> String {
    hex::encode(bearer_token_sha256(token))
}
