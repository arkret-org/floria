//! CXP-0010 media-service token binding scaffolds (R3 spec-sync 2026-05-27).
//!
//! # Role decision (MEDIA-1)
//!
//! Per `_before_todos.md` §1.5 and `_floria_todos.md` MEDIA-1, floria's v1
//! role for `cx.call.media.token_exchange` is **not an issuer**. The
//! production binary does not advertise a media-token minting surface in
//! `describe` and does not register a public `/rtc/token` route; if a
//! deployment adds a proxy in front of soland, floria must relay the
//! `MediaTokenResponse` without re-signing or mutating it.
//!
//! Self-issuing (option (b) in the todo: floria itself signs the
//! `participant_binding` and issues `backend_token` when co-located with
//! the SFU as a multi-tenant push gateway) is deferred:
//!
//! ```ignore
//! // TODO(R3.1): self-issue path — sign participant_binding with
//! //   floria's own media-service service_id key, anchor issuer_kid to
//! //   the current `cx.realm.media_service.service_id` epoch, mint a
//! //   backend-specific `backend_token` (LiveKit JWT / contrix-native
//! //   detached JWS / mediasoup ticket / …) and emit a signed
//! //   `MediaTokenResponse`.
//! ```
//!
//! The scaffolds below cover the wire shapes (MEDIA-2, MEDIA-3), TTL +
//! issuer anchoring + focus matching guards (MEDIA-4), and the
//! participant-binding signing helper signature (MEDIA-5). The local
//! signing methods are fail-closed scaffolds, not a public v1 HTTP
//! surface.

use std::{collections::BTreeMap, time::Duration};

use serde::{Deserialize, Serialize};
use serde_json::Value;

// Re-export the SDK types so call sites (and the future self-issue
// path) speak a single vocabulary with the rest of the contrix stack.
pub use contrix::{
    MediaBackendType, MediaTokenExchangeRequest, MediaTokenResponse, ParticipantBinding,
};

/// Spec ceiling: media tokens MUST NOT have TTL > 600 seconds.
/// Mirrors `contrix::MEDIA_TOKEN_TTL_MAX_SECS`.
pub const TOKEN_TTL_MAX_SECS: u64 = contrix::MEDIA_TOKEN_TTL_MAX_SECS;

/// Spec SHOULD floor: floria's proxy / self-issue default is 300s.
/// Mirrors `contrix::MEDIA_TOKEN_TTL_SHOULD_SECS`.
pub const TOKEN_TTL_DEFAULT_SECS: u64 = contrix::MEDIA_TOKEN_TTL_SHOULD_SECS;

/// MEDIA-4 — return the floria-default token TTL: 300s, capped at the
/// spec ceiling of 600s. Callers MAY override but MUST clamp to the
/// ceiling before signing.
#[must_use]
pub fn default_token_ttl() -> Duration {
    Duration::from_secs(TOKEN_TTL_DEFAULT_SECS)
}

/// MEDIA-4 — enforce the spec TTL ceiling. Returns `Err` when the
/// requested TTL exceeds [`TOKEN_TTL_MAX_SECS`].
///
/// Surface: `participant_binding_invalid` (per CXP-0010 §6.4 and
/// `contrix::media::validate_token_ttl`).
pub fn enforce_ttl_ceiling(ttl: Duration) -> Result<Duration, MediaBindingError> {
    if ttl.as_secs() == 0 {
        return Err(MediaBindingError::ParticipantBindingInvalid(
            "token TTL must be non-zero".to_owned(),
        ));
    }
    if ttl.as_secs() > TOKEN_TTL_MAX_SECS {
        return Err(MediaBindingError::ParticipantBindingInvalid(format!(
            "token TTL {}s exceeds 600s ceiling",
            ttl.as_secs()
        )));
    }
    Ok(ttl)
}

/// MEDIA-4 — strict focus_id check: the focus chosen by the client MUST
/// be byte-equal to the focus already committed in `cx.call.state`'s
/// `session_focus`. Any drift fails closed with `focus_mismatch`.
pub fn ensure_focus_matches(
    requested_focus_id: &str,
    session_focus_id: &str,
) -> Result<(), MediaBindingError> {
    if requested_focus_id == session_focus_id {
        Ok(())
    } else {
        Err(MediaBindingError::FocusMismatch {
            requested: requested_focus_id.to_owned(),
            session: session_focus_id.to_owned(),
        })
    }
}

/// MEDIA-4 — anchor the issuer_kid (and `service_signature.kid`) of an
/// outbound or inbound token to the `cx.realm.media_service.service_id`
/// currently committed in the realm's `media_service` epoch.
///
/// `kid` here is whatever the token-exchange response embedded (either
/// `participant_binding.issuer_kid` or `service_signature` `kid`).
/// `active_service_did` is the DID of the current
/// `media_service.service_id`.
///
/// The reference rule: `kid` MUST start with the active service DID
/// followed by a `#key-…` DID URL fragment. Any drift is
/// `token_issuer_unauthorised`.
pub fn ensure_issuer_anchored(
    kid: &str,
    active_service_did: &str,
) -> Result<(), MediaBindingError> {
    let kid = kid.trim();
    let active = active_service_did.trim();
    if kid.is_empty() || active.is_empty() {
        return Err(MediaBindingError::TokenIssuerUnauthorised(
            "issuer_kid and active_service_did must be non-empty".to_owned(),
        ));
    }
    // Allow either the exact DID URL (`did:web:media.example#key-1`)
    // or the bare DID — both forms appear in the binding specs
    // (contrix-native §2 and livekit §2).
    let did_prefix = kid.split_once('#').map(|(did, _)| did).unwrap_or(kid);
    if did_prefix == active {
        Ok(())
    } else {
        Err(MediaBindingError::TokenIssuerUnauthorised(format!(
            "issuer kid `{kid}` does not resolve to active media_service \
             service_id `{active_service_did}`"
        )))
    }
}

/// CXP-0010 wire error surface relevant to the token-exchange path.
/// floria's proxy mode forwards the upstream error code verbatim; the
/// self-issue path (TODO(R3.1)) constructs these directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaBindingError {
    /// `focus_mismatch` — requested focus_id != committed session_focus.
    FocusMismatch { requested: String, session: String },
    /// `unknown_focus_type` — backend label not in the v1 enum.
    UnknownFocusType(String),
    /// `token_issuer_unauthorised` — kid not anchored to current
    /// `cx.realm.media_service.service_id`.
    TokenIssuerUnauthorised(String),
    /// `participant_binding_invalid` — TTL out of bounds, missing field,
    /// or signature failure.
    ParticipantBindingInvalid(String),
    /// `legacy_single_endpoint_media_service` — caller is still on the
    /// v1.0 single-`sfu_endpoint` shape (forbidden in v1.1 cycle).
    LegacySingleEndpointMediaService,
}

impl MediaBindingError {
    /// Wire-form error code per `_before_todos.md` §0.7.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::FocusMismatch { .. } => "focus_mismatch",
            Self::UnknownFocusType(_) => "unknown_focus_type",
            Self::TokenIssuerUnauthorised(_) => "token_issuer_unauthorised",
            Self::ParticipantBindingInvalid(_) => "participant_binding_invalid",
            Self::LegacySingleEndpointMediaService => "legacy_single_endpoint_media_service",
        }
    }
}

impl std::fmt::Display for MediaBindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FocusMismatch { requested, session } => write!(
                f,
                "focus_mismatch: requested `{requested}` does not equal \
                 committed session_focus `{session}`"
            ),
            Self::UnknownFocusType(label) => {
                write!(f, "unknown_focus_type: `{label}` is not a v1 backend label")
            }
            Self::TokenIssuerUnauthorised(msg) => {
                write!(f, "token_issuer_unauthorised: {msg}")
            }
            Self::ParticipantBindingInvalid(msg) => {
                write!(f, "participant_binding_invalid: {msg}")
            }
            Self::LegacySingleEndpointMediaService => write!(
                f,
                "legacy_single_endpoint_media_service: realm still uses the \
                 v1.0 single-`sfu_endpoint` shape; upgrade to multi-focus \
                 `foci[]` before requesting a media token"
            ),
        }
    }
}

impl std::error::Error for MediaBindingError {}

// ─── MEDIA-2: contrix-native binding token format ─────────────────────────
//
// Spec: contrix-spec/spec/v1/zh/crypto-media/bindings/contrix-native.md §2.

/// MEDIA-2 — payload of the contrix-native `backend_token` (a detached
/// JWS, signed by the token issuer's `assertionMethod` key over
/// `service_id.service_did`).
///
/// Mirrors the JSON shape in `bindings/contrix-native.md` §2. The
/// outer JWS envelope (`alg`/`kid`/`payload`/`sig`) is constructed by
/// [`ContrixNativeBackendToken::sign`] (currently `TODO(R3.1)`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContrixNativeTokenPayload {
    pub call_id: String,
    pub focus_id: String,
    pub participant_identity: String,
    pub issued_at: String,
    pub expires_at: String,
    pub media: ContrixNativeMediaCaps,
}

/// MEDIA-2 — `media` field of the contrix-native token payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContrixNativeMediaCaps {
    pub audio: bool,
    pub video: bool,
    pub screen: bool,
}

/// MEDIA-2 — detached-JWS envelope of the contrix-native backend token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContrixNativeBackendToken {
    /// JOSE alg. Always `EdDSA` for the reference impl.
    pub alg: String,
    /// DID URL of the media service signing key, e.g.
    /// `did:web:media.example#key-1`.
    pub kid: String,
    pub payload: ContrixNativeTokenPayload,
    /// base64url detached signature.
    pub sig: String,
}

impl ContrixNativeBackendToken {
    /// MEDIA-2 — JOSE alg used by the reference contrix-native impl.
    pub const ALG: &'static str = "EdDSA";

    /// Construct an unsigned token shell. The caller is responsible for
    /// filling `sig`. floria's proxy mode never reaches this code path;
    /// the self-issue path (TODO(R3.1)) does.
    #[must_use]
    pub fn unsigned(kid: impl Into<String>, payload: ContrixNativeTokenPayload) -> Self {
        Self {
            alg: Self::ALG.to_owned(),
            kid: kid.into(),
            payload,
            sig: String::new(),
        }
    }

    /// TODO(R3.1) — Ed25519 sign the canonical bytes of (`alg`||`kid`||
    /// canonical(payload)) using the active media-service assertionMethod
    /// key, then populate `sig` with the base64url-detached form.
    ///
    /// Until the self-issue path is wired up this is a no-op marker that
    /// callers MUST audit before relying on the result. The proxy path
    /// does not exercise this method.
    pub fn sign(&mut self, _signing_key_pem: &[u8]) -> Result<(), MediaBindingError> {
        // TODO(R3.1): real Ed25519 detached-JWS signature over the
        // canonical form. For now we fail closed so accidental call
        // sites surface immediately.
        Err(MediaBindingError::ParticipantBindingInvalid(
            "ContrixNativeBackendToken::sign is TODO(R3.1) — floria is in \
             proxy-only mode for the v1 cycle"
                .to_owned(),
        ))
    }
}

// ─── MEDIA-3: LiveKit binding token format ───────────────────────────────
//
// Spec: contrix-spec/spec/v1/zh/crypto-media/bindings/livekit.md §2.

/// MEDIA-3 — LiveKit JWT claim shape for `backend_token`.
///
/// Mirrors the table in `bindings/livekit.md` §2. The actual JWT
/// signing (HS256 with LiveKit API key/secret) lives in
/// [`LiveKitBackendToken::sign`] (currently `TODO(R3.1)`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveKitClaims {
    /// LiveKit API key (= JWT `iss`).
    pub iss: String,
    /// `participant_identity` (= JWT `sub`).
    pub sub: String,
    /// `iat` — issued-at unix epoch.
    pub iat: i64,
    /// `nbf` — not-before unix epoch (typically `iat`).
    pub nbf: i64,
    /// `exp` — expiry unix epoch. MUST be ≤ `iat + 600`.
    pub exp: i64,
    /// Optional display label. Per §2 this MUST NOT carry actor identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub video: LiveKitVideoGrant,
}

/// MEDIA-3 — LiveKit `video.*` grant block.
///
/// The shape here is a strict subset of LiveKit's `VideoGrant`; floria
/// MUST NOT inject `metadata` or `canUpdateOwnMetadata` (livekit.md §2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveKitVideoGrant {
    /// Hashed `call_id` — never the raw `cx:call:…` id (livekit.md §2
    /// recommendation).
    pub room: String,
    #[serde(rename = "roomJoin")]
    pub room_join: bool,
    #[serde(rename = "canPublish")]
    pub can_publish: bool,
    #[serde(rename = "canSubscribe")]
    pub can_subscribe: bool,
    #[serde(rename = "canPublishSources")]
    pub can_publish_sources: Vec<String>,
    /// `false` — Contrix does not use LiveKit hidden participants.
    pub hidden: bool,
    /// `false` — recording goes through the Contrix blob pipeline, NOT
    /// LiveKit's recorder claim. Hard-coded to `false` to avoid the
    /// `recording_artifact_pipeline_bypassed` failure mode.
    pub recorder: bool,
}

impl LiveKitVideoGrant {
    /// MEDIA-3 — build a video grant from `desired_media` caps.
    /// Recorder is forced to `false`. `metadata` and
    /// `canUpdateOwnMetadata` are absent by construction.
    #[must_use]
    pub fn for_participant(
        call_room_hash: impl Into<String>,
        caps: ContrixNativeMediaCaps,
    ) -> Self {
        let mut sources = Vec::new();
        if caps.audio {
            sources.push("microphone".to_owned());
        }
        if caps.video {
            sources.push("camera".to_owned());
        }
        if caps.screen {
            sources.push("screen_share".to_owned());
        }
        Self {
            room: call_room_hash.into(),
            room_join: true,
            can_publish: caps.audio || caps.video || caps.screen,
            can_subscribe: true,
            can_publish_sources: sources,
            hidden: false,
            recorder: false,
        }
    }
}

/// MEDIA-3 — LiveKit JWT envelope (HS256 over `header.payload`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveKitBackendToken {
    pub claims: LiveKitClaims,
    /// Compact serialization of the signed JWT. `String::new()` until
    /// [`LiveKitBackendToken::sign`] runs.
    pub compact: String,
}

impl LiveKitBackendToken {
    /// Construct an unsigned token shell.
    #[must_use]
    pub fn unsigned(claims: LiveKitClaims) -> Self {
        Self {
            claims,
            compact: String::new(),
        }
    }

    /// TODO(R3.1) — HS256-sign with the LiveKit API key/secret and
    /// populate `compact`. floria's proxy mode never calls this; the
    /// self-issue path does.
    pub fn sign(&mut self, _api_key: &str, _api_secret: &[u8]) -> Result<(), MediaBindingError> {
        // TODO(R3.1): real HS256 JWT compact-serialization using the
        // LiveKit API key/secret. For now fail closed.
        Err(MediaBindingError::ParticipantBindingInvalid(
            "LiveKitBackendToken::sign is TODO(R3.1) — floria is in proxy-only \
             mode for the v1 cycle"
                .to_owned(),
        ))
    }
}

// ─── MEDIA-5: participant_binding signing helper ─────────────────────────

/// MEDIA-5 — canonical body that the issuer signs to populate
/// [`ParticipantBinding::sig`]. The canonical form is the JSON object
/// `{ scheme, issuer_kid, realm_id, call_id, focus_id, actor_id,
/// device_id, participant_identity, expires_at }` serialized with
/// sorted keys (UTF-8, no whitespace).
///
/// Returns the canonical bytes; signing is the caller's responsibility
/// (TODO(R3.1) — the v1 cycle's floria proxies and does not sign).
pub fn participant_binding_canonical_bytes(
    binding: &ParticipantBinding,
) -> Result<Vec<u8>, MediaBindingError> {
    let map = BTreeMap::from([
        (
            "actor_id",
            Value::String(binding.actor_id.as_str().to_owned()),
        ),
        (
            "call_id",
            Value::String(binding.call_id.as_str().to_owned()),
        ),
        (
            "device_id",
            Value::String(binding.device_id.as_str().to_owned()),
        ),
        ("expires_at", Value::String(binding.expires_at.to_rfc3339())),
        ("focus_id", Value::String(binding.focus_id.clone())),
        ("issuer_kid", Value::String(binding.issuer_kid.clone())),
        (
            "participant_identity",
            Value::String(binding.participant_identity.clone()),
        ),
        (
            "realm_id",
            Value::String(binding.realm_id.as_str().to_owned()),
        ),
        ("scheme", Value::String(binding.scheme.clone())),
    ]);
    serde_json::to_vec(&map).map_err(|e| {
        MediaBindingError::ParticipantBindingInvalid(format!(
            "failed to canonicalize participant_binding: {e}"
        ))
    })
}

/// MEDIA-5 — sign a freshly-constructed [`ParticipantBinding`] with the
/// issuer's media-service Ed25519 key. Populates [`ParticipantBinding::sig`].
///
/// TODO(R3.1) — implement the Ed25519 detached-signature path. floria's
/// v1 proxy mode never reaches this; the self-issue path does.
pub fn sign_participant_binding(
    _binding: &mut ParticipantBinding,
    _issuer_signing_key_pem: &[u8],
) -> Result<(), MediaBindingError> {
    // TODO(R3.1): Ed25519 detached-sign `participant_binding_canonical_bytes`
    // using the active media-service `assertionMethod` key, then assign
    // the base64url signature to `binding.sig`. The canonical bytes
    // helper above is already in shape; only the crypto path is stubbed.
    Err(MediaBindingError::ParticipantBindingInvalid(
        "sign_participant_binding is TODO(R3.1) — floria is in proxy-only \
         mode for the v1 cycle; self-issuing would require a media-service \
         signing key wired into floria's keystore"
            .to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_ceiling_rejects_above_600s_and_zero() {
        assert!(enforce_ttl_ceiling(Duration::from_secs(0)).is_err());
        assert!(enforce_ttl_ceiling(Duration::from_secs(300)).is_ok());
        assert!(enforce_ttl_ceiling(Duration::from_secs(600)).is_ok());
        let err = enforce_ttl_ceiling(Duration::from_secs(601)).unwrap_err();
        assert_eq!(err.code(), "participant_binding_invalid");
    }

    #[test]
    fn default_ttl_is_300_within_ceiling() {
        let ttl = default_token_ttl();
        assert_eq!(ttl.as_secs(), 300);
        assert!(enforce_ttl_ceiling(ttl).is_ok());
    }

    #[test]
    fn focus_strict_match() {
        assert!(ensure_focus_matches("fra-1", "fra-1").is_ok());
        let err = ensure_focus_matches("fra-1", "fra-2").unwrap_err();
        assert_eq!(err.code(), "focus_mismatch");
    }

    #[test]
    fn issuer_anchored_to_active_service_did() {
        assert!(
            ensure_issuer_anchored("did:web:media.example#key-1", "did:web:media.example",).is_ok()
        );
        assert!(ensure_issuer_anchored("did:web:media.example", "did:web:media.example").is_ok());
        let err = ensure_issuer_anchored("did:web:rogue.example#key-1", "did:web:media.example")
            .unwrap_err();
        assert_eq!(err.code(), "token_issuer_unauthorised");
    }

    #[test]
    fn livekit_video_grant_caps() {
        let grant = LiveKitVideoGrant::for_participant(
            "cx_call_abc",
            ContrixNativeMediaCaps {
                audio: true,
                video: true,
                screen: false,
            },
        );
        assert!(!grant.recorder, "recorder MUST be false (livekit.md §2)");
        assert!(!grant.hidden);
        assert!(grant.room_join);
        assert!(grant.can_publish);
        assert!(grant.can_subscribe);
        assert_eq!(grant.can_publish_sources, vec!["microphone", "camera"]);
    }

    #[test]
    fn contrix_native_token_unsigned_shell() {
        let token = ContrixNativeBackendToken::unsigned(
            "did:web:media.example#key-1",
            ContrixNativeTokenPayload {
                call_id: "cx:call:0196441c-0000-7000-8000-000000000000".to_owned(),
                focus_id: "fra-1".to_owned(),
                participant_identity: "cx:rtc_participant:0198c2f4-0000-7000-8000-000000000000"
                    .to_owned(),
                issued_at: "2026-05-27T12:29:56Z".to_owned(),
                expires_at: "2026-05-27T12:34:56Z".to_owned(),
                media: ContrixNativeMediaCaps {
                    audio: true,
                    video: true,
                    screen: false,
                },
            },
        );
        assert_eq!(token.alg, "EdDSA");
        assert!(token.sig.is_empty(), "unsigned shell carries empty sig");
    }

    #[test]
    fn sign_helpers_are_todo_r31() {
        // Both signing helpers must fail closed until the v1 self-issue
        // path is wired up. Catching this regression early ensures we
        // never silently emit an unsigned token onto the wire.
        let mut token = ContrixNativeBackendToken::unsigned(
            "did:web:media.example#key-1",
            ContrixNativeTokenPayload {
                call_id: "cx:call:0196441c-0000-7000-8000-000000000000".to_owned(),
                focus_id: "fra-1".to_owned(),
                participant_identity: "cx:rtc_participant:0198c2f4-0000-7000-8000-000000000000"
                    .to_owned(),
                issued_at: "2026-05-27T12:29:56Z".to_owned(),
                expires_at: "2026-05-27T12:34:56Z".to_owned(),
                media: ContrixNativeMediaCaps {
                    audio: false,
                    video: false,
                    screen: false,
                },
            },
        );
        let err = token.sign(&[]).unwrap_err();
        assert_eq!(err.code(), "participant_binding_invalid");

        let mut lk = LiveKitBackendToken::unsigned(LiveKitClaims {
            iss: "APIabc".to_owned(),
            sub: "cx:rtc_participant:0198c2f4-0000-7000-8000-000000000000".to_owned(),
            iat: 0,
            nbf: 0,
            exp: 300,
            name: None,
            video: LiveKitVideoGrant::for_participant(
                "cx_call_abc",
                ContrixNativeMediaCaps {
                    audio: true,
                    video: false,
                    screen: false,
                },
            ),
        });
        let err = lk.sign("APIabc", &[]).unwrap_err();
        assert_eq!(err.code(), "participant_binding_invalid");
    }

    #[test]
    fn participant_binding_canonical_bytes_sort_keys() {
        let binding: ParticipantBinding = serde_json::from_value(serde_json::json!({
            "scheme": ParticipantBinding::SCHEME,
            "sig": "ignored-by-canonical-body",
            "issuer_kid": "did:web:media.example#key-1",
            "realm_id": "cx:realm:01904100-0000-7000-8000-000000000001",
            "call_id": "cx:call:01904100-0000-7000-8000-000000000002",
            "focus_id": "fra-1",
            "actor_id": "did:web:alice.example",
            "device_id": "cx:device:01904100-0000-7000-8000-000000000004",
            "participant_identity": "cx:rtc_participant:0198c2f4-0000-7000-8000-000000000000",
            "expires_at": "2026-05-27T12:34:56Z"
        }))
        .unwrap();

        let bytes = participant_binding_canonical_bytes(&binding).unwrap();

        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            "{\"actor_id\":\"did:web:alice.example\",\"call_id\":\"cx:call:01904100-0000-7000-8000-000000000002\",\"device_id\":\"cx:device:01904100-0000-7000-8000-000000000004\",\"expires_at\":\"2026-05-27T12:34:56+00:00\",\"focus_id\":\"fra-1\",\"issuer_kid\":\"did:web:media.example#key-1\",\"participant_identity\":\"cx:rtc_participant:0198c2f4-0000-7000-8000-000000000000\",\"realm_id\":\"cx:realm:01904100-0000-7000-8000-000000000001\",\"scheme\":\"cx.media.participant_binding.v1\"}"
        );
    }

    #[test]
    fn error_codes_match_spec() {
        assert_eq!(
            MediaBindingError::FocusMismatch {
                requested: "a".to_owned(),
                session: "b".to_owned()
            }
            .code(),
            "focus_mismatch"
        );
        assert_eq!(
            MediaBindingError::UnknownFocusType("foo".to_owned()).code(),
            "unknown_focus_type"
        );
        assert_eq!(
            MediaBindingError::TokenIssuerUnauthorised("x".to_owned()).code(),
            "token_issuer_unauthorised"
        );
        assert_eq!(
            MediaBindingError::ParticipantBindingInvalid("x".to_owned()).code(),
            "participant_binding_invalid"
        );
        assert_eq!(
            MediaBindingError::LegacySingleEndpointMediaService.code(),
            "legacy_single_endpoint_media_service"
        );
    }
}
