//! HTTP request/response bodies for `/v1/*`.

use serde::{Deserialize, Serialize};

use crate::SecretString;

pub const LOGIN_PATH: &str = "/v1/login";
pub const LOGOUT_PATH: &str = "/v1/logout";
pub const LOGOUT_ALL_PATH: &str = "/v1/logout_all";
pub const WS_PATH: &str = "/v1/ws";
/// `POST` a picture (image/png); `GET /v1/blobs/<hash>` to fetch one.
pub const BLOBS_PATH: &str = "/v1/blobs";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobUploaded {
    pub hash: crate::profile::BlobHash,
}

/// `POST /v1/plugins` (body: the wasm module, `Content-Type: application/wasm`).
pub const PLUGINS_PATH: &str = "/v1/plugins";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginInstalled {
    pub plugin: crate::plugin::PluginView,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginRequest {
    pub password: SecretString,
    /// The device token from this device's last successful login, if it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_token: Option<SecretString>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginResponse {
    pub token: SecretString,
    /// Absolute session expiry (unix ms). The session can end earlier via idle timeout or revocation.
    pub expires_at_ms: i64,
    /// A fresh device token. It replaces any token sent with the request (which stops
    /// working); store it and send it with the next login.
    pub device_token: SecretString,
}

/// Every non-2xx response body. Codes are fixed strings; the server never echoes input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorBody {
    pub error: ErrorCode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    BadRequest,
    Unauthorized,
    /// The request came from a browser (it carried an `Origin` header).
    ForbiddenOrigin,
    NotFound,
    MethodNotAllowed,
    PayloadTooLarge,
    UnsupportedMediaType,
    TooManyRequests,
    /// The kill switch is on: agent runtimes can't connect.
    AgentsPaused,
    /// Not a valid plugin (see `plugin::PluginError`; the client checks first).
    InvalidPlugin,
    Internal,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_request_is_strict() {
        assert!(crate::decode::<LoginRequest>(br#"{"password":"x"}"#).is_ok());
        assert!(
            crate::decode::<LoginRequest>(br#"{"password":"x","device_token":"spw_d_1"}"#).is_ok()
        );
        for bad in [
            r#"{}"#,
            r#"{"password":"x","admin":true}"#,
            r#"{"password":"x","password":"y"}"#,
            r#"{"password":1}"#,
            r#"{"password":null}"#,
            r#"["x"]"#,
            r#"{"Password":"x"}"#,
            r#"{"password":"x","device_token":null}"#,
            r#"{"password":"x","device_token":1}"#,
        ] {
            assert!(crate::decode::<LoginRequest>(bad.as_bytes()).is_err(), "{bad}");
        }
    }
}
