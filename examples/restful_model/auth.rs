use axum::extract::FromRequestParts;
use axum::RequestPartsExt;

use axum::http::request::Parts;
use axum::http::Extensions;
use axum::response::IntoResponse;
use axum::{http::StatusCode, Json};
use axum_casbin_auth::CasbinAuthClaims;
use axum_extra::headers::authorization::Bearer;
use axum_extra::headers::Authorization;
use axum_extra::typed_header::*;
use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug)]
pub enum AuthError {
    InvalidToken,
}

pub type JwtResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub fn sign(email: String) -> JwtResult<String> {
    Ok(jsonwebtoken::encode(
        &Header::default(),
        &Claims::new(email),
        &EncodingKey::from_secret("SECRET".as_bytes()),
    )?)
}

pub fn verify(token: &str) -> JwtResult<Claims> {
    Ok(jsonwebtoken::decode(
        token,
        &DecodingKey::from_secret("SECRET".as_bytes()),
        &Validation::default(),
    )
    .map(|data| data.claims)?)
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Claims {
    pub subject: String,
    pub exp: i64,
    pub iat: i64,
}

impl Claims {
    pub fn new(email: String) -> Self {
        let iat = Utc::now();
        let exp = iat + Duration::hours(24);
        Self {
            subject: email,
            iat: iat.timestamp(),
            exp: exp.timestamp(),
        }
    }
}

#[axum::async_trait]
impl<B> FromRequestParts<B> for Claims
where
    B: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &B) -> Result<Self, Self::Rejection> {
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| AuthError::InvalidToken)?;

        let token_data = verify(bearer.token()).map_err(|e| {
            println!("{:?}", e);
            AuthError::InvalidToken
        })?;
        let mut claims_extension = Extensions::new();
        claims_extension.insert(CasbinAuthClaims::new(token_data.clone().subject));
        let _ = parts.extensions.extend(claims_extension);
        Ok(token_data)
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        let (status, error_message) = match self {
            AuthError::InvalidToken => (StatusCode::BAD_REQUEST, "Invalid token"),
        };
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}
