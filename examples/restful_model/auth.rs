use axum::extract::{FromRequest, RequestParts, TypedHeader};

use axum::headers::{authorization::Bearer, Authorization};
use axum::response::IntoResponse;
use axum::{http::StatusCode, Json};
use axum_casbin_auth::CasbinAuthClaims;
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
impl<B> FromRequest<B> for Claims
where
    B: Send,
{
    type Rejection = AuthError;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let TypedHeader(Authorization(bearer)) =
            TypedHeader::<Authorization<Bearer>>::from_request(req)
                .await
                .map_err(|e| {
                    println!("{:?}", e);
                    AuthError::InvalidToken
                })?;

        let token_data = verify(bearer.token()).map_err(|e| {
            println!("{:?}", e);
            AuthError::InvalidToken
        })?;
        req.extensions_mut().insert(token_data.clone());
        req.extensions_mut()
            .insert(CasbinAuthClaims::new(token_data.clone().subject));
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
