# axum-casbin-auth

This library implements the Service, Layer traits of Tower for Authorisation Service using Casbin.
Please read [Casbin](https://casbin.io/docs/overview) for all supported models and features. The basic idea is to have a set of Casbin Policies and the service expects a struct with Subject: String in the request.
The service then matches with the policies defined for casbin and tries to authorise the subject. If failed, the layer rejects with UNAUTHORISED response. You can find many supported Authorisation models [here](https://casbin.io/docs/supported-models).
Below is a basic usage of the library for RESTful model.

## Installation

Install my-project with npm

Cargo.toml

```toml
[dependencies]
# Other deps
axum-casbin-auth = "*"
```

## Code usage

jwt.rs

```rust
use std::str::FromStr;

use crate::constants::JWT_SECRET;
use async_trait::async_trait;
use axum::extract::{FromRequest, TypedHeader};
use axum::RequestPartsExt;
use axum::http::request::Parts;
use axum::http::Extensions;
use axum::headers::{authorization::Bearer, Authorization};
use axum::response::IntoResponse;
use axum::{http::StatusCode, Json};
use axum_casbin_auth::CasbinAuthClaims;
use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::json;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Claims {
    pub subject: String,
    pub exp: i64,
    pub iat: i64,
    pub user_id: i32,
}

impl Claims {
    pub fn new(email: String, user_id: i32, role: String) -> Self {
        let iat = Utc::now();
        let exp = iat + Duration::hours(24);
        Self {
            subject: email,
            iat: iat.timestamp(),
            exp: exp.timestamp(),
            user_id,
            role: ROLES::from_str(&role).unwrap(),
        }
    }
}

pub fn sign(email: String, user_id: i32, role: String) -> ErrorResult<String> {
    Ok(jsonwebtoken::encode(
        &Header::default(),
        &Claims::new(email, user_id, role),
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )?)
}

pub fn verify(token: &str) -> ErrorResult<Claims> {
    Ok(jsonwebtoken::decode(
        token,
        &DecodingKey::from_secret(JWT_SECRET.as_bytes()),
        &Validation::default(),
    )
    .map(|data| data.claims)?)
}

#[derive(Debug)]
pub enum AuthError {
    WrongCredentials,
    MissingCredentials,
    TokenCreation,
    InvalidToken,
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
            AuthError::WrongCredentials => (StatusCode::UNAUTHORIZED, "Wrong credentials"),
            AuthError::MissingCredentials => (StatusCode::BAD_REQUEST, "Missing credentials"),
            AuthError::TokenCreation => (StatusCode::INTERNAL_SERVER_ERROR, "Token creation error"),
            AuthError::InvalidToken => (StatusCode::BAD_REQUEST, "Invalid token"),
        };
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}
```

Create a folder called casbin (or any name) inside your project root and create two files.

1. model.conf

```conf
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)
```

2. policy.csv

```csv
p, admin@test.com, *, POST
```

Please read Casbin documentation for detailed explanations

main.rs

```rust
use axum_casbin_auth::{
    casbin::{CoreApi, Enforcer},
    CasbinAuthLayer,
};

use lib::utils::jwt::Claims;
// ... server code

let e = Enforcer::new("casbin/model.conf", "casbin/policy.csv").await?;
let casbin_auth_enforcer = Arc::new(RwLock::new(e));

let app = Router::new()
    .route("/inventory", post(add_product::handle))
    // Order is important
    .layer(CasbinAuthLayer::new(casbin_auth_enforcer))
    .layer(from_extractor::<Claims>());

// ...
```

After this any request will be authenticated by the Claims extractor and will inject the CasbinAuthClaims with subject in the request post which will be passed through the CasbinAuthLayer and the request will be authorised based on the policies.
The policies can be dynamically stored and maintained in databases as well. You can find more Adapters [here](https://casbin.io/docs/adapters#:~:text=Rust)
