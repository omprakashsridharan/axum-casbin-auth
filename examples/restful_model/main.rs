use crate::auth::{sign, Claims};
use axum::{
    middleware::from_extractor,
    routing::{get, post},
    Router,
};
use axum_casbin_auth::{
    casbin::{CoreApi, Enforcer},
    CasbinAuthLayer,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

mod auth;

async fn root() -> &'static str {
    "Hello, World!"
}

async fn protected() -> &'static str {
    "I AM PROTECTED! Only Authorised subjects can come here.
    If you get this response, then it means you are already authorised"
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let normal_user_token = sign(String::from("user@test.com")).unwrap();
    let admin_user_token = sign(String::from("admin@test.com")).unwrap();

    println!("Admin token: {}", admin_user_token);
    println!("Normal user token: {}", normal_user_token);

    let e = Enforcer::new("casbin/model.conf", "casbin/policy.csv").await?;
    let casbin_auth_enforcer = Arc::new(RwLock::new(e));

    let app = Router::new()
        .route("/protected", post(protected))
        .layer(CasbinAuthLayer::new(casbin_auth_enforcer))
        .layer(from_extractor::<Claims>())
        .route("/", get(root));

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
    Ok(())
}
