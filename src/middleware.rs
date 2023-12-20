use std::{convert::Infallible, sync::Arc};

use axum::{
    body::Body,
    http::{Request, StatusCode},
    response::Response,
};
use casbin::{CoreApi, Enforcer};
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tower::{Layer, Service};

#[derive(Clone)]
pub struct CasbinAuthLayer {
    enforcer: Arc<RwLock<Enforcer>>,
}

impl CasbinAuthLayer {
    pub fn new(enforcer: Arc<RwLock<Enforcer>>) -> Self {
        Self { enforcer }
    }
}

#[derive(Clone)]
pub struct CasbinAuthMiddleware<S> {
    inner: S,
    enforcer: Arc<RwLock<Enforcer>>,
}

impl<S> Layer<S> for CasbinAuthLayer {
    type Service = CasbinAuthMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CasbinAuthMiddleware {
            inner,
            enforcer: self.enforcer.clone(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CasbinAuthClaims {
    pub subject: String,
}

impl CasbinAuthClaims {
    pub fn new(subject: String) -> Self {
        Self { subject }
    }
}

impl<S> Service<Request<Body>> for CasbinAuthMiddleware<S>
where
    S: Service<Request<Body>, Response = Response, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let cloned_enforcer = self.enforcer.clone();
        let not_ready_inner = self.inner.clone();
        let mut ready_inner = std::mem::replace(&mut self.inner, not_ready_inner);
        let path = request.uri().clone().to_string();
        let method = request.method().clone().to_string();
        let option_vals = request
            .extensions()
            .get::<CasbinAuthClaims>()
            .map(|x| x.to_owned());
        println!("{:?}", option_vals);
        let future = ready_inner.call(request);

        Box::pin(async move {
            let unauthorized_response: Response<Body> = Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::empty())
                .unwrap();
            let mut lock = cloned_enforcer.write().await;
            if let Some(vals) = option_vals {
                match lock.enforce_mut(vec![vals.subject.clone(), path, method]) {
                    Ok(true) => {
                        drop(lock);
                        let response: Response<Body> = future.await?;
                        Ok(response)
                    }
                    Ok(false) => {
                        drop(lock);
                        Ok(unauthorized_response)
                    }
                    Err(_) => {
                        drop(lock);
                        Ok(unauthorized_response)
                    }
                }
            } else {
                Ok(unauthorized_response)
            }
        })
    }
}
