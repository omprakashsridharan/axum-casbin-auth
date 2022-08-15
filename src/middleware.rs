use std::sync::Arc;

use casbin::{CoreApi, Enforcer};
use futures::future::BoxFuture;
use http::{Response, StatusCode};
use hyper::{Body, Request};
use tokio::sync::RwLock;
use tower_http::auth::AsyncAuthorizeRequest;

pub struct CasbinAuth {
    enforcer: Arc<RwLock<Enforcer>>,
}

#[derive(Clone)]
pub struct CasbinAuthClaims {
    pub subject: String,
}

impl<B> AsyncAuthorizeRequest<B> for CasbinAuth
where
    B: Send + 'static,
{
    type RequestBody = B;

    type ResponseBody = Body;

    type Future = BoxFuture<'static, Result<Request<B>, Response<Self::ResponseBody>>>;

    fn authorize(&mut self, mut request: Request<B>) -> Self::Future {
        let cloned_enforcer = self.enforcer.clone();
        Box::pin(async move {
            let path = request.uri();
            let method = request.method().to_string().to_owned();
            let mut lock = cloned_enforcer.write().await;
            let option_vals = request
                .extensions()
                .get::<CasbinAuthClaims>()
                .map(|x| x.to_owned());
            let unauthorized_response = Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::empty())
                .unwrap();
            if let Some(vals) = option_vals {
                match lock.enforce_mut(vec![
                    vals.subject.clone(),
                    path.to_string(),
                    method.to_string(),
                ]) {
                    Ok(true) => {
                        drop(lock);
                        request.extensions_mut().insert(vals.subject);
                        Ok(request)
                    }
                    Ok(false) => {
                        drop(lock);
                        Err(unauthorized_response)
                    }
                    Err(_) => {
                        drop(lock);
                        Err(unauthorized_response)
                    }
                }
            } else {
                Err(unauthorized_response)
            }
        })
    }
}
