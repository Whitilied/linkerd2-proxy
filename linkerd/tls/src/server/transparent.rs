use super::{detect::DetectSni, terminate::NewTerminate, ClientId, Sni};
use futures::prelude::*;
use linkerd_detect::{DetectService, DetectTimeout};
use linkerd_error::Error;
use linkerd_identity::Name;
use linkerd_stack::NewService;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::time;

#[derive(Clone, Debug)]
pub struct NewTransparent<L, N> {
    local: Option<L>,
    inner: N,
    timeout: time::Duration,
}

#[derive(Clone, Debug)]
pub enum Transparent<T, L, N, S> {
    Disabled(S),
    Enabled(DetectService<T, DetectTimeout<DetectSni>, Handshake<T, L, N>>),
}

#[derive(Clone, Debug)]
struct Handshake<T, L, N> {
    target: T,
    local: L,
    terminate: NewTerminate<L, N>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Status {
    Disabled,
    Passthru { sni: Option<Name> },
    Terminated { client_id: Option<Name> },
}

// === impl NewTransparent ===

impl<T, L, N> NewService<T> for NewTransparent<L, N>
where
    T: Clone,
    L: Clone,
    N: NewService<(Status, T)> + Clone,
{
    type Service = Transparent<T, L, N, N::Service>;

    fn new_service(&mut self, target: T) -> Self::Service {
        match self.local.clone() {
            Some(local) => {
                let inner = Handshake {
                    target: target.clone(),
                    local: local.clone(),
                    terminate: NewTerminate::new(local, self.inner.clone()),
                };
                let detect = DetectTimeout::new(self.timeout, DetectSni::default());
                Transparent::Enabled(DetectService::new(target, detect, inner))
            }
            None => Transparent::Disabled(self.inner.new_service((Status::Disabled, target))),
        }
    }
}

// === impl Handshake ===

impl<I, T, L, N, S> tower::Service<I> for Handshake<T, L, N>
where
    T: Clone,
    N: NewService<(Status, T), Service = S>,
    S: tower::Service<I, Response = ()>,
    S::Error: Into<Error>,
    S::Future: Send + 'static,
{
    type Response = ();
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<(), Error>> + Send + 'static>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self {
            Self::Disabled(s) => s.poll_ready(cx).map_err(Into::into),
            Self::Enabled(hs) => hs.poll_ready(cx),
        }
    }

    fn call(&mut self, io: I) -> Self::Future {
        match self {
            Self::Disabled(s) => Box::pin(s.call(io).err_into::<Error>()),
            Self::Enabled(hs) => Box::pin(hs.call(io)),
        }
    }
}

// === impl Handshake ===

impl<I, T, L, N, S> tower::Service<I> for Handshake<T, L, N, S>
where
    T: Clone,
    N: NewService<(Status, T), Service = S>,
    S: tower::Service<I, Response = ()>,
    S::Error: Into<Error>,
    S::Future: Send + 'static,
{
    type Response = ();
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<(), Error>> + Send + 'static>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, io: I) -> Self::Future {
        match self {
            Self::Disabled(s) => Box::pin(s.call(io).err_into::<Error>()),
            Self::Enabled(hs) => Box::pin(hs.call(io)),
        }
    }
}
