use super::{detect::DetectSni, terminate::NewTerminate, ClientId, Sni};
use futures::prelude::*;
use linkerd_detect::DetectService;
use linkerd_error::Error;
use linkerd_identity::Name;
use linkerd_stack::NewService;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

#[derive(Clone, Debug)]
pub struct NewTransparent<L, N> {
    local: Option<L>,
    inner: N,
}

#[derive(Clone, Debug)]
pub enum Transparent<T, L, N, S> {
    Disabled(S),
    Enabled(DetectService<NewHandshake<L, N, T>, DetectSni>),
}

#[derive(Clone, Debug)]
struct NewHandshake<L, N, T> {
    local: L,
    innner: NewTerminate<L, N, T>,
    target: T,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Status {
    Disabled,
    Passthru { sni: Option<Name> },
    Terminated { client_id: Option<Name> },
}

// === impl NewTransparent ===

impl<L: Clone, N, T> NewService<T> for NewTransparent<L, N>
where
    N: NewService<(Status, T)>,
{
    type Service = Transparent<L, N, N::Service, T>;

    fn new_service(&mut self, target: T) -> Self::Service {
        match self.local.clone() {
            Some(local) => Transparent::Enabled(NewHandshake { local }),
            None => Transparent::Disabled(self.inner.new_service((Status::Disabled, target))),
        }
    }
}

// === impl Transparent ===

impl<I, L, N, S, T> tower::Service<I> for Transparent<L, N, S, T>
where
    N: NewService<(Status, T), Service = S>,
    S: tower::Service<I>,
    S::Error: Into<Error>,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<S::Response, Error>> + Send + 'static>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self {
            Self::Disabled(s) => s.poll_ready(cx).map_err(Into::into),
            Self::Enabled { .. } => Poll::Ready(Ok(())),
        }
    }

    fn call(&mut self, io: I) -> Self::Future {
        match self {
            Self::Disabled(s) => Box::pin(s.call(io).err_into::<Error>()),
            Self::Enabled { inner, target } => {
                unimplemented!();
            }
        }
    }
}
