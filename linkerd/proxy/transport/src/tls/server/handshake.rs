use super::{Conditional, HasConfig, ReasonForNoPeerName};
use crate::io;
use futures::{future, prelude::*};
use linkerd2_error::Error;
use linkerd2_identity::Name;
use linkerd2_stack::NewService;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tokio_rustls::{server::TlsStream, TlsAcceptor};
use tower::{util::ServiceExt, Service};
use tracing::trace;

/// Creates a Service that always terminates TLS as long as a local TLS config is
/// present.
#[derive(Clone, Debug)]
pub struct NewHandshake<I, N> {
    local: Conditional<I>,
    inner: N,
}

#[derive(Clone, Debug)]
pub enum Handshake<L, N, S, T> {
    Forward(S),
    Terminate { local: L, inner: N, target: T },
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ClientId(pub Name);

pub type Io<T> = io::EitherIo<T, TlsStream<T>>;

impl<L, N, T> NewService<T> for NewHandshake<L, N>
where
    L: HasConfig + Clone,
    N: NewService<(Conditional<ClientId>, T)> + Clone,
{
    type Service = Handshake<L, N, N::Service, T>;

    fn new_service(&mut self, target: T) -> Self::Service {
        match self.local.as_ref() {
            Conditional::None(reason) => {
                let svc = self.inner.new_service((Conditional::None(reason), target));
                Handshake::Forward(svc)
            }
            Conditional::Some(local) => Handshake::Terminate {
                local: local.clone(),
                inner: self.inner.clone(),
                target,
            },
        }
    }
}

impl<T, I, L, N, S> Service<I> for Handshake<L, N, S, T>
where
    I: io::AsyncRead + io::AsyncWrite + Send + Unpin + 'static,
    T: Clone + Send + 'static,
    L: HasConfig,
    N: NewService<(Conditional<ClientId>, T), Service = S> + Clone + Send + 'static,
    S: Service<Io<I>> + Send,
    S::Error: Into<Error>,
    S::Future: Send,
{
    type Response = S::Response;
    type Error = Error;
    type Future = future::Either<
        future::ErrInto<S::Future, Error>,
        Pin<Box<dyn Future<Output = Result<S::Response, Error>> + Send + 'static>>,
    >;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        match self {
            Self::Forward(svc) => svc.poll_ready(cx).map_err(Into::into),
            Self::Terminate { .. } => Poll::Ready(Ok(())),
        }
    }

    fn call(&mut self, io: I) -> Self::Future {
        match self {
            Self::Forward(svc) => {
                future::Either::Left(svc.call(io::EitherIo::Left(io)).err_into::<Error>())
            }
            Self::Terminate {
                inner,
                local,
                target,
            } => {
                trace!("Initiating TLS handshake");
                let accept = TlsAcceptor::from(local.tls_server_config()).accept(io);
                let target = target.clone();
                let mut inner = inner.clone();
                future::Either::Right(Box::pin(async move {
                    let io = accept.await?;
                    let client_id = client_identity(&io);
                    trace!(client.id = ?client_id, "Handshake complete");
                    let status = client_id
                        .map(|id| Conditional::Some(ClientId(id)))
                        .unwrap_or(Conditional::None(ReasonForNoPeerName::NoPeerIdFromRemote));
                    inner
                        .new_service((status, target))
                        .oneshot(io::EitherIo::Right(io))
                        .err_into::<Error>()
                        .await
                }))
            }
        }
    }
}

fn client_identity<S>(tls: &TlsStream<S>) -> Option<Name> {
    use linkerd2_dns_name as dns;
    use rustls::Session;
    use webpki::GeneralDNSNameRef;

    let (_io, session) = tls.get_ref();
    let certs = session.get_peer_certificates()?;
    let c = certs.first().map(rustls::Certificate::as_ref)?;
    let end_cert = webpki::EndEntityCert::from(c).ok()?;
    let dns_names = end_cert.dns_names().ok()?;

    match dns_names.first()? {
        GeneralDNSNameRef::DNSName(n) => Some(Name::from(dns::Name::from(n.to_owned()))),
        GeneralDNSNameRef::Wildcard(_) => {
            // Wildcards can perhaps be handled in a future path...
            None
        }
    }
}
