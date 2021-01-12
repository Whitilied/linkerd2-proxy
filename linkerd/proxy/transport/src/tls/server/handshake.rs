use super::HasConfig;
use crate::io;
use futures::prelude::*;
use linkerd_error::Error;
use linkerd_identity::Name;
use linkerd_stack::NewService;
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
pub struct NewHandshake<L, N> {
    local: L,
    inner: N,
}

#[derive(Clone, Debug)]
pub struct Handshake<L, N, T> {
    local: L,
    inner: N,
    target: T,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ClientId(pub Name);

impl<L, N, T> NewService<T> for NewHandshake<L, N>
where
    L: HasConfig + Clone,
    N: NewService<(Option<ClientId>, T)> + Clone,
{
    type Service = Handshake<L, N, T>;

    fn new_service(&mut self, target: T) -> Self::Service {
        Handshake {
            local: self.local.clone(),
            inner: self.inner.clone(),
            target,
        }
    }
}

impl<T, I, L, N, S> Service<I> for Handshake<L, N, T>
where
    I: io::AsyncRead + io::AsyncWrite + Send + Unpin + 'static,
    T: Clone + Send + 'static,
    L: HasConfig,
    N: NewService<(Option<ClientId>, T), Service = S> + Clone + Send + 'static,
    S: Service<TlsStream<I>> + Send,
    S::Error: Into<Error>,
    S::Future: Send,
{
    type Response = S::Response;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<S::Response, Error>> + Send + 'static>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, io: I) -> Self::Future {
        trace!("Initiating TLS handshake");
        let accept = TlsAcceptor::from(self.local.tls_server_config()).accept(io);
        let target = self.target.clone();
        let mut inner = self.inner.clone();
        Box::pin(async move {
            let io = accept.await?;
            let id = client_identity(&io);
            trace!(client.id = ?id, "Handshake complete");
            inner
                .new_service((id.map(ClientId), target))
                .oneshot(io)
                .err_into::<Error>()
                .await
        })
    }
}

fn client_identity<S>(tls: &TlsStream<S>) -> Option<Name> {
    use linkerd_dns_name as dns;
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
