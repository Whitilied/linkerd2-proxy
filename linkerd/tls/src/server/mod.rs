mod client_hello;

use crate::ReasonForNoPeerName;

use self::client_hello::{parse_sni, Incomplete, Sni};
use bytes::BytesMut;
use futures::prelude::*;
use linkerd_conditional::Conditional;
use linkerd_dns_name as dns;
use linkerd_error::Error;
use linkerd_identity as identity;
use linkerd_io::{EitherIo, PrefixedIo};
use linkerd_stack::{layer, NewService};
pub use rustls::ServerConfig as Config;
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{self, AsyncReadExt},
    net::TcpStream,
};
use tokio_rustls::server::TlsStream;
use tower::util::ServiceExt;
use tracing::{debug, trace};

pub trait HasConfig {
    fn tls_server_name(&self) -> identity::Name;
    fn tls_server_config(&self) -> Arc<Config>;
}

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub enum Status {
    Disabled,
    Clear,
    Passthru { sni: identity::Name },
    Terminated { client_id: Option<identity::Name> },
}

/// Must be implemented for I/O types like `TcpStream` on which TLS is
/// transparently detected.
///
/// This is necessary so that we can be generic over the I/O type but still use
/// `TcpStream::peek` to avoid allocating for mTLS SNI detection.
#[async_trait::async_trait]
pub trait Detectable {
    /// Attempts to detect a `ClientHello` message from the underlying transport
    /// and, if its SNI matches `local_name`, initiates a TLS server handshake to
    /// decrypt the stream.
    ///
    /// Returns the client's identity, if one exists, and an optionally decrypted
    /// transport.
    async fn detected(
        self,
        config: Arc<Config>,
        local_name: identity::Name,
    ) -> io::Result<(Status, Io<Self>)>
    where
        Self: Sized;
}

/// Produces a server config that fails to handshake all connections.
pub fn empty_config() -> Arc<Config> {
    let verifier = rustls::NoClientAuth::new();
    Arc::new(Config::new(verifier))
}

// TODO sni name
pub type Meta<T> = (Status, T);

pub type Io<T> = EitherIo<PrefixedIo<T>, TlsStream<PrefixedIo<T>>>;

pub type Connection<T, I> = (Meta<T>, Io<I>);

#[derive(Clone, Debug)]
pub struct NewDetectTls<L, A> {
    local_identity: Option<L>,
    inner: A,
    timeout: Duration,
}

#[derive(Clone, Debug)]
pub struct DetectTimeout(());

#[derive(Clone, Debug)]
pub struct DetectTls<T, L, N> {
    target: T,
    local_identity: Option<L>,
    inner: N,
    timeout: Duration,
}

// The initial peek buffer is statically allocated on the stack and is fairly small; but it is
// large enough to hold the ~300B ClientHello sent by proxies.
const PEEK_CAPACITY: usize = 512;

// A larger fallback buffer is allocated onto the heap if the initial peek buffer is
// insufficient. This is the same value used in HTTP detection.
const BUFFER_CAPACITY: usize = 8192;

// === impl Status ===

impl Status {
    pub fn as_peer_identity(&self) -> Conditional<&identity::Name, ReasonForNoPeerName> {
        match self {
            Self::Clear => Conditional::None(ReasonForNoPeerName::NoTlsFromRemote),
            Self::Terminated {
                client_id: Some(id),
            } => Conditional::Some(id),
            Self::Terminated { client_id: None } => {
                Conditional::None(ReasonForNoPeerName::NoPeerIdFromRemote)
            }
            Self::Passthru { .. } => Conditional::None(ReasonForNoPeerName::NoTlsFromRemote),
            Self::Disabled => Conditional::None(ReasonForNoPeerName::LocalIdentityDisabled),
        }
    }
}

// === impl NewDetectTls ===

impl<I: HasConfig, N> NewDetectTls<I, N> {
    pub fn new(local_identity: Option<I>, inner: N, timeout: Duration) -> Self {
        Self {
            local_identity,
            inner,
            timeout,
        }
    }

    pub fn layer(
        local_identity: Option<I>,
        timeout: Duration,
    ) -> impl layer::Layer<N, Service = Self> + Clone
    where
        I: Clone,
    {
        layer::mk(move |inner| Self::new(local_identity.clone(), inner, timeout))
    }
}

impl<T, L, N> NewService<T> for NewDetectTls<L, N>
where
    L: HasConfig + Clone,
    N: NewService<Meta<T>> + Clone,
{
    type Service = DetectTls<T, L, N>;

    fn new_service(&mut self, target: T) -> Self::Service {
        DetectTls {
            target,
            local_identity: self.local_identity.clone(),
            inner: self.inner.clone(),
            timeout: self.timeout,
        }
    }
}

// === impl DetectTls ===

impl<I, L, N, NSvc, T> tower::Service<I> for DetectTls<T, L, N>
where
    I: Detectable + Send + 'static,
    L: HasConfig,
    N: NewService<Meta<T>, Service = NSvc> + Clone + Send + 'static,
    NSvc: tower::Service<Io<I>, Response = ()> + Send + 'static,
    NSvc::Error: Into<Error>,
    NSvc::Future: Send,
    T: Clone + Send + 'static,
{
    type Response = ();
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<(), Error>> + Send + 'static>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, tcp: I) -> Self::Future {
        let target = self.target.clone();
        let mut new_accept = self.inner.clone();

        match self.local_identity.as_ref() {
            Some(local) => {
                let config = local.tls_server_config();
                let name = local.tls_server_name();
                let timeout = tokio::time::sleep(self.timeout);
                Box::pin(async move {
                    let (status, io) = tokio::select! {
                        res = tcp.detected(config, name) => { res? }
                        () = timeout => {
                            return Err(DetectTimeout(()).into());
                        }
                    };
                    new_accept
                        .new_service((status, target))
                        .oneshot(io)
                        .err_into::<Error>()
                        .await
                })
            }

            None => {
                let svc = new_accept.new_service((Status::Disabled, target));
                Box::pin(svc.oneshot(EitherIo::Left(tcp.into())).err_into::<Error>())
            }
        }
    }
}

// === impl Detectable ===

#[async_trait::async_trait]
impl Detectable for TcpStream {
    async fn detected(
        mut self,
        tls_config: Arc<Config>,
        local_id: identity::Name,
    ) -> io::Result<(Status, Io<Self>)> {
        // First, try to use MSG_PEEK to read the SNI from the TLS ClientHello.
        // Because peeked data does not need to be retained, we use a static
        // buffer to prevent needless heap allocation.
        //
        // Anecdotally, the ClientHello sent by Linkerd proxies is <300B. So a
        // ~500B byte buffer is more than enough.
        let mut buf = [0u8; PEEK_CAPACITY];
        let sz = self.peek(&mut buf).await?;
        debug!(sz, "Peeked bytes from TCP stream");
        if let Ok(read) = parse_sni(&buf) {
            match read {
                Some(Sni(sni)) if sni == local_id => {
                    trace!("Identified matching SNI via peek");
                    // Terminate the TLS stream.
                    let (client_id, tls) = handshake(tls_config, PrefixedIo::from(self)).await?;
                    return Ok((Status::Terminated { client_id }, EitherIo::Right(tls)));
                }
                sni => {
                    trace!(?sni, "Not a matching TLS ClientHello");
                    let status = sni
                        .map(|Sni(sni)| Status::Passthru { sni })
                        .unwrap_or(Status::Clear);
                    return Ok((status, EitherIo::Left(self.into())));
                }
            }
        }

        // Peeking didn't return enough data, so instead we'll allocate more
        // capacity and try reading data from the socket.
        debug!("Attempting to buffer TLS ClientHello after incomplete peek");
        let mut buf = BytesMut::with_capacity(BUFFER_CAPACITY);
        debug!(buf.capacity = %buf.capacity(), "Reading bytes from TCP stream");
        while self.read_buf(&mut buf).await? != 0 {
            debug!(buf.len = %buf.len(), "Read bytes from TCP stream");
            match parse_sni(buf.as_ref()) {
                Ok(Some(Sni(sni))) if sni == local_id => {
                    trace!("Identified matching SNI via buffered read");
                    // Terminate the TLS stream.
                    let (client_id, tls) =
                        handshake(tls_config.clone(), PrefixedIo::new(buf.freeze(), self)).await?;
                    return Ok((Status::Terminated { client_id }, EitherIo::Right(tls)));
                }

                Ok(Some(Sni(sni))) => {
                    return Ok((
                        Status::Passthru { sni },
                        EitherIo::Left(PrefixedIo::new(buf.freeze(), self)),
                    ));
                }

                Err(Incomplete) if buf.capacity() > 0 => {}
                _ => break,
            }
        }

        trace!("Could not read TLS ClientHello via buffering");
        Ok((
            Status::Clear,
            EitherIo::Left(PrefixedIo::new(buf.freeze(), self)),
        ))
    }
}

async fn handshake<T>(
    tls_config: Arc<Config>,
    io: T,
) -> io::Result<(Option<identity::Name>, tokio_rustls::server::TlsStream<T>)>
where
    T: io::AsyncRead + io::AsyncWrite + Unpin,
{
    let tls = tokio_rustls::TlsAcceptor::from(tls_config)
        .accept(io)
        .await?;
    let client_id = client_identity(&tls);
    trace!(client.did = ?client_id, "Accepted TLS connection");
    Ok((client_id, tls))
}

fn client_identity<S>(tls: &tokio_rustls::server::TlsStream<S>) -> Option<identity::Name> {
    use rustls::Session;
    use webpki::GeneralDNSNameRef;

    let (_io, session) = tls.get_ref();
    let certs = session.get_peer_certificates()?;
    let c = certs.first().map(rustls::Certificate::as_ref)?;
    let end_cert = webpki::EndEntityCert::from(c).ok()?;
    let dns_names = end_cert.dns_names().ok()?;

    match dns_names.first()? {
        GeneralDNSNameRef::DNSName(n) => Some(identity::Name::from(dns::Name::from(n.to_owned()))),
        GeneralDNSNameRef::Wildcard(_) => {
            // Wildcards can perhaps be handled in a future path...
            None
        }
    }
}

impl HasConfig for identity::CrtKey {
    fn tls_server_name(&self) -> identity::Name {
        identity::CrtKey::tls_server_name(self)
    }

    fn tls_server_config(&self) -> Arc<Config> {
        identity::CrtKey::tls_server_config(self)
    }
}

impl std::fmt::Display for DetectTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TLS detection timeout")
    }
}

impl std::error::Error for DetectTimeout {}
