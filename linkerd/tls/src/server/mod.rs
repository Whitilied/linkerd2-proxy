mod client_hello;
mod detect;

pub use self::detect::{Detectable, NewDetectTls};
use crate::ReasonForNoPeerName;
use linkerd_conditional::Conditional;
use linkerd_identity as identity;
use linkerd_io::{EitherIo, PrefixedIo};
pub use rustls::ServerConfig as Config;
use std::sync::Arc;
use tokio_rustls::server::TlsStream;

pub trait HasConfig {
    fn tls_server_name(&self) -> identity::Name;
    fn tls_server_config(&self) -> Arc<Config>;
}

/// Produces a server config that fails to handshake all connections.
pub fn empty_config() -> Arc<Config> {
    let verifier = rustls::NoClientAuth::new();
    Arc::new(Config::new(verifier))
}

pub type Meta<T> = (Status, T);

pub type Io<T> = EitherIo<PrefixedIo<T>, TlsStream<PrefixedIo<T>>>;

pub type Connection<T, I> = (Meta<T>, Io<I>);

/// Describes the status of an accepted connection.
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub enum Status {
    /// TLS is disabled on this proxy.
    Disabled,

    /// No TLS was detected.
    Clear,

    /// TLS was detected for a non-proxy server. The proxy is acting as a pass-through.
    Passthru { sni: identity::Name },

    /// TLS was terminated. A client ID is expected to be present unless this
    /// connection is the first connection established from the proxy to the
    /// Identity service.
    Terminated { client_id: Option<identity::Name> },
}

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

//#[cfg(test)]
impl HasConfig for identity::CrtKey {
    fn tls_server_name(&self) -> identity::Name {
        identity::CrtKey::tls_server_name(self)
    }

    fn tls_server_config(&self) -> Arc<Config> {
        identity::CrtKey::tls_server_config(self)
    }
}
