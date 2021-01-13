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

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub enum Status {
    Disabled,
    Clear,
    Passthru { sni: identity::Name },
    Terminated { client_id: Option<identity::Name> },
}

/// Produces a server config that fails to handshake all connections.
pub fn empty_config() -> Arc<Config> {
    let verifier = rustls::NoClientAuth::new();
    Arc::new(Config::new(verifier))
}

pub type Meta<T> = (Status, T);

pub type Io<T> = EitherIo<PrefixedIo<T>, TlsStream<PrefixedIo<T>>>;

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
