use crate::endpoint::TcpAccept;
use indexmap::IndexSet;
use linkerd_app_core::{svc::stack::FilterRequest, Error};
use std::sync::Arc;

/// A connection policy that drops
#[derive(Clone, Debug)]
pub struct RequireIdentityForPorts {
    ports: Arc<IndexSet<u16>>,
}

#[derive(Debug)]
pub struct IdentityRequired(());

impl<T: IntoIterator<Item = u16>> From<T> for RequireIdentityForPorts {
    fn from(ports: T) -> Self {
        Self {
            ports: Arc::new(ports.into_iter().collect()),
        }
    }
}

impl FilterRequest<TcpAccept> for RequireIdentityForPorts {
    type Request = TcpAccept;

    fn filter(&self, meta: TcpAccept) -> Result<TcpAccept, Error> {
        let port = meta.target_addr.port();
        let id_required = self.ports.contains(&port);

        let client_id = meta.as_peer_identity();
        tracing::debug!(%port, client.id = ?client_id, %id_required);
        if id_required && client_id.is_none() {
            return Err(IdentityRequired(()).into());
        }

        Ok(meta)
    }
}

impl std::fmt::Display for IdentityRequired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "identity required")
    }
}

impl std::error::Error for IdentityRequired {}
