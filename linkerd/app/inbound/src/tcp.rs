use crate::PreventLoop;
pub use linkerd2_app_core::proxy::tcp::*;
use linkerd2_app_core::{
    config::ConnectConfig,
    svc,
    transport::{io, labels, Metrics},
    Error,
};
use std::marker::PhantomData;
use std::net::SocketAddr;
use tokio::net::TcpStream;

pub struct Connect<T> {
    config: ConnectConfig,
    prevent_loop: PreventLoop,
    metrics: Metrics,
    _marker: PhantomData<fn(T)>,
}

impl<T> Connect<T> {
    pub fn layer(config: ConnectConfig, prevent_loop: PreventLoop, metrics: Metrics) -> Self {
        Self {
            config,
            prevent_loop,
            metrics,
            _marker: PhantomData,
        }
    }
}

impl<T, C> svc::layer::Layer<C> for Connect<T>
where
    T: Send,
    for<'t> &'t T: Into<labels::Key> + Into<SocketAddr>,
    C: svc::Service<T, Response = TcpStream, Error = io::Error> + Send + 'static,
    C::Future: Send + 'static,
{
    type Service = svc::BoxService<T, io::BoxedIo, Error>;

    fn layer(&self, connect: C) -> Self::Service {
        svc::stack(connect)
            // Limits the time we wait for a connection to be established.
            .push_timeout(self.config.timeout)
            .push(self.metrics.layer_connect())
            .push_request_filter(self.prevent_loop)
            .push_map_response(io::BoxedIo::new) // Ensures the transport propagates shutdown properly.
            .push(svc::layer::mk(svc::BoxService::new))
            .into_inner()
    }
}

impl<T> Clone for Connect<T> {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            prevent_loop: self.prevent_loop,
            metrics: self.metrics.clone(),
            _marker: self._marker,
        }
    }
}
