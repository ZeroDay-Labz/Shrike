//! The intercepting proxy: TLS termination with our CA, recording, forwarding.

mod handler;
mod landing;
mod upstream;
pub use upstream::{client_tls_config, https_connector};

pub use handler::TrafficHandler;
pub use landing::{CERT_FILENAME, LANDING_HOSTS};

use crate::{
    ca::{CaManager, LeafCertAuthority},
    config::ProxyConfig,
    core::EventBus,
    intercept::Interceptor,
    match_replace::MatchReplace,
    scope::Scope,
};
use anyhow::{Context, Result};
use hudsucker::{Proxy, tokio_tungstenite::Connector};
use std::sync::{Arc, RwLock};
use tokio::net::TcpListener;
use tracing::info;

/// Bind the listener from `config`. Separate from [`serve`] so callers can
/// learn the bound address (e.g. when listening on port 0).
pub async fn bind(config: &ProxyConfig) -> Result<TcpListener> {
    TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("binding proxy listener on {}", config.listen))
}

/// Run the proxy on `listener` until `shutdown` resolves and in-flight
/// connections have drained.
#[allow(clippy::too_many_arguments)] // threads the engine's shared live state in
pub async fn serve(
    listener: TcpListener,
    config: ProxyConfig,
    ca: Arc<CaManager>,
    bus: EventBus,
    scope: Arc<RwLock<Scope>>,
    interceptor: Arc<Interceptor>,
    match_replace: Arc<RwLock<MatchReplace>>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let authority = LeafCertAuthority::new(Arc::clone(&ca), Arc::clone(&provider));
    let tls = upstream::client_tls_config(config.upstream_tls, provider)?;
    let connector = upstream::https_connector(tls.clone());
    let handler = TrafficHandler::new(bus, ca, config.clone(), scope, interceptor, match_replace);

    let local = listener.local_addr().context("reading listener address")?;
    info!(%local, "proxy listening");

    let proxy = Proxy::builder()
        .with_listener(listener)
        .with_ca(authority)
        .with_http_connector(connector)
        .with_websocket_connector(Connector::Rustls(Arc::new(tls)))
        .with_http_handler(handler.clone())
        .with_websocket_handler(handler)
        .with_graceful_shutdown(shutdown)
        .build()
        .context("building proxy")?;

    proxy.start().await.context("running proxy")
}
