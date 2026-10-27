//! Adapter that turns [`CaManager`] leaves into rustls server configurations
//! for the proxy's TLS termination, with an in-memory per-host cache.

use super::CaManager;
use anyhow::Result;
use hudsucker::certificate_authority::CertificateAuthority;
use hyper::http::uri::Authority;
use rustls::{ServerConfig, crypto::CryptoProvider};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tracing::{debug, error};

/// Hosts cached before the cache is cleared wholesale. Minting is cheap
/// (a single ECDSA signature), so a simple bound beats an LRU here.
const MAX_CACHED_HOSTS: usize = 4096;
/// Name used when a client asks for a host we cannot mint a certificate for.
/// The handshake then fails on the client side with a clear name mismatch
/// instead of tearing down the proxy task.
const FALLBACK_HOST: &str = "invalid.shrike.local";

pub struct LeafCertAuthority {
    ca: Arc<CaManager>,
    provider: Arc<CryptoProvider>,
    cache: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

impl LeafCertAuthority {
    pub fn new(ca: Arc<CaManager>, provider: Arc<CryptoProvider>) -> Self {
        Self {
            ca,
            provider,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Server configuration presenting a leaf for `host`, minted on first use.
    pub fn server_config_for(&self, host: &str) -> Result<Arc<ServerConfig>> {
        let key = host
            .trim_matches(|c| c == '[' || c == ']')
            .to_ascii_lowercase();
        if let Some(cfg) = self
            .cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&key)
        {
            debug!(host = %key, "leaf certificate cache hit");
            return Ok(Arc::clone(cfg));
        }

        debug!(host = %key, "minting leaf certificate");
        let leaf = self.ca.mint_leaf(&key)?;
        let mut cfg = ServerConfig::builder_with_provider(Arc::clone(&self.provider))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(vec![leaf], self.ca.leaf_key_der())?;
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let cfg = Arc::new(cfg);

        let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        if cache.len() >= MAX_CACHED_HOSTS {
            cache.clear();
        }
        cache.insert(key, Arc::clone(&cfg));
        Ok(cfg)
    }

    pub fn cached_hosts(&self) -> usize {
        self.cache.lock().unwrap_or_else(|p| p.into_inner()).len()
    }
}

impl CertificateAuthority for LeafCertAuthority {
    async fn gen_server_config(&self, authority: &Authority) -> Arc<ServerConfig> {
        match self.server_config_for(authority.host()) {
            Ok(cfg) => cfg,
            Err(err) => {
                error!(host = %authority.host(), error = %err, "cannot mint leaf certificate; serving fallback");
                self.server_config_for(FALLBACK_HOST)
                    .expect("fallback host name is always mintable")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authority() -> LeafCertAuthority {
        let dir = tempfile::tempdir().unwrap();
        let ca = CaManager::create(dir.path()).unwrap();
        LeafCertAuthority::new(
            Arc::new(ca),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
    }

    #[test]
    fn caches_per_host_case_insensitively() {
        let auth = authority();
        let a = auth.server_config_for("Example.com").unwrap();
        let b = auth.server_config_for("example.COM").unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        let c = auth.server_config_for("other.example").unwrap();
        assert!(!Arc::ptr_eq(&a, &c));
        assert_eq!(auth.cached_hosts(), 2);
    }

    #[test]
    fn offers_h2_and_http11() {
        let auth = authority();
        let cfg = auth.server_config_for("h2.test").unwrap();
        assert_eq!(
            cfg.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[tokio::test]
    async fn falls_back_for_unmintable_host() {
        let auth = authority();
        let bad = Authority::from_static("bad!host");
        let _cfg = auth.gen_server_config(&bad).await;
        assert!(auth.cached_hosts() >= 1);
    }
}
