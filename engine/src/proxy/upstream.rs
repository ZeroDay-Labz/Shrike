//! Upstream (proxy -> server) TLS configuration and connector.

use crate::config::UpstreamTlsMode;
use anyhow::{Context, Result};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use rustls::{
    ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use std::sync::Arc;
use tracing::{info, warn};

/// Build the rustls client configuration used for every upstream TLS connection.
pub fn client_tls_config(
    mode: UpstreamTlsMode,
    provider: Arc<CryptoProvider>,
) -> Result<ClientConfig> {
    let builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .context("rustls protocol versions")?;

    // ALPN is left empty here on purpose: the hyper-rustls connector fills in
    // h2 + http/1.1 itself (and asserts the list is empty), and the WebSocket
    // connector must stay on HTTP/1.1.
    let config = match mode {
        UpstreamTlsMode::Verify => builder
            .with_root_certificates(trust_roots())
            .with_no_client_auth(),
        UpstreamTlsMode::AcceptInvalid => {
            warn!("upstream certificate verification DISABLED (--insecure-upstream)");
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert { provider }))
                .with_no_client_auth()
        }
    };
    Ok(config)
}

/// Mozilla's bundled roots plus whatever the OS trust store provides
/// (corporate CAs, lab CAs the user already installed).
fn trust_roots() -> RootCertStore {
    let mut roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let native = rustls_native_certs::load_native_certs();
    let (added, ignored) = roots.add_parsable_certificates(native.certs);
    for err in native.errors {
        warn!(error = %err, "could not load a native root certificate");
    }
    info!(
        bundled = webpki_roots::TLS_SERVER_ROOTS.len(),
        native_added = added,
        native_ignored = ignored,
        "upstream trust roots loaded"
    );
    roots
}

/// Connector handling both `http://` and `https://` upstreams.
pub fn https_connector(config: ClientConfig) -> HttpsConnector<HttpConnector> {
    hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(config)
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build()
}

/// Verifier that accepts any server certificate but still checks handshake
/// signatures, so the connection is at least bound to the key in the cert.
#[derive(Debug)]
struct AcceptAnyServerCert {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_modes_build_and_connector_adds_alpn() {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        for mode in [UpstreamTlsMode::Verify, UpstreamTlsMode::AcceptInvalid] {
            let cfg = client_tls_config(mode, Arc::clone(&provider)).unwrap();
            assert!(cfg.alpn_protocols.is_empty(), "connector owns ALPN");
            let _connector = https_connector(cfg);
        }
    }
}
