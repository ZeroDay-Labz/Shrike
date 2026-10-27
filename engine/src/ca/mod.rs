//! Local certificate authority.
//!
//! A single root CA is generated once and persisted under the data directory.
//! Every TLS connection the proxy terminates is served with a short-lived leaf
//! certificate for that host, signed by the root. Clients trust the root once;
//! the leaves are minted on demand and cached in memory.

mod authority;
pub mod trust;

pub use authority::LeafCertAuthority;

use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use rcgen::PublicKeyData;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SerialNumber,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};
use time::{Duration, OffsetDateTime};

/// Common name on the generated root certificate.
pub const CA_COMMON_NAME: &str = "Shrike Local Proxy CA";
pub const CA_KEY_FILE: &str = "ca.key.pem";
pub const CA_CERT_FILE: &str = "ca.cert.pem";

const CA_VALIDITY_DAYS: i64 = 10 * 365;
const LEAF_VALIDITY_DAYS: i64 = 365;
/// Leaves are back-dated slightly so clients with a lagging clock accept them.
const LEAF_NOT_BEFORE_SKEW_SECS: i64 = 300;
/// X.509 limits CommonName to 64 characters; longer hosts rely on the SAN alone.
const MAX_COMMON_NAME_LEN: usize = 64;

/// Owns the root CA key material and mints leaf certificates.
pub struct CaManager {
    dir: PathBuf,
    issuer: Issuer<'static, KeyPair>,
    ca_cert_der: CertificateDer<'static>,
    ca_cert_pem: String,
    /// base64(SHA-256(SubjectPublicKeyInfo)) of the CA key — the value Chromium's
    /// `--ignore-certificate-errors-spki-list` flag expects.
    spki_sha256_b64: String,
    /// One ephemeral key shared by every leaf this process mints. Leaves are
    /// never persisted, so a per-process key is as private as a per-host one
    /// and avoids a key generation on every new host.
    leaf_key: KeyPair,
    leaf_key_der: PrivateKeyDer<'static>,
}

impl std::fmt::Debug for CaManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaManager")
            .field("dir", &self.dir)
            .field("fingerprint", &self.fingerprint_sha256())
            .finish()
    }
}

impl CaManager {
    /// Load the CA from `dir`, creating a fresh one if none exists.
    /// Returns the manager and whether a new CA was generated.
    pub fn load_or_create(dir: &Path) -> Result<(Self, bool)> {
        let key_path = dir.join(CA_KEY_FILE);
        let cert_path = dir.join(CA_CERT_FILE);
        if key_path.exists() && cert_path.exists() {
            return Ok((Self::load(dir)?, false));
        }
        if key_path.exists() != cert_path.exists() {
            return Err(anyhow!(
                "CA directory {} is half-initialised (only one of {CA_KEY_FILE}/{CA_CERT_FILE} exists); \
                 move it aside or run `shrike ca reset`",
                dir.display()
            ));
        }
        Ok((Self::create(dir)?, true))
    }

    /// Load an existing CA from `dir`.
    pub fn load(dir: &Path) -> Result<Self> {
        let key_pem = fs::read_to_string(dir.join(CA_KEY_FILE))
            .with_context(|| format!("reading {}", dir.join(CA_KEY_FILE).display()))?;
        let cert_pem = fs::read_to_string(dir.join(CA_CERT_FILE))
            .with_context(|| format!("reading {}", dir.join(CA_CERT_FILE).display()))?;
        Self::from_pem(dir, key_pem, cert_pem)
    }

    /// Generate a new root CA and persist it to `dir`, replacing any existing one.
    pub fn create(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;

        let key = KeyPair::generate().context("generating CA key pair")?;
        let now = OffsetDateTime::now_utc();

        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params.not_before = now - Duration::days(1);
        params.not_after = now + Duration::days(CA_VALIDITY_DAYS);
        params.serial_number = Some(random_serial());
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, CA_COMMON_NAME);
        dn.push(DnType::OrganizationName, "shrike");
        params.distinguished_name = dn;

        let cert = params
            .self_signed(&key)
            .context("self-signing CA certificate")?;
        let key_pem = key.serialize_pem();
        let cert_pem = cert.pem();

        write_private(&dir.join(CA_KEY_FILE), key_pem.as_bytes())?;
        fs::write(dir.join(CA_CERT_FILE), cert_pem.as_bytes())
            .with_context(|| format!("writing {}", dir.join(CA_CERT_FILE).display()))?;

        Self::from_pem(dir, key_pem, cert_pem)
    }

    fn from_pem(dir: &Path, key_pem: String, cert_pem: String) -> Result<Self> {
        let key = KeyPair::from_pem(&key_pem).context("parsing CA private key")?;
        // SubjectPublicKeyInfo hash, captured before the key moves into the issuer.
        let spki_sha256_b64 = B64.encode(Sha256::digest(key.subject_public_key_info()));
        let issuer = Issuer::from_ca_cert_pem(&cert_pem, key).context("parsing CA certificate")?;

        let ca_cert_der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .next()
            .ok_or_else(|| anyhow!("CA certificate file contains no CERTIFICATE block"))?
            .context("decoding CA certificate PEM")?;

        let leaf_key = KeyPair::generate().context("generating leaf key pair")?;
        let leaf_key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));

        Ok(Self {
            dir: dir.to_path_buf(),
            issuer,
            ca_cert_der,
            ca_cert_pem: cert_pem,
            spki_sha256_b64,
            leaf_key,
            leaf_key_der,
        })
    }

    /// Delete the persisted CA (if any) and generate a new one.
    pub fn reset(dir: &Path) -> Result<Self> {
        for name in [CA_KEY_FILE, CA_CERT_FILE] {
            let p = dir.join(name);
            if p.exists() {
                fs::remove_file(&p).with_context(|| format!("removing {}", p.display()))?;
            }
        }
        Self::create(dir)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn cert_path(&self) -> PathBuf {
        self.dir.join(CA_CERT_FILE)
    }

    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    pub fn ca_cert_der(&self) -> &CertificateDer<'static> {
        &self.ca_cert_der
    }

    /// SHA-256 fingerprint of the root certificate, colon-separated upper-case hex
    /// (the format browsers show in their certificate viewers).
    pub fn fingerprint_sha256(&self) -> String {
        let digest = Sha256::digest(self.ca_cert_der.as_ref());
        hex::encode_upper(digest)
            .as_bytes()
            .chunks(2)
            .map(|c| std::str::from_utf8(c).unwrap_or("??"))
            .collect::<Vec<_>>()
            .join(":")
    }

    /// base64(SHA-256(SubjectPublicKeyInfo)) of the CA key, for Chromium's
    /// `--ignore-certificate-errors-spki-list` flag (trust only this CA).
    pub fn spki_sha256_base64(&self) -> &str {
        &self.spki_sha256_b64
    }

    /// Write the root certificate (PEM) to `out`, for importing into a trust store.
    pub fn export_cert(&self, out: &Path) -> Result<()> {
        fs::write(out, self.ca_cert_pem.as_bytes())
            .with_context(|| format!("writing {}", out.display()))
    }

    /// Private key for every leaf minted by this manager (PKCS#8 DER).
    pub fn leaf_key_der(&self) -> PrivateKeyDer<'static> {
        self.leaf_key_der.clone_key()
    }

    /// Mint a server certificate for `host` (a DNS name or an IP address literal),
    /// signed by the root. The certificate's private key is [`Self::leaf_key_der`].
    pub fn mint_leaf(&self, host: &str) -> Result<CertificateDer<'static>> {
        let host = host.trim_matches(|c| c == '[' || c == ']');
        validate_host(host)?;
        let now = OffsetDateTime::now_utc();

        let mut params = CertificateParams::new(vec![host.to_string()])
            .with_context(|| format!("host {host:?} is not a valid DNS name or IP address"))?;
        let mut dn = DistinguishedName::new();
        if host.len() <= MAX_COMMON_NAME_LEN {
            dn.push(DnType::CommonName, host);
        }
        dn.push(DnType::OrganizationName, "shrike proxy");
        params.distinguished_name = dn;
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        params.not_before = now - Duration::seconds(LEAF_NOT_BEFORE_SKEW_SECS);
        params.not_after = now + Duration::days(LEAF_VALIDITY_DAYS);
        params.serial_number = Some(random_serial());

        let cert = params
            .signed_by(&self.leaf_key, &self.issuer)
            .with_context(|| format!("signing leaf certificate for {host}"))?;
        Ok(cert.der().clone())
    }
}

/// Accept IP literals and DNS-style names (labels of letters, digits, `-`, `_`,
/// optionally a leading `*.`). Anything else is refused up front, because the
/// certificate encoder only checks that the name is ASCII.
fn validate_host(host: &str) -> Result<()> {
    if host.is_empty() {
        return Err(anyhow!("cannot mint a certificate for an empty host name"));
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Ok(());
    }
    if host.len() > 253 {
        return Err(anyhow!("host name {host:?} is too long"));
    }
    let body = host.strip_prefix("*.").unwrap_or(host);
    let valid = !body.is_empty()
        && body.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    if valid {
        Ok(())
    } else {
        Err(anyhow!(
            "host name {host:?} is not a valid DNS name or IP address"
        ))
    }
}

/// 128-bit random, positive serial number.
fn random_serial() -> SerialNumber {
    let mut bytes: [u8; 16] = rand::random();
    bytes[0] &= 0x7f; // keep the INTEGER positive
    bytes[0] |= 0x01; // and non-zero
    SerialNumber::from_slice(&bytes)
}

/// Write a file readable only by the current user.
fn write_private(path: &Path, contents: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::{io::Write, os::unix::fs::OpenOptionsExt};
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("creating {}", path.display()))?;
        f.write_all(contents)
            .with_context(|| format!("writing {}", path.display()))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        fs::write(path, contents).with_context(|| format!("writing {}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::{
        extensions::GeneralName,
        prelude::{FromDer, X509Certificate},
    };

    fn parse(der: &[u8]) -> X509Certificate<'_> {
        X509Certificate::from_der(der).expect("valid DER").1
    }

    #[test]
    fn creates_and_reloads_same_ca() {
        let dir = tempfile::tempdir().unwrap();
        let (ca, created) = CaManager::load_or_create(dir.path()).unwrap();
        assert!(created);
        assert!(dir.path().join(CA_KEY_FILE).exists());
        assert!(dir.path().join(CA_CERT_FILE).exists());

        let (again, created) = CaManager::load_or_create(dir.path()).unwrap();
        assert!(!created);
        assert_eq!(ca.fingerprint_sha256(), again.fingerprint_sha256());
        assert_eq!(ca.ca_cert_pem(), again.ca_cert_pem());
    }

    #[cfg(unix)]
    #[test]
    fn private_key_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        CaManager::create(dir.path()).unwrap();
        let mode = fs::metadata(dir.path().join(CA_KEY_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn root_is_a_signing_ca() {
        let dir = tempfile::tempdir().unwrap();
        let ca = CaManager::create(dir.path()).unwrap();
        let cert = parse(ca.ca_cert_der());
        assert!(cert.is_ca());
        assert_eq!(cert.subject(), cert.issuer());
        let ku = cert.key_usage().unwrap().expect("key usage present").value;
        assert!(ku.key_cert_sign());
        assert!(cert.validity().is_valid());
        assert!(
            cert.subject().to_string().contains(CA_COMMON_NAME),
            "subject {}",
            cert.subject()
        );
        assert!(
            cert.verify_signature(None).is_ok(),
            "root must be self-signed"
        );
    }

    #[test]
    fn fingerprint_is_colon_separated_sha256() {
        let dir = tempfile::tempdir().unwrap();
        let ca = CaManager::create(dir.path()).unwrap();
        let fp = ca.fingerprint_sha256();
        assert_eq!(fp.len(), 32 * 2 + 31);
        assert!(
            fp.split(':')
                .all(|c| c.len() == 2 && c.chars().all(|ch| ch.is_ascii_hexdigit()))
        );
    }

    #[test]
    fn dns_leaf_is_valid_server_cert_signed_by_root() {
        let dir = tempfile::tempdir().unwrap();
        let ca = CaManager::create(dir.path()).unwrap();
        let leaf_der = ca.mint_leaf("www.example.com").unwrap();
        let leaf = parse(&leaf_der);
        let root = parse(ca.ca_cert_der());

        assert!(!leaf.is_ca());
        assert_eq!(leaf.issuer(), root.subject());
        assert!(leaf.validity().is_valid());
        assert!(leaf.verify_signature(Some(root.public_key())).is_ok());

        let san = leaf
            .subject_alternative_name()
            .unwrap()
            .expect("SAN present")
            .value;
        assert!(
            san.general_names
                .iter()
                .any(|n| matches!(n, GeneralName::DNSName("www.example.com")))
        );

        let eku = leaf
            .extended_key_usage()
            .unwrap()
            .expect("EKU present")
            .value;
        assert!(eku.server_auth);
        assert!(leaf.subject().to_string().contains("www.example.com"));
        assert!(
            leaf.get_extension_unique(
                &x509_parser::oid_registry::OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER
            )
            .unwrap()
            .is_some()
        );
    }

    #[test]
    fn ip_leaf_uses_ip_san() {
        let dir = tempfile::tempdir().unwrap();
        let ca = CaManager::create(dir.path()).unwrap();
        for (host, expected) in [
            ("127.0.0.1", vec![127, 0, 0, 1]),
            ("[::1]", {
                let mut v = vec![0u8; 16];
                v[15] = 1;
                v
            }),
        ] {
            let leaf_der = ca.mint_leaf(host).unwrap();
            let leaf = parse(&leaf_der);
            let san = leaf
                .subject_alternative_name()
                .unwrap()
                .expect("SAN present")
                .value;
            assert!(
                san.general_names
                    .iter()
                    .any(|n| matches!(n, GeneralName::IPAddress(b) if *b == expected.as_slice())),
                "no IP SAN for {host}: {:?}",
                san.general_names
            );
        }
    }

    #[test]
    fn leaves_have_unique_serials() {
        let dir = tempfile::tempdir().unwrap();
        let ca = CaManager::create(dir.path()).unwrap();
        let a = parse(&ca.mint_leaf("a.test").unwrap())
            .raw_serial()
            .to_vec();
        let b = parse(&ca.mint_leaf("a.test").unwrap())
            .raw_serial()
            .to_vec();
        assert_ne!(a, b);
    }

    #[test]
    fn long_host_omits_common_name_but_keeps_san() {
        let dir = tempfile::tempdir().unwrap();
        let ca = CaManager::create(dir.path()).unwrap();
        let host = format!("{}.{}.example.com", "a".repeat(30), "b".repeat(30));
        let leaf = ca.mint_leaf(&host).unwrap();
        let leaf = parse(&leaf);
        assert!(!leaf.subject().to_string().contains(&host));
        let san = leaf.subject_alternative_name().unwrap().unwrap().value;
        assert!(
            san.general_names
                .iter()
                .any(|n| matches!(n, GeneralName::DNSName(h) if *h == host))
        );
    }

    #[test]
    fn rejects_garbage_host() {
        let dir = tempfile::tempdir().unwrap();
        let ca = CaManager::create(dir.path()).unwrap();
        for bad in [
            "",
            "bad host with spaces",
            "a..b",
            "-leading.dash",
            "trailing.",
            "ünïcode.example",
            "x!y",
        ] {
            assert!(ca.mint_leaf(bad).is_err(), "{bad:?} should be rejected");
        }
        for good in [
            "localhost",
            "a-b_c.example",
            "*.wild.example",
            "xn--bcher-kva.example",
            "10.0.0.1",
            "::1",
        ] {
            assert!(ca.mint_leaf(good).is_ok(), "{good:?} should be accepted");
        }
    }

    #[test]
    fn spki_fingerprint_is_stable_base64_sha256() {
        let dir = tempfile::tempdir().unwrap();
        let ca = CaManager::create(dir.path()).unwrap();
        let spki = ca.spki_sha256_base64().to_string();
        // base64 of a 32-byte SHA-256 is 44 chars (with padding).
        assert_eq!(spki.len(), 44);
        assert!(spki.ends_with('='));
        // stable across reload, and distinct per CA.
        assert_eq!(
            CaManager::load(dir.path()).unwrap().spki_sha256_base64(),
            spki
        );
        let other = tempfile::tempdir().unwrap();
        assert_ne!(
            CaManager::create(other.path())
                .unwrap()
                .spki_sha256_base64(),
            spki
        );
    }

    #[test]
    fn reset_produces_a_different_ca() {
        let dir = tempfile::tempdir().unwrap();
        let first = CaManager::create(dir.path()).unwrap().fingerprint_sha256();
        let second = CaManager::reset(dir.path()).unwrap().fingerprint_sha256();
        assert_ne!(first, second);
        let reloaded = CaManager::load(dir.path()).unwrap().fingerprint_sha256();
        assert_eq!(second, reloaded);
    }
}
