//! Native JSON Web Token tool (RFC 7519 / 7515) — a clean-room, in-app
//! reimplementation of the common "JWT editor" workflow, with no JVM involved.
//!
//! Decodes a token's header/payload for inspection, and signs/re-signs with the
//! HMAC family (HS256/384/512) or the unsecured `none` algorithm — the pieces
//! needed to tamper with and test JWT-based auth. RSA/EC signing is out of scope
//! here (a later slice); those algorithms are reported, not forged.

use anyhow::{Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256, Sha384, Sha512};

/// A decoded token, ready to display and edit.
#[derive(Debug, Clone, Serialize)]
pub struct JwtParts {
    /// Pretty-printed header JSON (or the raw bytes if it was not valid JSON).
    pub header: String,
    /// Pretty-printed payload JSON (or raw).
    pub payload: String,
    /// The signature segment, exactly as it appeared (base64url), empty for `none`.
    pub signature: String,
    pub alg: Option<String>,
    pub typ: Option<String>,
    pub warnings: Vec<String>,
}

fn b64url_decode(seg: &str) -> Result<Vec<u8>> {
    // Tolerate tokens that carry base64url padding by stripping it first.
    let trimmed = seg.trim_end_matches('=');
    URL_SAFE_NO_PAD
        .decode(trimmed)
        .map_err(|e| anyhow!("invalid base64url segment: {e}"))
}

fn pretty_or_raw(bytes: &[u8], warnings: &mut Vec<String>, which: &str) -> (String, Option<Value>) {
    let text = String::from_utf8_lossy(bytes).into_owned();
    match serde_json::from_str::<Value>(&text) {
        Ok(v) => (
            serde_json::to_string_pretty(&v).unwrap_or_else(|_| text.clone()),
            Some(v),
        ),
        Err(_) => {
            warnings.push(format!("{which} is not valid JSON"));
            (text, None)
        }
    }
}

/// Decode a compact JWT (`header.payload[.signature]`) for inspection.
pub fn decode(token: &str) -> Result<JwtParts> {
    let parts: Vec<&str> = token.trim().split('.').collect();
    if parts.len() < 2 {
        bail!("not a JWT: expected at least header.payload");
    }
    let mut warnings = Vec::new();
    let (header, header_val) = pretty_or_raw(&b64url_decode(parts[0])?, &mut warnings, "header");
    let (payload, _) = pretty_or_raw(&b64url_decode(parts[1])?, &mut warnings, "payload");
    let signature = parts.get(2).map(|s| s.to_string()).unwrap_or_default();

    let str_field = |k: &str| {
        header_val
            .as_ref()
            .and_then(|v| v.get(k))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    };
    let alg = str_field("alg");
    if alg.as_deref() == Some("none") {
        warnings.push("alg is \"none\" — the signature is not verified".to_string());
    }
    if parts.len() < 3 || signature.is_empty() {
        warnings.push("token has no signature".to_string());
    }
    Ok(JwtParts {
        header,
        payload,
        signature,
        alg,
        typ: str_field("typ"),
        warnings,
    })
}

/// HMAC (RFC 2104) over a SHA-2 hasher, hand-rolled so no extra crate is needed.
fn hmac<D: Digest>(key: &[u8], msg: &[u8], block: usize) -> Vec<u8> {
    let mut k = if key.len() > block {
        let mut h = D::new();
        h.update(key);
        h.finalize().to_vec()
    } else {
        key.to_vec()
    };
    k.resize(block, 0);
    let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    let mut inner = D::new();
    inner.update(&ipad);
    inner.update(msg);
    let ih = inner.finalize();
    let mut outer = D::new();
    outer.update(&opad);
    outer.update(&ih);
    outer.finalize().to_vec()
}

/// Raw signature bytes for `signing_input` under `alg`. `none` yields no bytes;
/// RSA/EC and anything else is refused (this tool signs HMAC + none only).
fn sign_bytes(alg: &str, secret: &[u8], signing_input: &[u8]) -> Result<Vec<u8>> {
    match alg.to_ascii_uppercase().as_str() {
        "HS256" => Ok(hmac::<Sha256>(secret, signing_input, 64)),
        "HS384" => Ok(hmac::<Sha384>(secret, signing_input, 128)),
        "HS512" => Ok(hmac::<Sha512>(secret, signing_input, 128)),
        "NONE" => Ok(Vec::new()),
        other => bail!("unsupported algorithm {other}: this tool signs HS256/384/512 and none"),
    }
}

/// Sign (or re-sign) a token from header + payload JSON. The header's `alg` is
/// forced to `alg` so it matches the signature. Returns the compact JWT.
pub fn sign(header_json: &str, payload_json: &str, alg: &str, secret: &str) -> Result<String> {
    let mut header: Value =
        serde_json::from_str(header_json).map_err(|e| anyhow!("header is not valid JSON: {e}"))?;
    let payload: Value = serde_json::from_str(payload_json)
        .map_err(|e| anyhow!("payload is not valid JSON: {e}"))?;
    // Make the header's alg authoritative so verifiers see what we actually used.
    if let Some(obj) = header.as_object_mut() {
        obj.insert("alg".to_string(), Value::String(alg.to_string()));
    }
    let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
    let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload)?);
    let signing_input = format!("{h}.{p}");
    let sig = sign_bytes(alg, secret.as_bytes(), signing_input.as_bytes())?;
    Ok(format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig)))
}

/// Verify a token's HMAC/none signature with `secret`. Returns whether it is valid.
pub fn verify(token: &str, secret: &str) -> Result<bool> {
    let parts: Vec<&str> = token.trim().split('.').collect();
    if parts.len() < 2 {
        bail!("not a JWT");
    }
    let header: Value = serde_json::from_slice(&b64url_decode(parts[0])?)
        .map_err(|_| anyhow!("header is not valid JSON"))?;
    let alg = header
        .get("alg")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("header has no alg"))?;
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let expected = URL_SAFE_NO_PAD.encode(sign_bytes(
        alg,
        secret.as_bytes(),
        signing_input.as_bytes(),
    )?);
    Ok(parts.get(2).copied().unwrap_or("") == expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hs256_sign_verify_roundtrip() {
        let tok = sign(
            r#"{"alg":"HS256","typ":"JWT"}"#,
            r#"{"sub":"1","admin":false}"#,
            "HS256",
            "secret",
        )
        .unwrap();
        assert_eq!(tok.split('.').count(), 3);
        assert!(
            verify(&tok, "secret").unwrap(),
            "signed token verifies with the right key"
        );
        assert!(!verify(&tok, "wrong").unwrap(), "wrong key fails");
    }

    #[test]
    fn tamper_is_detected() {
        let tok = sign(r#"{"alg":"HS256"}"#, r#"{"admin":false}"#, "HS256", "k").unwrap();
        // forge the payload to admin:true, keep the old signature
        let forged_payload = URL_SAFE_NO_PAD.encode(br#"{"admin":true}"#);
        let parts: Vec<&str> = tok.split('.').collect();
        let forged = format!("{}.{}.{}", parts[0], forged_payload, parts[2]);
        assert!(
            !verify(&forged, "k").unwrap(),
            "tampered payload must fail verification"
        );
    }

    #[test]
    fn decode_reads_header_and_payload() {
        let tok = sign(
            r#"{"alg":"HS256","typ":"JWT"}"#,
            r#"{"sub":"abc"}"#,
            "HS256",
            "s",
        )
        .unwrap();
        let d = decode(&tok).unwrap();
        assert_eq!(d.alg.as_deref(), Some("HS256"));
        assert_eq!(d.typ.as_deref(), Some("JWT"));
        assert!(d.payload.contains("\"sub\""));
        assert!(!d.signature.is_empty());
    }

    #[test]
    fn none_alg_has_empty_signature() {
        let tok = sign(r#"{"alg":"HS256"}"#, r#"{"x":1}"#, "none", "ignored").unwrap();
        assert!(
            tok.ends_with('.'),
            "none produces an empty signature segment"
        );
        assert!(verify(&tok, "").unwrap(), "none verifies regardless of key");
        let d = decode(&tok).unwrap();
        assert!(
            d.warnings
                .iter()
                .any(|w| w.contains("none") || w.contains("no signature"))
        );
    }

    #[test]
    fn rsa_signing_is_refused() {
        assert!(sign(r#"{"alg":"RS256"}"#, "{}", "RS256", "k").is_err());
    }
}
