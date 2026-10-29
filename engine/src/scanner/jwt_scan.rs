//! Native JSON Web Token security checks.
//!
//! A clean-room implementation written from the well-known JWT weakness classes
//! (RFC 7519 + the OWASP JWT guidance), not ported from any extension. It finds
//! JWTs where applications actually carry them — `Authorization: Bearer`,
//! cookies, and `Set-Cookie` — and flags:
//!
//! - `alg: none` (unsigned tokens a server may accept as forged),
//! - HMAC tokens signed with a trivially guessable secret,
//! - tokens with no expiry, and tokens still being sent after they expired.
//!
//! The weak-secret check reuses Shrike's own HMAC from [`crate::tools::jwt`];
//! the small wordlist is common defaults, not copied material.

use crate::core::Transaction;
use crate::findings::{Confidence, Severity};
use crate::scanner::Hit;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;

/// Common/default HMAC signing secrets seen in tutorials, framework defaults and
/// copy-paste code. A hit here means the token can be forged outright.
const WEAK_SECRETS: &[&str] = &[
    "secret",
    "password",
    "changeme",
    "admin",
    "test",
    "jwt",
    "key",
    "private",
    "secretkey",
    "secret123",
    "123456",
    "qwerty",
    "your-256-bit-secret",
    "your_jwt_secret",
    "supersecret",
    "s3cr3t",
    "token",
    "jwtsecret",
    "mysecret",
    "default",
];

/// Most JWTs to analyse per transaction (bounds work on pathological inputs).
const MAX_TOKENS: usize = 8;

/// A JWT found in a message, with a human label for where it came from.
struct Located {
    token: String,
    /// Where it was found, e.g. `Authorization` or a cookie name — also the
    /// finding's `param`, so re-sends of the same token dedupe.
    location: String,
}

/// Run the JWT checks over one transaction. `now_secs` is the current Unix time
/// (passed in so the expiry check is deterministic under test).
pub fn jwt_hits(txn: &Transaction, now_secs: u64) -> Vec<Hit> {
    let mut hits = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for loc in collect_tokens(txn).into_iter().take(MAX_TOKENS) {
        // One finding set per distinct token, regardless of how many places it
        // appears, keyed by location for stable dedup.
        if !seen.insert(loc.token.clone()) {
            continue;
        }
        analyse(&loc, now_secs, &mut hits);
    }
    hits
}

/// Gather JWT candidates from the request's Authorization and Cookie headers and
/// the response's Set-Cookie headers.
fn collect_tokens(txn: &Transaction) -> Vec<Located> {
    let mut out = Vec::new();
    let req = &txn.request;

    if let Some(auth) = req.header("authorization") {
        let token = auth.strip_prefix("Bearer ").unwrap_or(auth).trim();
        if is_jwt_shaped(token) {
            out.push(Located {
                token: token.to_string(),
                location: "Authorization".to_string(),
            });
        }
    }

    for h in &req.headers {
        if h.name.eq_ignore_ascii_case("cookie") {
            collect_from_cookies(&h.value, &mut out);
        }
    }
    if let Some(resp) = txn.response.as_ref() {
        for h in &resp.headers {
            if h.name.eq_ignore_ascii_case("set-cookie") {
                // Set-Cookie is `name=value; attr; attr` — only the first pair.
                if let Some(first) = h.value.split(';').next() {
                    collect_from_cookies(first, &mut out);
                }
            }
        }
    }
    out
}

fn collect_from_cookies(header: &str, out: &mut Vec<Located>) {
    for pair in header.split(';') {
        if let Some((name, value)) = pair.split_once('=') {
            let value = value.trim();
            if is_jwt_shaped(value) {
                out.push(Located {
                    token: value.to_string(),
                    location: format!("cookie {}", name.trim()),
                });
            }
        }
    }
}

/// A compact JWT is three base64url segments; the header segment begins `eyJ`
/// (base64url of `{"`). Cheap pre-filter before we try to decode.
fn is_jwt_shaped(s: &str) -> bool {
    let segs: Vec<&str> = s.split('.').collect();
    (segs.len() == 2 || segs.len() == 3)
        && segs[0].starts_with("eyJ")
        && segs[0].len() >= 8
        && segs[1].starts_with("eyJ")
}

fn decode_segment(seg: &str) -> Option<Value> {
    let bytes = URL_SAFE_NO_PAD.decode(seg.trim_end_matches('=')).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn analyse(loc: &Located, now_secs: u64, hits: &mut Vec<Hit>) {
    let segs: Vec<&str> = loc.token.split('.').collect();
    let Some(header) = decode_segment(segs[0]) else {
        return; // not actually a JWT
    };
    let payload = segs.get(1).and_then(|s| decode_segment(s));
    let alg = header
        .get("alg")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let at = |check_id: &'static str, title: &str, sev, conf, detail: String| Hit {
        check_id,
        title: title.to_string(),
        severity: sev,
        confidence: conf,
        detail,
        param: Some(loc.location.clone()),
    };

    // 1. Unsigned token (alg: none in any casing).
    if alg.eq_ignore_ascii_case("none") {
        hits.push(at(
            "jwt-alg-none",
            "JWT uses the unsigned \"none\" algorithm",
            Severity::High,
            Confidence::Firm,
            format!(
                "The token in {} declares alg=\"{alg}\", which carries no signature. If the server \
                 accepts it, an attacker can forge arbitrary claims. Confirm the server rejects \
                 alg=none.",
                loc.location
            ),
        ));
    }

    // 2. Weak HMAC secret — only meaningful for HMAC algorithms.
    if alg.len() == 5
        && alg.to_ascii_uppercase().starts_with("HS")
        && let Some(secret) = WEAK_SECRETS
            .iter()
            .find(|s| crate::tools::jwt::verify(&loc.token, s).unwrap_or(false))
    {
        hits.push(at(
            "jwt-weak-secret",
            "JWT signed with a guessable secret",
            Severity::Critical,
            Confidence::Certain,
            format!(
                "The {alg} token in {} verifies against the common secret \"{secret}\". The \
                 signing key is trivially guessable, so tokens can be forged. Rotate to a long \
                 random key.",
                loc.location
            ),
        ));
    }

    // 3. / 4. Expiry hygiene (payload claims).
    if let Some(payload) = payload {
        match payload.get("exp").and_then(as_unix) {
            None => hits.push(at(
                "jwt-no-expiry",
                "JWT has no expiry claim",
                Severity::Low,
                Confidence::Firm,
                format!(
                    "The token in {} has no \"exp\" claim, so a leaked token is valid indefinitely.",
                    loc.location
                ),
            )),
            Some(exp) if exp < now_secs => hits.push(at(
                "jwt-expired",
                "Expired JWT still in use",
                Severity::Info,
                Confidence::Certain,
                format!(
                    "The token in {} expired at Unix time {exp} but is still being sent. Usually \
                     operational, but worth confirming the server actually rejects it.",
                    loc.location
                ),
            )),
            _ => {}
        }
    }
}

/// A numeric date claim as whole seconds (JSON numbers may be float).
fn as_unix(v: &Value) -> Option<u64> {
    v.as_u64().or_else(|| v.as_f64().map(|f| f as u64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{CapturedRequest, CapturedResponse, Transaction};
    use crate::tools::jwt;
    use bytes::Bytes;

    fn req_with_headers(headers: &[(&str, &str)]) -> CapturedRequest {
        let mut b = hyper::Request::builder()
            .method("GET")
            .uri("https://api.test/me");
        for (n, v) in headers {
            b = b.header(*n, *v);
        }
        let (parts, ()) = b.body(()).unwrap().into_parts();
        CapturedRequest::from_parts(
            1,
            "127.0.0.1:1".parse().unwrap(),
            &parts,
            Bytes::new(),
            0,
            true,
        )
        .unwrap()
    }

    fn txn(req: CapturedRequest, resp: Option<CapturedResponse>) -> Transaction {
        Transaction {
            request: req,
            response: resp,
            error: None,
            duration: std::time::Duration::from_millis(1),
        }
    }

    fn token(alg: &str, payload: &str, secret: &str) -> String {
        jwt::sign(&format!("{{\"alg\":\"{alg}\"}}"), payload, alg, secret).unwrap()
    }

    #[test]
    fn jwt_shape_filter_rejects_non_tokens() {
        assert!(is_jwt_shaped("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc"));
        assert!(!is_jwt_shaped("not-a-token"));
        assert!(!is_jwt_shaped("Bearer xyz"));
        assert!(!is_jwt_shaped("eyJ.only-one-seg"));
    }

    #[test]
    fn flags_weak_secret_in_bearer_header() {
        let t = token("HS256", "{\"sub\":\"1\",\"exp\":9999999999}", "secret");
        let hits = jwt_hits(
            &txn(
                req_with_headers(&[("authorization", &format!("Bearer {t}"))]),
                None,
            ),
            1000,
        );
        assert!(hits.iter().any(|h| h.check_id == "jwt-weak-secret"));
        assert_eq!(
            hits.iter()
                .find(|h| h.check_id == "jwt-weak-secret")
                .unwrap()
                .param
                .as_deref(),
            Some("Authorization")
        );
    }

    #[test]
    fn strong_secret_is_not_flagged() {
        let t = token(
            "HS256",
            "{\"sub\":\"1\",\"exp\":9999999999}",
            "9f3b2c1a-super-long-random-key-not-in-list",
        );
        let hits = jwt_hits(
            &txn(
                req_with_headers(&[("authorization", &format!("Bearer {t}"))]),
                None,
            ),
            1000,
        );
        assert!(!hits.iter().any(|h| h.check_id == "jwt-weak-secret"));
        // but it still has an expiry, so no no-expiry finding either
        assert!(!hits.iter().any(|h| h.check_id == "jwt-no-expiry"));
    }

    #[test]
    fn flags_alg_none_and_missing_expiry() {
        // alg=none token: header.payload. (empty sig)
        let header = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"none\"}");
        let payload = URL_SAFE_NO_PAD.encode(b"{\"sub\":\"admin\"}");
        let t = format!("{header}.{payload}.");
        let hits = jwt_hits(
            &txn(
                req_with_headers(&[("authorization", &format!("Bearer {t}"))]),
                None,
            ),
            1000,
        );
        assert!(hits.iter().any(|h| h.check_id == "jwt-alg-none"));
        assert!(hits.iter().any(|h| h.check_id == "jwt-no-expiry"));
    }

    #[test]
    fn flags_expired_token_in_cookie() {
        let t = token(
            "HS256",
            "{\"sub\":\"1\",\"exp\":500}",
            "9f3b2c1a-super-long-random-key",
        );
        let hits = jwt_hits(
            &txn(
                req_with_headers(&[("cookie", &format!("session={t}; theme=dark"))]),
                None,
            ),
            1000,
        );
        let expired = hits
            .iter()
            .find(|h| h.check_id == "jwt-expired")
            .expect("expired flagged");
        assert_eq!(expired.param.as_deref(), Some("cookie session"));
    }

    #[test]
    fn ignores_requests_without_jwts() {
        let hits = jwt_hits(
            &txn(
                req_with_headers(&[
                    ("authorization", "Basic dXNlcjpwYXNz"),
                    ("cookie", "theme=dark"),
                ]),
                None,
            ),
            1000,
        );
        assert!(hits.is_empty());
    }
}
