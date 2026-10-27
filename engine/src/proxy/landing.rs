//! The proxy answers `http://shrike/` itself so users can download the CA
//! certificate from any browser that is already pointed at the proxy.

use crate::ca::CaManager;
use hudsucker::Body;
use hyper::{Request, Response, StatusCode, header};

/// Host names the proxy serves itself instead of forwarding.
pub const LANDING_HOSTS: [&str; 2] = ["shrike", "shrike.local"];
pub const CERT_FILENAME: &str = "shrike-ca.crt";

pub fn is_landing_request(req: &Request<Body>) -> bool {
    matches!(req.uri().scheme_str(), Some("http") | None)
        && req
            .uri()
            .host()
            .map(|h| LANDING_HOSTS.iter().any(|l| h.eq_ignore_ascii_case(l)))
            .unwrap_or(false)
}

pub fn respond(ca: &CaManager, req: &Request<Body>) -> Response<Body> {
    match req.uri().path() {
        "/cert" | "/cert.pem" | "/ca.crt" | "/shrike-ca.crt" => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/x-x509-ca-cert")
            // `inline` matters: Firefox then opens its "trust this CA" dialog
            // instead of saving a file, so the CA takes effect without a restart.
            .header(
                header::CONTENT_DISPOSITION,
                format!("inline; filename=\"{CERT_FILENAME}\""),
            )
            .header(header::CACHE_CONTROL, "no-store")
            .body(Body::from(ca.ca_cert_pem().to_string()))
            .expect("static response"),
        "/" => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .header(header::CACHE_CONTROL, "no-store")
            .body(Body::from(landing_html(ca)))
            .expect("static response"),
        _ => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Body::from("not found\n"))
            .expect("static response"),
    }
}

fn landing_html(ca: &CaManager) -> String {
    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>shrike proxy</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{{--bg:#fff;--fg:#1a1a1a;--muted:#5a5f66;--accent:#0b5fff;--card:#f4f6f8}}
@media (prefers-color-scheme:dark){{:root{{--bg:#121417;--fg:#e8eaed;--muted:#9aa3ad;--accent:#6ea8ff;--card:#1c2026}}}}
body{{margin:0;padding:24px 16px;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,sans-serif}}
main{{max-width:640px;margin:0 auto}}h1{{font-size:1.4rem;margin:0 0 .5rem}}
a.btn{{display:inline-block;background:var(--accent);color:#fff;padding:.6rem 1rem;border-radius:8px;text-decoration:none;font-weight:600}}
code{{background:var(--card);padding:.1rem .35rem;border-radius:4px;word-break:break-all}}
.card{{background:var(--card);border-radius:10px;padding:1rem;margin:1rem 0}}p{{margin:.5rem 0}}.muted{{color:var(--muted)}}
</style></head><body><main>
<h1>shrike proxy is running</h1>
<p class="muted">Your browser is talking to the proxy. Install its root certificate to intercept HTTPS.</p>
<p><a class="btn" href="/cert">Download CA certificate</a></p>
<div class="card">
<p><strong>SHA-256 fingerprint</strong><br><code>{fp}</code></p>
<p class="muted">Compare this with the fingerprint shown when you import the certificate.</p>
</div>
<div class="card">
<p><strong>Firefox</strong>: click the button above; Firefox asks whether to trust the new authority. Tick “Trust this CA to identify websites” and confirm. It takes effect immediately, no restart. (If no dialog appears: Settings → Privacy &amp; Security → View Certificates → Authorities → Import.)</p>
<p><strong>Chrome / Chromium (Linux)</strong>: Settings → Privacy and security → Security → Manage certificates → Authorities → Import.</p>
<p><strong>System (Fedora)</strong>: <code>sudo cp {file} /etc/pki/ca-trust/source/anchors/ &amp;&amp; sudo update-ca-trust</code></p>
<p><strong>curl</strong>: <code>curl --proxy http://127.0.0.1:8080 --cacert {file} https://example.com</code></p>
</div>
</main></body></html>
"#,
        fp = ca.fingerprint_sha256(),
        file = CERT_FILENAME,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(uri: &str) -> Request<Body> {
        Request::builder().uri(uri).body(Body::empty()).unwrap()
    }

    #[test]
    fn detects_landing_hosts_on_plain_http_only() {
        assert!(is_landing_request(&req("http://shrike/")));
        assert!(is_landing_request(&req("http://SHRIKE.local/cert")));
        assert!(!is_landing_request(&req("https://shrike/")));
        assert!(!is_landing_request(&req("http://example.com/")));
    }

    #[test]
    fn serves_cert_and_page() {
        let dir = tempfile::tempdir().unwrap();
        let ca = CaManager::create(dir.path()).unwrap();
        let res = respond(&ca, &req("http://shrike/cert"));
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers()[header::CONTENT_TYPE],
            "application/x-x509-ca-cert"
        );
        let res = respond(&ca, &req("http://shrike/"));
        assert_eq!(res.status(), StatusCode::OK);
        let res = respond(&ca, &req("http://shrike/nope"));
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }
}
