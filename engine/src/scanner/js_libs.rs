//! Native vulnerable-JavaScript-library check (a clean-room equivalent of the
//! retire.js scanner): passively fingerprint front-end libraries by version from
//! script URLs and inline banners, and flag versions with publicly known
//! vulnerabilities.
//!
//! The dataset below is a curated, extensible table of the most common libraries
//! and the version each is fixed in — reimplemented from public advisory data,
//! not copied from any project's files. Detection is deliberately conservative
//! (name-adjacent version captures only) to keep false positives low; it can be
//! widened, or backed by the full public dataset, later.

use super::Hit;
use crate::core::{CapturedResponse, Transaction};
use crate::findings::{Confidence, Severity};
use regex::Regex;
use std::cmp::Ordering;
use std::sync::OnceLock;

/// A known vulnerability: everything strictly below `fixed_in` is affected.
struct Vuln {
    fixed_in: &'static str,
    severity: Severity,
    summary: &'static str,
}

/// A library and how to detect its version, with its known vulnerabilities.
struct LibDef {
    name: &'static str,
    /// Regexes with a single capture group for the version (first match wins).
    patterns: &'static [&'static str],
    vulns: &'static [Vuln],
}

use Severity::{High, Medium};

/// Curated dataset. `fixed_in` is the first safe version; summaries paraphrase
/// public advisories. Ordered newest-fix last so the highest applicable severity
/// is reported.
const LIBS: &[LibDef] = &[
    LibDef {
        name: "jQuery",
        patterns: &[
            r"(?i)jquery[-.](\d+\.\d+\.\d+)(?:\.slim)?(?:\.min)?\.js",
            r"(?i)jQuery (?:JavaScript Library )?v(\d+\.\d+\.\d+)",
        ],
        vulns: &[
            Vuln {
                fixed_in: "1.9.0",
                severity: Medium,
                summary: "selector-based XSS and cross-domain request issues (pre-1.9)",
            },
            Vuln {
                fixed_in: "3.0.0",
                severity: Medium,
                summary: "cross-site scripting via jQuery.htmlPrefilter / location-based selectors",
            },
            Vuln {
                fixed_in: "3.5.0",
                severity: Medium,
                summary: "XSS via untrusted HTML passed to DOM-manipulation methods (CVE-2020-11022/11023)",
            },
        ],
    },
    LibDef {
        name: "jQuery UI",
        patterns: &[
            r"(?i)jquery-ui[-.](\d+\.\d+\.\d+)(?:\.min)?\.js",
            r"(?i)jQuery UI (?:- v)?(\d+\.\d+\.\d+)",
        ],
        vulns: &[Vuln {
            fixed_in: "1.13.2",
            severity: Medium,
            summary: "XSS in the datepicker/dialog title and other options (CVE-2022-31160 and earlier)",
        }],
    },
    LibDef {
        name: "AngularJS",
        patterns: &[
            r"(?i)angular(?:js)?[-.](\d+\.\d+\.\d+)(?:\.min)?\.js",
            r"(?i)angular(?:js)? (?:- )?v(\d+\.\d+\.\d+)",
        ],
        vulns: &[Vuln {
            fixed_in: "1.8.3",
            severity: Medium,
            summary: "multiple sandbox-bypass and prototype-pollution issues; AngularJS 1.x is end-of-life and unmaintained",
        }],
    },
    LibDef {
        name: "Bootstrap",
        patterns: &[
            r"(?i)bootstrap[-.](\d+\.\d+\.\d+)(?:\.min)?\.(?:js|css)",
            r"(?i)Bootstrap v(\d+\.\d+\.\d+)",
        ],
        vulns: &[
            Vuln {
                fixed_in: "3.4.1",
                severity: Medium,
                summary: "XSS via data-* attributes in tooltip/popover/scrollspy (CVE-2019-8331 and earlier)",
            },
            Vuln {
                fixed_in: "4.3.1",
                severity: Medium,
                summary: "XSS via data-template / data-target attributes (CVE-2019-8331)",
            },
        ],
    },
    LibDef {
        name: "Lodash",
        patterns: &[
            r"(?i)lodash[-.](\d+\.\d+\.\d+)(?:\.min)?\.js",
            r"(?i)lodash(?:\.js)? v?(\d+\.\d+\.\d+)",
        ],
        vulns: &[Vuln {
            fixed_in: "4.17.21",
            severity: High,
            summary: "prototype pollution and command-injection via template/zipObjectDeep (CVE-2019-10744, CVE-2021-23337)",
        }],
    },
    LibDef {
        name: "Underscore.js",
        patterns: &[
            r"(?i)underscore[-.](\d+\.\d+\.\d+)(?:\.min)?\.js",
            r"(?i)Underscore\.js (\d+\.\d+\.\d+)",
        ],
        vulns: &[Vuln {
            fixed_in: "1.12.1",
            severity: High,
            summary: "arbitrary code execution via the template function (CVE-2021-23358)",
        }],
    },
    LibDef {
        name: "Moment.js",
        patterns: &[
            r"(?i)moment[-.](\d+\.\d+\.\d+)(?:\.min)?\.js",
            r"(?is)moment\.js.{0,40}?version\s*:?\s*(\d+\.\d+\.\d+)",
        ],
        vulns: &[Vuln {
            fixed_in: "2.29.4",
            severity: Medium,
            summary: "path traversal and inefficient-regex denial of service (CVE-2022-24785, CVE-2022-31129)",
        }],
    },
    LibDef {
        name: "Handlebars",
        patterns: &[
            r"(?i)handlebars[-.](\d+\.\d+\.\d+)(?:\.min)?\.js",
            r"(?i)Handlebars(?:\.js)?.{0,20}?v(\d+\.\d+\.\d+)",
        ],
        vulns: &[Vuln {
            fixed_in: "4.7.7",
            severity: High,
            summary: "prototype pollution leading to remote code execution during template compilation (CVE-2019-19919, CVE-2021-23369)",
        }],
    },
    LibDef {
        name: "Axios",
        patterns: &[
            r"(?i)axios[-./](\d+\.\d+\.\d+)(?:\.min)?\.js",
            r"(?i)axios v?(\d+\.\d+\.\d+)",
        ],
        vulns: &[Vuln {
            fixed_in: "0.21.2",
            severity: Medium,
            summary: "server-side request forgery and inefficient-regex DoS (CVE-2020-28168, CVE-2021-3749)",
        }],
    },
    LibDef {
        name: "DOMPurify",
        patterns: &[
            r"(?i)(?:dompurify|purify)[-.](\d+\.\d+\.\d+)(?:\.min)?\.js",
            r"(?i)DOMPurify.{0,20}?(\d+\.\d+\.\d+)",
        ],
        vulns: &[Vuln {
            fixed_in: "2.4.0",
            severity: Medium,
            summary: "sanitiser bypasses allowing XSS in older releases",
        }],
    },
];

struct Compiled {
    name: &'static str,
    res: Vec<Regex>,
    vulns: &'static [Vuln],
}

fn compiled() -> &'static [Compiled] {
    static C: OnceLock<Vec<Compiled>> = OnceLock::new();
    C.get_or_init(|| {
        LIBS.iter()
            .map(|l| Compiled {
                name: l.name,
                res: l
                    .patterns
                    .iter()
                    .filter_map(|p| Regex::new(p).ok())
                    .collect(),
                vulns: l.vulns,
            })
            .collect()
    })
}

/// Compare dotted numeric versions; non-numeric trailing parts are ignored.
fn version_cmp(a: &str, b: &str) -> Ordering {
    let parse = |s: &str| -> Vec<u32> {
        s.split('.')
            .map(|p| {
                p.chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect::<String>()
                    .parse()
                    .unwrap_or(0)
            })
            .collect()
    };
    let (pa, pb) = (parse(a), parse(b));
    for i in 0..pa.len().max(pb.len()) {
        match pa
            .get(i)
            .copied()
            .unwrap_or(0)
            .cmp(&pb.get(i).copied().unwrap_or(0))
        {
            Ordering::Equal => continue,
            other => return other,
        }
    }
    Ordering::Equal
}

/// Flag vulnerable front-end libraries detected in a response. `corpus` should be
/// the response body plus the request URL (so versioned `.js` filenames count).
pub fn js_library_hits(txn: &Transaction, body: &str, resp: &CapturedResponse) -> Vec<Hit> {
    // Build the text to fingerprint: the body, the request URL, and any script
    // src URLs in the HTML (so a page that merely references a CDN lib is seen).
    let mut corpus = String::with_capacity(body.len() + 256);
    corpus.push_str(body);
    corpus.push('\n');
    corpus.push_str(&txn.request.url());
    for m in script_src_regex().captures_iter(body) {
        if let Some(src) = m.get(1) {
            corpus.push('\n');
            corpus.push_str(src.as_str());
        }
    }
    let _ = resp; // reserved: could consult headers later

    let mut hits = Vec::new();
    for lib in compiled() {
        let Some(version) = lib
            .res
            .iter()
            .find_map(|re| re.captures(&corpus).and_then(|c| c.get(1)))
            .map(|m| m.as_str().to_string())
        else {
            continue;
        };
        // The worst applicable advisory for the detected version.
        let worst = lib
            .vulns
            .iter()
            .filter(|v| version_cmp(&version, v.fixed_in) == Ordering::Less)
            .max_by_key(|v| v.severity as u8);
        let Some(worst) = worst else {
            continue;
        };
        let fixes: Vec<&str> = lib
            .vulns
            .iter()
            .filter(|v| version_cmp(&version, v.fixed_in) == Ordering::Less)
            .map(|v| v.summary)
            .collect();
        hits.push(Hit {
            check_id: "js-vuln-lib",
            title: format!("Vulnerable JavaScript library: {} {}", lib.name, version),
            severity: worst.severity,
            confidence: Confidence::Firm,
            detail: format!(
                "{} {} is in use. Known issues affecting this version:\n- {}\n\nUpgrade to {} or later.",
                lib.name,
                version,
                fixes.join("\n- "),
                worst.fixed_in,
            ),
            // The library name differentiates findings at the same location.
            param: Some(lib.name.to_string()),
        });
    }
    hits
}

fn script_src_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r#"(?i)<script[^>]+src\s*=\s*["']([^"']+)["']"#).expect("valid regex")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{CapturedRequest, CapturedResponse};
    use bytes::Bytes;

    fn txn_with(url: &str, body: &str, ctype: &str) -> Transaction {
        let (rp, _) = hyper::Request::builder()
            .method("GET")
            .uri(url)
            .body(())
            .unwrap()
            .into_parts();
        let request = CapturedRequest::from_parts(
            1,
            "127.0.0.1:9000".parse().unwrap(),
            &rp,
            Bytes::new(),
            0,
            true,
        )
        .unwrap();
        let (sp, _) = hyper::Response::builder()
            .status(200)
            .header("content-type", ctype)
            .body(())
            .unwrap()
            .into_parts();
        let response = CapturedResponse::from_parts(
            &sp,
            Bytes::copy_from_slice(body.as_bytes()),
            body.len(),
            true,
        );
        Transaction {
            request,
            response: Some(response),
            error: None,
            duration: std::time::Duration::from_millis(1),
        }
    }

    fn run(path: &str, body: &str, ctype: &str) -> Vec<Hit> {
        let txn = txn_with(&format!("https://lab.test{path}"), body, ctype);
        let resp = txn.response.clone().unwrap();
        js_library_hits(&txn, body, &resp)
    }

    #[test]
    fn version_comparison_is_numeric_not_lexical() {
        assert_eq!(version_cmp("3.4.1", "3.5.0"), Ordering::Less);
        assert_eq!(version_cmp("3.10.0", "3.9.0"), Ordering::Greater); // not lexical
        assert_eq!(version_cmp("1.8.3", "1.8.3"), Ordering::Equal);
        assert_eq!(version_cmp("1.7.2-beta", "1.8.0"), Ordering::Less);
    }

    #[test]
    fn flags_old_jquery_from_script_url() {
        let body =
            r#"<html><head><script src="/assets/jquery-1.7.2.min.js"></script></head></html>"#;
        let hits = run("/", body, "text/html");
        assert!(
            hits.iter().any(|h| h.title.contains("jQuery 1.7.2")),
            "expected a jQuery 1.7.2 finding, got {:?}",
            hits.iter().map(|h| &h.title).collect::<Vec<_>>()
        );
    }

    #[test]
    fn flags_old_jquery_from_inline_banner() {
        let body = "/*! jQuery JavaScript Library v3.3.1\n * https://jquery.com/ */";
        let hits = run("/app.js", body, "application/javascript");
        assert_eq!(hits.len(), 1);
        assert!(hits[0].title.contains("jQuery 3.3.1"));
        assert_eq!(hits[0].param.as_deref(), Some("jQuery"));
    }

    #[test]
    fn does_not_flag_a_patched_version() {
        let body = r#"<script src="/jquery-3.7.1.min.js"></script>"#;
        assert!(run("/", body, "text/html").is_empty());
    }

    #[test]
    fn flags_vulnerable_lodash_high_severity() {
        let hits = run("/static/lodash-4.17.10.min.js", "", "text/html");
        assert!(
            hits.iter()
                .any(|h| h.title.contains("Lodash 4.17.10") && h.severity == Severity::High)
        );
    }
}
