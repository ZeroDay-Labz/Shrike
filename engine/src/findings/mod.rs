//! Findings & annotations: the triage layer.
//!
//! A *finding* is a security issue recorded against the project — raised by the
//! operator today, and by the passive/active scanner once it lands (findings are
//! the home its output will file into). An *annotation* is a lightweight note +
//! highlight colour attached to a single captured transaction, for marking
//! history rows while reviewing.
//!
//! This module owns the value types and the report renderers (JSON + a
//! self-contained HTML document). Persistence lives in [`crate::store`].

use serde::{Deserialize, Serialize};

/// How serious a finding is. Ordered low→high so a descending sort yields the
/// usual "most severe first" presentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// Parse a stored/lowercase label; unknown values fall back to `Info`.
    pub fn parse(s: &str) -> Severity {
        match s.to_ascii_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        }
    }

    /// Every severity, most severe first — for summary tables.
    pub fn all_desc() -> [Severity; 5] {
        [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ]
    }
}

/// How sure we are the finding is real (distinct from its severity).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Tentative,
    Firm,
    Certain,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::Tentative => "tentative",
            Confidence::Firm => "firm",
            Confidence::Certain => "certain",
        }
    }
    pub fn parse(s: &str) -> Confidence {
        match s.to_ascii_lowercase().as_str() {
            "certain" => Confidence::Certain,
            "firm" => Confidence::Firm,
            _ => Confidence::Tentative,
        }
    }
}

/// Triage state of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    Open,
    Confirmed,
    FalsePositive,
    Resolved,
}

impl FindingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            FindingStatus::Open => "open",
            FindingStatus::Confirmed => "confirmed",
            FindingStatus::FalsePositive => "false_positive",
            FindingStatus::Resolved => "resolved",
        }
    }
    pub fn parse(s: &str) -> FindingStatus {
        match s.to_ascii_lowercase().as_str() {
            "confirmed" => FindingStatus::Confirmed,
            "false_positive" => FindingStatus::FalsePositive,
            "resolved" => FindingStatus::Resolved,
            _ => FindingStatus::Open,
        }
    }
}

/// A recorded security issue. The serializable view that crosses the engine
/// boundary and round-trips to the store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: u64,
    pub severity: Severity,
    pub confidence: Confidence,
    pub status: FindingStatus,
    pub title: String,
    /// Free-form detail / evidence (markdown-ish plain text).
    #[serde(default)]
    pub detail: String,
    /// Affected host, when the finding is tied to one.
    #[serde(default)]
    pub host: Option<String>,
    /// Affected path, when known.
    #[serde(default)]
    pub path: Option<String>,
    /// Transaction ids this finding is evidenced by.
    #[serde(default)]
    pub transaction_ids: Vec<u64>,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

/// Input to create a finding. Severity/confidence/status default sensibly so
/// callers (and the scanner) can supply only what they know.
#[derive(Debug, Clone, Deserialize)]
pub struct NewFinding {
    pub title: String,
    #[serde(default = "default_severity")]
    pub severity: Severity,
    #[serde(default = "default_confidence")]
    pub confidence: Confidence,
    #[serde(default)]
    pub detail: String,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub transaction_ids: Vec<u64>,
}

fn default_severity() -> Severity {
    Severity::Info
}
fn default_confidence() -> Confidence {
    Confidence::Firm
}

/// Partial update to an existing finding; only the set fields change.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct FindingUpdate {
    #[serde(default)]
    pub severity: Option<Severity>,
    #[serde(default)]
    pub confidence: Option<Confidence>,
    #[serde(default)]
    pub status: Option<FindingStatus>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub transaction_ids: Option<Vec<u64>>,
}

/// A note + highlight colour on a single captured transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Annotation {
    pub transaction_id: u64,
    /// A UI colour name/token (e.g. `red`, `amber`); `None` clears the highlight.
    #[serde(default)]
    pub color: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
    pub updated_at_ms: u64,
}

/// A findings report, ready to render.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub project: String,
    pub generated_at_ms: u64,
    /// Per-severity counts, most severe first.
    pub summary: Vec<SeverityCount>,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SeverityCount {
    pub severity: Severity,
    pub count: u64,
}

impl Report {
    /// Build a report from a finding set, computing the severity summary.
    pub fn new(project: impl Into<String>, generated_at_ms: u64, mut findings: Vec<Finding>) -> Report {
        // Most severe first, then most recently updated.
        findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then(b.updated_at_ms.cmp(&a.updated_at_ms))
        });
        let summary = Severity::all_desc()
            .into_iter()
            .map(|sev| SeverityCount {
                severity: sev,
                count: findings.iter().filter(|f| f.severity == sev).count() as u64,
            })
            .collect();
        Report {
            project: project.into(),
            generated_at_ms,
            summary,
            findings,
        }
    }

    /// Render as pretty JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".into())
    }

    /// Render as a self-contained HTML document (no external assets).
    pub fn to_html(&self) -> String {
        let mut out = String::with_capacity(4096);
        out.push_str(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
             <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
             <title>Shrike — Findings report</title><style>",
        );
        out.push_str(REPORT_CSS);
        out.push_str("</style></head><body><main>");
        out.push_str(&format!(
            "<header><h1>Findings report</h1><p class=\"meta\">{} · generated {}</p></header>",
            esc(&self.project),
            esc(&fmt_millis(self.generated_at_ms)),
        ));

        // Summary strip.
        out.push_str("<section class=\"summary\">");
        for s in &self.summary {
            out.push_str(&format!(
                "<div class=\"pill sev-{}\"><span class=\"n\">{}</span><span class=\"l\">{}</span></div>",
                s.severity.as_str(),
                s.count,
                s.severity.as_str(),
            ));
        }
        out.push_str("</section>");

        if self.findings.is_empty() {
            out.push_str("<p class=\"empty\">No findings recorded.</p>");
        }
        for f in &self.findings {
            out.push_str("<article class=\"finding\">");
            out.push_str(&format!(
                "<h2><span class=\"badge sev-{}\">{}</span> {}</h2>",
                f.severity.as_str(),
                f.severity.as_str(),
                esc(&f.title),
            ));
            out.push_str(&format!(
                "<p class=\"tags\"><span>confidence: {}</span><span>status: {}</span>{}{}</p>",
                f.confidence.as_str(),
                f.status.as_str(),
                f.host
                    .as_deref()
                    .map(|h| format!("<span>host: {}</span>", esc(h)))
                    .unwrap_or_default(),
                f.path
                    .as_deref()
                    .map(|p| format!("<span>path: {}</span>", esc(p)))
                    .unwrap_or_default(),
            ));
            if !f.detail.is_empty() {
                out.push_str(&format!("<pre class=\"detail\">{}</pre>", esc(&f.detail)));
            }
            if !f.transaction_ids.is_empty() {
                let ids = f
                    .transaction_ids
                    .iter()
                    .map(|i| i.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                out.push_str(&format!(
                    "<p class=\"evidence\">evidence: transaction(s) {}</p>",
                    esc(&ids)
                ));
            }
            out.push_str("</article>");
        }
        out.push_str("</main></body></html>");
        out
    }
}

const REPORT_CSS: &str = "\
:root{color-scheme:light dark}\
body{font:15px/1.5 system-ui,sans-serif;margin:0;background:#0f1115;color:#e6e6e6}\
main{max-width:900px;margin:0 auto;padding:32px 20px}\
header h1{margin:0 0 4px;font-size:24px}\
.meta{color:#8a93a3;margin:0 0 24px}\
.summary{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:28px}\
.pill{display:flex;flex-direction:column;align-items:center;min-width:72px;padding:10px;border-radius:8px;background:#1a1e26;border:1px solid #2a2f3a}\
.pill .n{font-size:22px;font-weight:700}\
.pill .l{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:#8a93a3}\
.finding{background:#161a21;border:1px solid #262b36;border-radius:10px;padding:16px 18px;margin-bottom:14px}\
.finding h2{margin:0 0 8px;font-size:17px;display:flex;align-items:center;gap:8px}\
.badge{font-size:11px;text-transform:uppercase;letter-spacing:.04em;padding:2px 8px;border-radius:999px;color:#fff}\
.tags{margin:0 0 10px;color:#8a93a3;font-size:13px;display:flex;gap:14px;flex-wrap:wrap}\
.detail{white-space:pre-wrap;background:#0f1218;border:1px solid #242934;border-radius:8px;padding:12px;overflow:auto;font:13px/1.5 ui-monospace,monospace}\
.evidence{color:#8a93a3;font-size:13px;margin:8px 0 0}\
.empty{color:#8a93a3}\
.sev-critical{background:#7f1d1d}.sev-high{background:#b45309}.sev-medium{background:#a16207}.sev-low{background:#1e6091}.sev-info{background:#374151}\
.pill.sev-critical{border-color:#7f1d1d}.pill.sev-high{border-color:#b45309}.pill.sev-medium{border-color:#a16207}.pill.sev-low{border-color:#1e6091}.pill.sev-info{border-color:#374151}\
";

/// Minimal HTML-escape for text interpolated into the report.
fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            _ => o.push(c),
        }
    }
    o
}

/// Format epoch-millis as an ISO-8601 UTC string without pulling in chrono.
fn fmt_millis(ms: u64) -> String {
    // Days from civil (Howard Hinnant's algorithm) → Y-M-D, plus H:M:S.
    let secs = (ms / 1000) as i64;
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (h, mi, s) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02} {h:02}:{mi:02}:{s:02} UTC")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(id: u64, sev: Severity, title: &str) -> Finding {
        Finding {
            id,
            severity: sev,
            confidence: Confidence::Firm,
            status: FindingStatus::Open,
            title: title.into(),
            detail: String::new(),
            host: None,
            path: None,
            transaction_ids: vec![],
            created_at_ms: 1,
            updated_at_ms: id,
        }
    }

    #[test]
    fn severity_round_trips_and_orders() {
        for s in Severity::all_desc() {
            assert_eq!(Severity::parse(s.as_str()), s);
        }
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::Info < Severity::Low);
        assert_eq!(Severity::parse("bogus"), Severity::Info);
    }

    #[test]
    fn report_sorts_most_severe_first_and_counts() {
        let findings = vec![
            finding(1, Severity::Low, "a"),
            finding(2, Severity::Critical, "b"),
            finding(3, Severity::Medium, "c"),
        ];
        let r = Report::new("proj", 0, findings);
        assert_eq!(r.findings[0].severity, Severity::Critical);
        assert_eq!(r.findings.last().unwrap().severity, Severity::Low);
        let crit = r
            .summary
            .iter()
            .find(|s| s.severity == Severity::Critical)
            .unwrap();
        assert_eq!(crit.count, 1);
    }

    #[test]
    fn html_report_is_self_contained_and_escapes() {
        let mut f = finding(1, Severity::High, "<script>alert(1)</script>");
        f.detail = "payload: \" & <b>".into();
        f.host = Some("lab.test".into());
        f.transaction_ids = vec![7, 8];
        let html = Report::new("Engagement", 0, vec![f]).to_html();
        assert!(html.starts_with("<!doctype html>"));
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("lab.test"));
        assert!(html.contains("transaction(s) 7, 8"));
        // no external resource references
        assert!(!html.contains("http://") && !html.contains("https://"));
    }

    #[test]
    fn fmt_millis_is_iso_utc() {
        // 2021-01-01T00:00:00Z = 1_609_459_200_000 ms
        assert_eq!(fmt_millis(1_609_459_200_000), "2021-01-01 00:00:00 UTC");
    }
}
