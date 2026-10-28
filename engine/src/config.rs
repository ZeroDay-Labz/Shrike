use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
};

/// How the proxy validates the TLS certificates presented by upstream servers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamTlsMode {
    /// Verify against the bundled Mozilla roots plus the OS trust store.
    Verify,
    /// Accept any certificate. Needed for self-signed lab targets; never for general browsing.
    AcceptInvalid,
}

/// Runtime configuration for the proxy listener.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Address the proxy listens on.
    pub listen: SocketAddr,
    /// Directory holding the CA key/cert and, later, project data.
    pub data_dir: PathBuf,
    /// Upstream certificate validation policy.
    pub upstream_tls: UpstreamTlsMode,
    /// Bodies larger than this are forwarded untouched but not retained in the record.
    pub max_capture_bytes: usize,
    /// Hosts whose CONNECT tunnels are passed through without TLS interception
    /// (certificate-pinned apps, update servers, ...). Matched case-insensitively,
    /// with a leading `.` meaning "this domain and all subdomains".
    pub passthrough_hosts: Vec<String>,
    /// When set, requests whose target is outside the configured scope are
    /// refused at the proxy with 403 instead of being forwarded. Off by default
    /// so ordinary browsing records everything; automated tools always honour scope.
    pub drop_out_of_scope: bool,
    /// Optional path to a Chromium/Chrome binary for the integrated browser.
    /// `None` uses the bundled Chromium (resolved by the GUI) or a system one.
    pub chromium_path: Option<String>,
    /// Optional GitHub personal access token for BApp-catalog/release API calls.
    /// Empty means unauthenticated (subject to GitHub's 60-requests/hour limit).
    pub github_token: String,
    /// When true (default), Intruder refuses to send requests that fall outside
    /// the configured target scope — scope is an enforcement boundary for
    /// automated tools, not just a UI filter.
    pub intruder_require_scope: bool,
    /// Total deadline for a manual/Intruder request (connect + response read),
    /// in milliseconds. Bounds a hung upstream so Stop is always responsive.
    pub request_timeout_ms: u64,
    /// History retention: keep at most this many newest transactions (0 =
    /// unlimited). Bounds unbounded project growth for long sessions.
    pub history_max_rows: usize,
    /// When true (default), the passive scanner inspects captured traffic and
    /// files Findings. No extra requests are ever sent.
    pub passive_scan_enabled: bool,
    /// Crawler: max concurrent in-flight fetches.
    pub crawl_concurrency: usize,
    /// Crawler: politeness delay between fetches per worker, in milliseconds.
    pub crawl_delay_ms: u64,
    /// Crawler: hard cap on pages fetched in one crawl.
    pub crawl_max_pages: usize,
    /// Active scanner: max concurrent in-flight probe requests.
    pub active_scan_concurrency: usize,
    /// Out-of-band interaction server (empty = disabled). Opt-in; used only by
    /// blind/OAST active checks.
    pub oob_server: String,
}

impl ProxyConfig {
    /// `~/.local/share/shrike` on Linux, the platform equivalent elsewhere.
    pub fn default_data_dir() -> PathBuf {
        directories::ProjectDirs::from("", "", "shrike")
            .map(|d| d.data_dir().to_path_buf())
            .unwrap_or_else(|| PathBuf::from(".shrike"))
    }

    pub fn ca_dir(&self) -> PathBuf {
        self.data_dir.join("ca")
    }

    /// True when `host` should be tunnelled without interception.
    pub fn is_passthrough(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        self.passthrough_hosts.iter().any(|rule| {
            let rule = rule.to_ascii_lowercase();
            if let Some(suffix) = rule.strip_prefix('.') {
                host == suffix || host.ends_with(&rule)
            } else {
                host == rule
            }
        })
    }
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
            data_dir: Self::default_data_dir(),
            upstream_tls: UpstreamTlsMode::Verify,
            max_capture_bytes: 10 * 1024 * 1024,
            passthrough_hosts: Vec::new(),
            drop_out_of_scope: false,
            chromium_path: None,
            github_token: String::new(),
            intruder_require_scope: true,
            request_timeout_ms: 30_000,
            history_max_rows: 0,
            passive_scan_enabled: true,
            crawl_concurrency: 8,
            crawl_delay_ms: 0,
            crawl_max_pages: 500,
            active_scan_concurrency: 10,
            oob_server: String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passthrough_rules_match_exact_and_suffix() {
        let cfg = ProxyConfig {
            passthrough_hosts: vec!["pinned.example".into(), ".apple.com".into()],
            ..ProxyConfig::default()
        };
        assert!(cfg.is_passthrough("pinned.example"));
        assert!(cfg.is_passthrough("PINNED.example"));
        assert!(!cfg.is_passthrough("sub.pinned.example"));
        assert!(cfg.is_passthrough("apple.com"));
        assert!(cfg.is_passthrough("push.apple.com"));
        assert!(!cfg.is_passthrough("notapple.com"));
    }
}
