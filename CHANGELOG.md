# Changelog

All notable changes to Shrike, the open source web application security testing platform and
Burp Suite alternative, are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/).

## [0.10.0] - 2026-11-01

Headline: the integrated browser is now Firefox, fully open source, searchable
out of the box, and configured with Shrike's proxy and CA automatically.

### Added
- **Firefox is the integrated browser**, bundled into the app. On launch Shrike
  generates an isolated profile (a `user.js` that sets the proxy and a quiet
  testing configuration) and an enterprise `policies.json` that installs Shrike's
  CA, so HTTPS is intercepted with no prompts and the address-bar search works
  immediately. A Chromium-family browser remains a runtime fallback.

### Changed
- The integrated browser no longer floods the proxy history on startup: Firefox's
  background phone-home (Safe Browsing, telemetry, Normandy, remote-settings
  blocklist, captive-portal checks, Pocket/activity-stream, suggestions, prefetch)
  is disabled in the generated profile.
- The Extender panel reports context-menu, passive-scan and legacy HTTP-listener
  hooks as wired and active (they were shown as unsupported).
- Extension scan checks are gated to textual responses, so running extensions do
  not slow down browsing with per-asset round-trips to the JVM.
- Release notes are now curated and SEO-focused, and a CHANGELOG is maintained.

### Known issues
- The AppImage is not published this release: linuxdeploy fails on the bundled
  Firefox. Use the `.deb`, `.rpm`, the portable `.tar.gz` or the Flatpak instead.
- In installed packages the resources directory is read-only, so the Firefox CA
  policy cannot be written there yet; the CA is not auto-trusted in installed
  builds (a dev run is fine). Installing the CA into the Firefox profile via
  certutil is the planned fix.

## [0.9.0] - 2026-11-01

Headline: Shrike can now confirm blind vulnerabilities, discover hidden content, and run
data-driven detections, which pushes it from a capture-and-replay workbench toward a full web
vulnerability scanner and bug bounty platform.

### Added
- **Out-of-band (OAST) interaction server.** A self-hosted DNS and HTTP listener for confirming
  blind SSRF, blind XSS, blind SQL injection and out-of-band RCE. Each probe mints a unique
  `token.your-domain` payload; the DNS or HTTP callback is correlated back to it and streamed live
  in a new **Interactions** tab. Self-hosted on purpose, so callbacks never route through a third
  party.
- **Content discovery.** A fast path and file brute-forcer (ffuf / dirsearch style) with a built-in
  wordlist plus your own words and extensions. It learns the "not found" fingerprint from random
  probes first, so soft-404s and catch-all pages do not bury real hits. New **Discovery** tab.
- **Templated scanner.** Data-driven detections added as JSON, no code required. Templates describe
  requests and word / regex / status matchers with and/or conditions plus extractors, with
  `{{BaseURL}}` interpolation. Built-ins ship for exposed `.git/config`, `.env`, `phpinfo()` and
  Spring Boot Actuator; user templates load from the data directory. New **Templates** tab, and
  matches file as Findings.

### Changed
- Extension scan checks are gated to textual responses, so running extensions no longer slow down
  browsing with per-asset round-trips to the JVM.
- The Extender panel now reports context-menu, passive-scan and legacy HTTP-listener hooks as wired
  and active (they were being shown as unsupported).
- README rewritten and expanded for the current feature set and discoverability.

## [0.8.0] - 2026-10-31

### Added
- **Legacy `IBurpExtender` extension support.** Pre-Montoya Java extensions now load and run.
- **Context-menu bridge.** Extensions contribute right-click actions that open their own UI.
- **Extension scanner hook.** An extension's passive scan checks (Montoya `ScanCheck` or legacy
  `IScannerCheck`) now run over captured traffic and file Shrike Findings.
- **Native race-condition attack.** Single-packet / last-byte-sync request racing in Intruder, plus
  hidden parameter discovery surfaced in Extras.

### Changed
- Settings reorganised into a responsive, titled card layout.

[0.9.0]: https://github.com/ZeroDay-Labz/Shrike/releases/tag/v0.9.0
[0.8.0]: https://github.com/ZeroDay-Labz/Shrike/releases/tag/v0.8.0
