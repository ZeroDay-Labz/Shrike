# BApp Store integration

> **Status: implemented.** The full public catalog is mirrored from GitHub
> (cache-first), one-click install resolves a release package, a committed jar,
> or a Python source entry point, and extensions run in Shrike's own JVM host
> (Java via the Montoya API, Python via Jython + the legacy Extender API).
> Installs are quarantined and never executed until an explicit Run. The notes
> below are the original design findings that led here.

Status: **desk analysis**. Items marked (verify) must be confirmed against the live
official pages before any adapter is built. This project never bypasses any vendor
licensing and never rehosts third-party packages whose license forbids it.

## What the BApp Store is

The BApp Store is the public web catalog of BApp extensions, mirrored as
per-extension GitHub repositories. Each listing is a human-facing web page with:
name, author, a description, categories, a popularity/rating indicator, a
"last updated" date, a link to the **source repository** (usually GitHub), and a
downloadable extension package. Extensions are installed inside the vendor's suite from the
Extensions tab.

## Programmatic access

- **No documented, supported public catalog API** is known (verify). The catalog
  is presented as web pages, not an advertised REST/JSON endpoint.
- Therefore we do **not** invent or depend on an undocumented endpoint.
- Options, in order of preference:
  1. **Official-browser + manual import** (safe default): the manager links to the
     official listing and source repo, and lets the user import a `.bapp`/`.jar`
     they downloaded themselves.
  2. **Conservative cache-first adapter** over publicly accessible catalog data,
     *only if* the vendor's terms permit automated access (verify). It must be
     cache-first (ETag/Last-Modified), refresh on demand, never poll, and degrade
     to option 1 offline.
- We never block app startup on catalog access.

## Identification, versions, metadata

- Listings carry a name and (effectively) a stable identifier via their listing
  URL/source repo; version and update date are shown per release (verify exact
  fields available programmatically).
- Metadata we can show when available: name, author, description, categories,
  official listing URL, source repo URL, latest version, last-updated date, and
  the vendor's own estimated impact ratings — clearly labelled as **their
  estimates**, distinct from any impact we measure locally.

## Runtimes (why "downloadable" ≠ "runnable" here)

BApp extensions target JVM-based extension APIs:
- **Java / Montoya API** (modern) or the **legacy Extender API**.
- **Python** extensions run via **Jython** (JVM); **Ruby** via **JRuby** (JVM).

Shrike is a Rust process with no JVM. Consequently **no BApp runs natively** in
Shrike. Downloading and inspecting a package is possible; executing it requires
either a native reimplementation or an optional Java compatibility host (see
[plugin-compatibility.md](plugin-compatibility.md)). We will never mark a package
"runnable" because it merely downloaded.

## Licensing / redistribution

- Licenses vary per extension (many are permissive/open on GitHub, some are not).
- We **verify each extension's license** before reusing source or redistributing a
  package. When reuse isn't permitted or is unclear, we implement equivalent
  behavior independently or obtain permission. We do not mirror packages whose
  license forbids redistribution; we link to the official download instead.

## Decision for the first implementation slice

Build the manager around **manual import + official links + local staging/
inspection**, with a cache-first metadata layer added only after Phase A verifies
terms and available fields. This is resource-light and avoids fragile or
unauthorized scraping. See the milestone order in the project spec.
