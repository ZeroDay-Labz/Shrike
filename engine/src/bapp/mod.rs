//! BApp Store integration (catalog + safe package inspection).
//!
//! Honest by construction: BApp extensions target the JVM (Montoya/Extender API,
//! or Jython/JRuby). Shrike is a Rust process with no JVM, so **no BApp runs
//! natively here**. This module lets the user browse a curated catalog, open the
//! official listing/source, and *inspect* a downloaded package safely (hash +
//! runtime classification) — it never executes anything. See
//! `docs/bapp-integration.md` and `docs/plugin-compatibility.md`.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Component, Path, PathBuf};

/// One entry in the bundled, offline catalog of notable BApps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BappEntry {
    pub id: String,
    pub name: String,
    pub author: String,
    pub category: String,
    pub description: String,
    /// Official source repository (best-effort; verify before trusting).
    pub repo_url: String,
    /// Official BApp Store, to find and download the extension.
    pub listing_url: String,
    /// Direct package download (release jar), when one is published — enables
    /// one-click install. `None` means resolve/download at install time.
    #[serde(default)]
    pub download_url: Option<String>,
    pub runtime: String,
    /// The Shrike tool that already covers this workflow, if any.
    #[serde(default)]
    pub native_equivalent: Option<String>,
    /// Curated, popular entries are featured at the top of the store.
    #[serde(default)]
    pub featured: bool,
}

/// The bundled catalog. Cache-first and fully offline: this ships with the app
/// and needs no network. A live catalog adapter is a separate, opt-in step
/// (see docs) — this is the always-available fallback.
pub fn catalog() -> Vec<BappEntry> {
    let mut entries: Vec<BappEntry> =
        serde_json::from_str(include_str!("catalog.json")).unwrap_or_default();
    // The bundled, hand-curated list is always the featured "top" set.
    for e in &mut entries {
        e.featured = true;
    }
    entries
}

/// Repo names in the catalog org that are not installable extensions
/// (tooling, the store site, API jars, check bundles) — filtered from the
/// "pull all" catalog so the list stays to actual BApps.
fn is_catalog_repo(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    const SKIP: &[&str] = &[
        "all-bappstore",
        "extension-portal",
        "bchecks",
        "bambdas",
        "burp-extensions",
        ".github",
    ];
    if SKIP.contains(&lower.as_str()) {
        return false;
    }
    // API/library jars, not standalone extensions.
    !(lower.ends_with("-api") || lower.ends_with("-lib") || lower.ends_with("-sdk"))
}

/// Turn a repo slug (`turbo-intruder`) into a display name (`Turbo Intruder`).
fn humanize(slug: &str) -> String {
    slug.split(['-', '_'])
        .filter(|w| !w.is_empty())
        .map(|w| {
            let mut c = w.chars();
            match c.next() {
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Deserialize)]
struct GithubRepo {
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    html_url: String,
    #[serde(default)]
    archived: bool,
    #[serde(default)]
    fork: bool,
}

/// Map one page of the GitHub org-repos API (a JSON array) into catalog entries,
/// dropping archived repos, forks, and non-extension tooling. Pure: the engine
/// handles the network, caching and pagination, so this is fixture-testable.
pub fn parse_github_repos(json: &str) -> Result<Vec<BappEntry>> {
    let repos: Vec<GithubRepo> =
        serde_json::from_str(json).context("parsing GitHub repos response")?;
    Ok(repos
        .into_iter()
        .filter(|r| !r.archived && !r.fork && is_catalog_repo(&r.name))
        .map(|r| BappEntry {
            name: humanize(&r.name),
            author: "community (public catalog)".to_string(),
            category: "Community".to_string(),
            description: r
                .description
                .filter(|d| !d.trim().is_empty())
                .unwrap_or_else(|| "BApp from the public catalog's GitHub mirror.".to_string()),
            repo_url: if r.html_url.is_empty() {
                format!("https://github.com/PortSwigger/{}", r.name)
            } else {
                r.html_url.clone()
            },
            listing_url: if r.html_url.is_empty() {
                format!("https://github.com/PortSwigger/{}", r.name)
            } else {
                r.html_url
            },
            download_url: None,
            runtime: "BApp (JVM)".to_string(),
            native_equivalent: None,
            featured: false,
            id: r.name,
        })
        .collect())
}

/// Blob (file) paths from a GitHub `git/trees/...?recursive=1` response.
/// Extract `owner/repo` from a GitHub repository URL. Returns `None` for a
/// non-github.com URL so the caller can fall back to its default org. Used so a
/// catalog entry that lives outside the mirror org (e.g. `h3xstream/burp-retire-js`)
/// is fetched from its real repository, not a guessed `<org>/<id>`.
pub fn github_slug(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("https://github.com/")
        .or_else(|| url.strip_prefix("http://github.com/"))
        .or_else(|| url.strip_prefix("https://www.github.com/"))?;
    let mut parts = rest.trim_end_matches('/').split('/');
    let owner = parts.next()?.trim();
    let repo = parts.next()?.trim().trim_end_matches(".git");
    if owner.is_empty() || repo.is_empty() {
        return None;
    }
    Some(format!("{owner}/{repo}"))
}

pub fn parse_tree_paths(json: &str) -> Vec<String> {
    #[derive(Deserialize)]
    struct Entry {
        path: String,
        #[serde(default, rename = "type")]
        kind: String,
    }
    #[derive(Deserialize)]
    struct Tree {
        #[serde(default)]
        tree: Vec<Entry>,
    }
    serde_json::from_str::<Tree>(json)
        .map(|t| {
            t.tree
                .into_iter()
                .filter(|e| e.kind == "blob")
                .map(|e| e.path)
                .collect()
        })
        .unwrap_or_default()
}

/// Ordered "grab from source" install candidates from a repo's blob paths:
/// committed `.jar`/`.bapp` packages first (shallowest, skipping test/example
/// dirs), then Python `.py` files. These need no compilation — exactly what we
/// can install directly from source when there is no release.
pub fn source_candidates(paths: &[String]) -> Vec<String> {
    let is_noise = |p: &str| {
        let l = p.to_ascii_lowercase();
        l.contains("test") || l.contains("example") || l.contains("sample") || is_dependency_dir(&l)
    };
    let depth = |p: &String| p.matches('/').count();
    let mut jars: Vec<&String> = paths
        .iter()
        .filter(|p| {
            let l = p.to_ascii_lowercase();
            (l.ends_with(".jar") || l.ends_with(".bapp")) && !is_noise(p)
        })
        .collect();
    let mut pys: Vec<&String> = paths
        .iter()
        .filter(|p| p.to_ascii_lowercase().ends_with(".py") && !is_noise(p))
        .collect();
    jars.sort_by_key(|p| depth(p));
    pys.sort_by_key(|p| depth(p));
    jars.into_iter().chain(pys).cloned().collect()
}

/// True for paths inside a directory of bundled third-party dependencies (e.g.
/// `libs/zap-2.4.3.jar`) or build tooling — never the extension itself.
fn is_dependency_dir(lower: &str) -> bool {
    lower
        .split('/')
        .rev()
        .skip(1) // the file name itself
        .any(|dir| {
            matches!(
                dir,
                // third-party / tooling
                "lib" | "libs" | "vendor" | "third_party" | "wrapper" | ".gradle" | ".mvn"
                // build outputs (a committed jar here is a stale artifact; build from source)
                | "target" | "build" | "out" | "bin"
            )
        })
}

/// The fields of a repository's `BappManifest.bmf` the installer acts on. The
/// manifest is plain `Key: Value` lines.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BappManifest {
    pub name: Option<String>,
    /// Path of the package (jar) or script (py) to load, relative to the repo.
    pub entry_point: Option<String>,
    /// 1 = Java, 2 = Python, 3 = Ruby.
    pub extension_type: Option<u8>,
    /// How the published package is built from source, if it must be.
    pub build_command: Option<String>,
}

impl BappManifest {
    /// Whether the manifest describes a Python (Jython) extension.
    pub fn is_python(&self) -> bool {
        self.extension_type == Some(2)
            || self
                .entry_point
                .as_deref()
                .is_some_and(|e| e.to_ascii_lowercase().ends_with(".py"))
    }
}

pub fn parse_manifest(text: &str) -> BappManifest {
    let mut m = BappManifest::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        let value = (!value.is_empty()).then(|| value.to_string());
        match key.trim() {
            "Name" => m.name = value,
            "EntryPoint" => m.entry_point = value,
            "ExtensionType" => m.extension_type = value.and_then(|v| v.parse().ok()),
            "BuildCommand" => m.build_command = value,
            _ => {}
        }
    }
    m
}

/// A repository-relative path that is safe to recreate under a local directory:
/// plain components only — no `..`, no absolute paths, no backslashes.
pub fn safe_rel_path(p: &str) -> Option<PathBuf> {
    if p.is_empty() || p.contains('\\') || p.contains('\0') {
        return None;
    }
    let path = Path::new(p);
    path.components()
        .all(|c| matches!(c, Component::Normal(_)))
        .then(|| path.to_path_buf())
}

/// Upper bound on files fetched for one Python extension's module tree.
pub const MAX_PYTHON_TREE_FILES: usize = 300;

/// The Python files a multi-file extension needs alongside its `entry` script:
/// every `.py` in the repository outside test/example directories, entry first.
/// `None` if the entry isn't in the tree or the tree is implausibly large.
pub fn python_tree_files(paths: &[String], entry: &str) -> Option<Vec<String>> {
    if !paths.iter().any(|p| p == entry) || safe_rel_path(entry).is_none() {
        return None;
    }
    let in_noise_dir = |p: &str| {
        p.to_ascii_lowercase().split('/').rev().skip(1).any(|d| {
            matches!(
                d,
                "test" | "tests" | "example" | "examples" | "sample" | "samples"
            )
        })
    };
    let mut files = vec![entry.to_string()];
    files.extend(
        paths
            .iter()
            .filter(|p| {
                p.as_str() != entry
                    && p.to_ascii_lowercase().ends_with(".py")
                    && !in_noise_dir(p)
                    && safe_rel_path(p).is_some()
            })
            .cloned(),
    );
    (files.len() <= MAX_PYTHON_TREE_FILES).then_some(files)
}

/// Pick a downloadable extension asset from a GitHub `releases/latest` response:
/// a `.jar` if present, else a `.bapp` (both are JVM packages Shrike can load).
/// Returns `(download_url, kind)` where `kind` is `"jar"` or `"bapp"`, or `None`
/// when the release has no installable package (source-only extension).
pub fn parse_release_asset(json: &str) -> Option<(String, String)> {
    #[derive(Deserialize)]
    struct Asset {
        name: String,
        browser_download_url: String,
    }
    #[derive(Deserialize)]
    struct Release {
        #[serde(default)]
        assets: Vec<Asset>,
    }
    let rel: Release = serde_json::from_str(json).ok()?;
    let ends = |a: &&Asset, ext: &str| a.name.to_ascii_lowercase().ends_with(ext);
    // Prefer a .jar, then fall back to a .bapp.
    let asset = rel
        .assets
        .iter()
        .find(|a| ends(a, ".jar"))
        .or_else(|| rel.assets.iter().find(|a| ends(a, ".bapp")))?;
    let kind = if ends(&asset, ".bapp") { "bapp" } else { "jar" };
    Some((asset.browser_download_url.clone(), kind.to_string()))
}

/// Result of inspecting a downloaded extension package. Describes it; never runs it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageInspection {
    pub filename: String,
    pub sha256: String,
    pub size_bytes: u64,
    /// "jar", "bapp", "python", "ruby", or "unknown".
    pub format: String,
    pub runtime: String,
    /// Honest compatibility status for Shrike's native runtime.
    pub compatibility: String,
    pub warnings: Vec<String>,
}

/// Largest package we will read into memory to hash/inspect.
const MAX_PACKAGE_BYTES: u64 = 128 * 1024 * 1024;

/// Hash and classify a package on disk. Does not extract or execute it.
pub fn inspect_package(path: impl AsRef<Path>) -> Result<PackageInspection> {
    let path = path.as_ref();
    let meta = std::fs::metadata(path).with_context(|| format!("reading {}", path.display()))?;
    let size_bytes = meta.len();
    if size_bytes > MAX_PACKAGE_BYTES {
        bail!("package is too large to inspect ({size_bytes} bytes)");
    }
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;

    let sha256 = hex::encode(Sha256::digest(&bytes));
    let filename = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let ext = path
        .extension()
        .map(|s| s.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();

    // A .bapp/.jar is a ZIP archive (magic "PK\x03\x04").
    let is_zip = bytes.starts_with(b"PK\x03\x04");
    let mut warnings = Vec::new();

    let (format, runtime, compatibility) = if ext == "bapp" || ext == "jar" || is_zip {
        (
            if ext == "bapp" { "bapp" } else { "jar" }.to_string(),
            "Java (Montoya/Extender API, JVM)".to_string(),
            "Not runnable in Shrike's native runtime — requires a JVM. Candidate for the optional Java \
             compatibility host or a native reimplementation (see docs/plugin-compatibility.md)."
                .to_string(),
        )
    } else if ext == "py" {
        (
            "python".to_string(),
            "Python via Jython (JVM)".to_string(),
            "Not runnable natively — Python BApps run on Jython (a JVM).".to_string(),
        )
    } else if ext == "rb" {
        (
            "ruby".to_string(),
            "Ruby via JRuby (JVM)".to_string(),
            "Not runnable natively — Ruby BApps run on JRuby (a JVM).".to_string(),
        )
    } else {
        warnings.push("unrecognised package format".to_string());
        (
            "unknown".to_string(),
            "unknown".to_string(),
            "Unrecognised package — cannot classify.".to_string(),
        )
    };

    if format == "bapp" || format == "jar" {
        warnings.push(
            "Archive contents not yet extracted/inspected (path-traversal and zip-bomb guards are a \
             planned slice). The package is only hashed and classified here; it is not unpacked or run."
                .to_string(),
        );
    }

    Ok(PackageInspection {
        filename,
        sha256,
        size_bytes,
        format,
        runtime,
        compatibility,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn github_slug_extracts_owner_and_repo() {
        assert_eq!(
            github_slug("https://github.com/h3xstream/burp-retire-js"),
            Some("h3xstream/burp-retire-js".into())
        );
        assert_eq!(
            github_slug("https://github.com/PortSwigger/logger/"),
            Some("PortSwigger/logger".into())
        );
        assert_eq!(
            github_slug("https://github.com/owner/repo.git"),
            Some("owner/repo".into())
        );
        // Not a github URL, or incomplete → None (caller falls back to the org).
        assert_eq!(github_slug("https://gitlab.com/a/b"), None);
        assert_eq!(github_slug("https://github.com/only-owner"), None);
    }

    #[test]
    fn catalog_parses_and_is_non_empty() {
        let c = catalog();
        assert!(!c.is_empty(), "bundled catalog should have entries");
        assert!(c.iter().any(|e| e.name == "JWT Editor"));
        assert!(c.iter().all(|e| !e.id.is_empty() && !e.runtime.is_empty()));
    }

    #[test]
    fn inspects_and_hashes_a_jar_like_zip() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("thing.jar");
        // minimal ZIP magic so it classifies as a JAR
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(b"PK\x03\x04rest-of-bytes").unwrap();
        drop(f);

        let r = inspect_package(&p).unwrap();
        assert_eq!(r.format, "jar");
        assert!(r.runtime.contains("JVM"));
        assert!(r.compatibility.contains("Not runnable"));
        assert_eq!(r.sha256.len(), 64, "sha256 is 32 bytes hex");
        assert!(r.size_bytes > 0);
    }

    #[test]
    fn github_repos_map_and_filter() {
        let json = r#"[
          {"name":"turbo-intruder","description":"A fast fuzzer","html_url":"https://github.com/PortSwigger/turbo-intruder","archived":false,"fork":false},
          {"name":"logger","description":null,"html_url":"https://github.com/PortSwigger/logger","archived":false,"fork":false},
          {"name":"old-thing","description":"x","html_url":"u","archived":true,"fork":false},
          {"name":"montoya-api","description":"api jar","html_url":"u","archived":false,"fork":false},
          {"name":"all-bappstore","description":"the store","html_url":"u","archived":false,"fork":false},
          {"name":"someones-fork","description":"x","html_url":"u","archived":false,"fork":true}
        ]"#;
        let entries = parse_github_repos(json).unwrap();
        let ids: Vec<&str> = entries.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["turbo-intruder", "logger"],
            "archived/fork/api/store filtered"
        );
        let turbo = &entries[0];
        assert_eq!(turbo.name, "Turbo Intruder", "slug humanized");
        assert!(!turbo.featured);
        // null description gets a sensible fallback, not an empty string
        assert!(!entries[1].description.trim().is_empty());
    }

    #[test]
    fn tree_paths_and_source_candidates() {
        let json = r#"{"tree":[
          {"path":"README.md","type":"blob"},
          {"path":"src/main/java/Foo.java","type":"blob"},
          {"path":"deep/dir/Ext.py","type":"blob"},
          {"path":"Ext.py","type":"blob"},
          {"path":"test/Test.py","type":"blob"},
          {"path":"dist/extension.jar","type":"blob"},
          {"path":"nested","type":"tree"}
        ]}"#;
        let paths = parse_tree_paths(json);
        assert!(paths.contains(&"Ext.py".to_string()));
        assert!(
            !paths.iter().any(|p| p == "nested"),
            "trees (dirs) excluded"
        );
        let cands = source_candidates(&paths);
        // jar first, then .py shallowest-first, test/ excluded
        assert_eq!(
            cands.first().map(String::as_str),
            Some("dist/extension.jar")
        );
        let py_order: Vec<&String> = cands.iter().filter(|p| p.ends_with(".py")).collect();
        assert_eq!(py_order, vec!["Ext.py", "deep/dir/Ext.py"]);
        assert!(!cands.iter().any(|p| p.contains("test")));
    }

    #[test]
    fn dependency_and_build_dirs_are_not_install_candidates() {
        // Retire.js ships its loadable jar only as a build output, and bundles a
        // third-party jar under libs/ — neither is a direct-install candidate.
        let paths = parse_tree_paths(
            r#"{"tree":[
              {"path":"libs/bundled-dep-2.4.3.jar","type":"blob"},
              {"path":"scanner-plugin/target/scanner-plugin-3.jar","type":"blob"},
              {"path":"build.gradle","type":"blob"}
            ]}"#,
        );
        assert!(
            source_candidates(&paths).is_empty(),
            "a bundled dependency jar is not the extension"
        );
    }

    #[test]
    fn manifest_parses_python_and_java_entry_points() {
        let py = parse_manifest(
            "Name: Autorize\nExtensionType: 2\nEntryPoint: Autorize.py\nBuildCommand: \n",
        );
        assert_eq!(py.name.as_deref(), Some("Autorize"));
        assert_eq!(py.entry_point.as_deref(), Some("Autorize.py"));
        assert!(py.is_python());
        assert_eq!(py.build_command, None, "an empty value is None");

        let java = parse_manifest(
            "Name: Scanner Plugin\nExtensionType: 1\nEntryPoint: target/scanner-plugin-3.jar\nBuildCommand: mvn package\n",
        );
        assert!(!java.is_python());
        assert_eq!(java.build_command.as_deref(), Some("mvn package"));
    }

    #[test]
    fn python_tree_collects_modules_entry_first_and_skips_tests() {
        let paths = vec![
            "Autorize.py".to_string(),
            "authorization/__init__.py".to_string(),
            "authorization/authorization.py".to_string(),
            "test/test_it.py".to_string(),
            "README.md".to_string(),
        ];
        let files = python_tree_files(&paths, "Autorize.py").unwrap();
        assert_eq!(files.first().map(String::as_str), Some("Autorize.py"));
        assert!(files.iter().any(|p| p == "authorization/authorization.py"));
        assert!(!files.iter().any(|p| p.contains("test")));
        assert!(!files.iter().any(|p| p.ends_with(".md")));
        // Entry not in the tree -> None (don't guess).
        assert!(python_tree_files(&paths, "Missing.py").is_none());
    }

    #[test]
    fn safe_rel_path_rejects_traversal_and_absolute_paths() {
        assert!(safe_rel_path("helpers/http.py").is_some());
        assert!(safe_rel_path("../etc/passwd").is_none());
        assert!(safe_rel_path("/etc/passwd").is_none());
        assert!(safe_rel_path("a/../../b").is_none());
        assert!(safe_rel_path("").is_none());
    }

    #[test]
    fn release_asset_is_picked_or_none() {
        let with_jar = r#"{"assets":[
          {"name":"notes.txt","browser_download_url":"https://x/notes.txt"},
          {"name":"ext-1.2.bapp","browser_download_url":"https://x/ext-1.2.bapp"},
          {"name":"ext-1.2.jar","browser_download_url":"https://x/ext-1.2.jar"}
        ]}"#;
        // .jar is preferred over .bapp when both are present
        assert_eq!(
            parse_release_asset(with_jar),
            Some(("https://x/ext-1.2.jar".to_string(), "jar".to_string()))
        );
        let only_bapp =
            r#"{"assets":[{"name":"thing.bapp","browser_download_url":"https://x/thing.bapp"}]}"#;
        assert_eq!(
            parse_release_asset(only_bapp),
            Some(("https://x/thing.bapp".to_string(), "bapp".to_string()))
        );
        let no_pkg =
            r#"{"assets":[{"name":"src.zip","browser_download_url":"https://x/src.zip"}]}"#;
        assert_eq!(parse_release_asset(no_pkg), None);
        assert_eq!(parse_release_asset("{}"), None);
    }

    #[test]
    fn curated_catalog_is_featured() {
        assert!(
            catalog().iter().all(|e| e.featured),
            "bundled entries are featured"
        );
    }

    #[test]
    fn classifies_python_and_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let py = dir.path().join("ext.py");
        std::fs::write(&py, b"print('hi')").unwrap();
        assert_eq!(inspect_package(&py).unwrap().format, "python");

        let bin = dir.path().join("data.bin");
        std::fs::write(&bin, b"\x00\x01\x02").unwrap();
        assert_eq!(inspect_package(&bin).unwrap().format, "unknown");
    }
}
