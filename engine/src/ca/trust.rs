//! Install the root CA into trust stores found on this machine.
//!
//! Firefox and Chromium on Linux keep their own NSS databases, so importing
//! into the OS store is not enough. `certutil` (nss-tools) can write to both.

use anyhow::{Context, Result, anyhow};
use std::{
    path::{Path, PathBuf},
    process::Command,
};

/// A discovered NSS certificate database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NssDatabase {
    pub label: String,
    pub dir: PathBuf,
}

/// Locate NSS databases under `home`: Chrome/Chromium's shared one and every
/// Firefox profile (native, Flatpak and Snap layouts).
pub fn find_nss_databases(home: &Path) -> Vec<NssDatabase> {
    let mut found = Vec::new();

    let chrome = home.join(".pki/nssdb");
    if chrome.join("cert9.db").exists() {
        found.push(NssDatabase {
            label: "Chrome/Chromium".into(),
            dir: chrome,
        });
    }

    let firefox_roots = [
        (".mozilla/firefox", "Firefox"),
        (".config/mozilla/firefox", "Firefox"),
        (
            ".var/app/org.mozilla.firefox/.mozilla/firefox",
            "Firefox (Flatpak)",
        ),
        ("snap/firefox/common/.mozilla/firefox", "Firefox (Snap)"),
        (".librewolf", "LibreWolf"),
        (".thunderbird", "Thunderbird"),
        (".config/thunderbird", "Thunderbird"),
    ];
    for (rel, label) in firefox_roots {
        let Ok(entries) = std::fs::read_dir(home.join(rel)) else {
            continue;
        };
        let mut profiles: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.join("cert9.db").exists())
            .collect();
        profiles.sort();
        for dir in profiles {
            let name = dir
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            found.push(NssDatabase {
                label: format!("{label} profile {name}"),
                dir,
            });
        }
    }
    found
}

pub fn certutil_available() -> bool {
    Command::new("certutil").arg("-H").output().is_ok()
}

/// Import `cert_pem` into `db` as a trusted server CA, replacing any earlier
/// entry with the same nickname (so `ca reset` followed by `ca trust` works).
pub fn trust_in_nss(db: &NssDatabase, cert_pem: &Path, nickname: &str) -> Result<()> {
    let dbspec = format!("sql:{}", db.dir.display());
    // Remove a stale copy first; failure here just means there was none.
    let _ = Command::new("certutil")
        .args(["-d", &dbspec, "-D", "-n", nickname])
        .output();
    let out = Command::new("certutil")
        .args(["-d", &dbspec, "-A", "-t", "C,,", "-n", nickname, "-i"])
        .arg(cert_pem)
        .output()
        .context("running certutil (install nss-tools)")?;
    if out.status.success() {
        Ok(())
    } else {
        Err(anyhow!(
            "certutil failed for {}: {}{}",
            db.dir.display(),
            String::from_utf8_lossy(&out.stdout).trim(),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// True if the nickname is present in the database.
pub fn is_trusted_in_nss(db: &NssDatabase, nickname: &str) -> bool {
    Command::new("certutil")
        .args([
            "-d",
            &format!("sql:{}", db.dir.display()),
            "-L",
            "-n",
            nickname,
        ])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// The command that would add the CA to the operating-system store.
pub fn system_trust_command(cert_pem: &Path) -> Option<String> {
    let cert = cert_pem.display();
    if Path::new("/etc/pki/ca-trust/source/anchors").is_dir() {
        Some(format!(
            "sudo cp {cert} /etc/pki/ca-trust/source/anchors/shrike-ca.crt && sudo update-ca-trust"
        ))
    } else if Path::new("/usr/local/share/ca-certificates").is_dir() {
        Some(format!(
            "sudo cp {cert} /usr/local/share/ca-certificates/shrike-ca.crt && sudo update-ca-certificates"
        ))
    } else if Path::new("/etc/ca-certificates/trust-source/anchors").is_dir() {
        Some(format!(
            "sudo cp {cert} /etc/ca-certificates/trust-source/anchors/shrike-ca.crt && sudo trust extract-compat"
        ))
    } else if cfg!(target_os = "macos") {
        Some(format!(
            "sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain {cert}"
        ))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_chrome_and_firefox_profiles() {
        let home = tempfile::tempdir().unwrap();
        let mk = |rel: &str| {
            let d = home.path().join(rel);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("cert9.db"), b"").unwrap();
        };
        mk(".pki/nssdb");
        mk(".mozilla/firefox/abc.default-release");
        mk(".mozilla/firefox/xyz.dev-edition");
        std::fs::create_dir_all(home.path().join(".mozilla/firefox/no-db-here")).unwrap();
        mk(".var/app/org.mozilla.firefox/.mozilla/firefox/flat.default");

        let dbs = find_nss_databases(home.path());
        let labels: Vec<&str> = dbs.iter().map(|d| d.label.as_str()).collect();
        assert_eq!(
            labels,
            vec![
                "Chrome/Chromium",
                "Firefox profile abc.default-release",
                "Firefox profile xyz.dev-edition",
                "Firefox (Flatpak) profile flat.default",
            ]
        );
    }

    #[test]
    fn empty_home_finds_nothing() {
        let home = tempfile::tempdir().unwrap();
        assert!(find_nss_databases(home.path()).is_empty());
    }

    /// Full round trip against a scratch NSS database when certutil is installed.
    #[test]
    fn imports_into_fresh_nss_db() {
        if !certutil_available() {
            eprintln!("certutil missing; skipping");
            return;
        }
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join(".pki/nssdb");
        std::fs::create_dir_all(&dir).unwrap();
        let ok = Command::new("certutil")
            .args([
                "-d",
                &format!("sql:{}", dir.display()),
                "-N",
                "--empty-password",
            ])
            .status()
            .unwrap()
            .success();
        assert!(ok);
        let ca = crate::ca::CaManager::create(&home.path().join("ca")).unwrap();
        let db = NssDatabase {
            label: "test".into(),
            dir,
        };
        assert!(!is_trusted_in_nss(&db, "shrike-test"));
        trust_in_nss(&db, &ca.cert_path(), "shrike-test").unwrap();
        assert!(is_trusted_in_nss(&db, "shrike-test"));
        // idempotent
        trust_in_nss(&db, &ca.cert_path(), "shrike-test").unwrap();
    }
}
