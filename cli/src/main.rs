use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use shrike_engine::{
    ca::{CaManager, trust},
    config::{ProxyConfig, UpstreamTlsMode},
    core::{EventBus, StdoutSink, TrafficSink},
    diagnostics::FriendlyTlsErrors,
    proxy,
};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tracing_subscriber::EnvFilter;

/// shrike: an original intercepting HTTPS proxy and web security toolkit.
#[derive(Parser, Debug)]
#[command(name = "shrike", version, about, long_about = None)]
struct Cli {
    /// Directory for the CA and project data (default: platform data dir).
    #[arg(long, global = true, env = "SHRIKE_DATA_DIR")]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,

    #[command(flatten)]
    run: RunArgs,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Start the intercepting proxy (default when no command is given).
    Run(RunArgs),
    /// Manage the root certificate authority.
    Ca {
        #[command(subcommand)]
        action: CaAction,
    },
}

#[derive(Subcommand, Debug)]
enum CaAction {
    /// Print where the CA lives and its fingerprint.
    Info,
    /// Write the CA certificate (PEM) to a file for importing into a trust store.
    Export {
        /// Output path (default: ./shrike-ca.crt).
        #[arg(default_value = proxy::CERT_FILENAME)]
        out: PathBuf,
    },
    /// Import the CA into every Firefox/Chrome profile on this machine (needs certutil from nss-tools).
    Trust {
        /// Only list what would be changed.
        #[arg(long, short = 'n')]
        dry_run: bool,
    },
    /// Delete the current CA and generate a new one. Every client must re-trust it.
    Reset {
        /// Skip the confirmation prompt.
        #[arg(long, short)]
        yes: bool,
    },
}

#[derive(Args, Debug, Clone)]
struct RunArgs {
    /// Address to listen on.
    #[arg(short, long, default_value = "127.0.0.1:8080")]
    listen: SocketAddr,

    /// Accept invalid/self-signed upstream certificates.
    #[arg(short = 'k', long)]
    insecure_upstream: bool,

    /// Host to tunnel without TLS interception; repeatable. A leading dot matches subdomains too.
    #[arg(long = "passthrough", value_name = "HOST")]
    passthrough_hosts: Vec<String>,

    /// Largest body (bytes) kept in the record; bigger ones are forwarded but not stored.
    #[arg(long, default_value_t = 10 * 1024 * 1024)]
    max_capture_bytes: usize,

    /// Print full requests and responses, not just one line per transaction.
    #[arg(short, long)]
    verbose: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let data_dir = cli.data_dir.unwrap_or_else(ProxyConfig::default_data_dir);
    let ca_dir = data_dir.join("ca");

    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
    tracing_subscriber::registry()
        .with(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                EnvFilter::new("shrike=info,shrike_engine=info,hudsucker=warn")
            }),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_writer(std::io::stderr),
        )
        .with(FriendlyTlsErrors::new(
            &ca_dir.join(shrike_engine::ca::CA_CERT_FILE),
        ))
        .init();

    match cli.command {
        Some(Command::Ca { action }) => ca_command(&ca_dir, action),
        Some(Command::Run(args)) => run(data_dir, args),
        None => run(data_dir, cli.run),
    }
}

fn ca_command(ca_dir: &std::path::Path, action: CaAction) -> Result<()> {
    match action {
        CaAction::Info => {
            let (ca, created) = CaManager::load_or_create(ca_dir)?;
            if created {
                println!("Generated a new CA.");
            }
            println!("Certificate : {}", ca.cert_path().display());
            println!(
                "Key         : {}",
                ca.dir().join(shrike_engine::ca::CA_KEY_FILE).display()
            );
            println!("SHA-256     : {}", ca.fingerprint_sha256());
            Ok(())
        }
        CaAction::Export { out } => {
            let (ca, _) = CaManager::load_or_create(ca_dir)?;
            ca.export_cert(&out)?;
            println!("Wrote {}", out.display());
            println!("SHA-256: {}", ca.fingerprint_sha256());
            Ok(())
        }
        CaAction::Trust { dry_run } => {
            let (ca, _) = CaManager::load_or_create(ca_dir)?;
            let home = directories::BaseDirs::new()
                .map(|b| b.home_dir().to_path_buf())
                .context("cannot determine home directory")?;
            let dbs = trust::find_nss_databases(&home);
            if dbs.is_empty() {
                println!(
                    "No Firefox or Chrome certificate databases found under {}.",
                    home.display()
                );
            } else if !dry_run && !trust::certutil_available() {
                anyhow::bail!(
                    "`certutil` not found; install nss-tools (Fedora: sudo dnf install nss-tools, Debian: sudo apt install libnss3-tools)"
                );
            }
            let mut failures = 0;
            for db in &dbs {
                if dry_run {
                    println!("would import into {:<40} {}", db.label, db.dir.display());
                    continue;
                }
                match trust::trust_in_nss(db, &ca.cert_path(), shrike_engine::ca::CA_COMMON_NAME) {
                    Ok(()) => println!("trusted in {:<40} {}", db.label, db.dir.display()),
                    Err(e) => {
                        failures += 1;
                        println!("FAILED    {:<40} {e}", db.label);
                    }
                }
            }
            if !dry_run && !dbs.is_empty() {
                println!("\nRestart Firefox/Chrome so they reload their certificate database.");
            }
            match trust::system_trust_command(&ca.cert_path()) {
                Some(cmd) => println!("For curl and other system tools, run:\n  {cmd}"),
                None => println!(
                    "For system tools, import {} into your OS trust store.",
                    ca.cert_path().display()
                ),
            }
            if failures > 0 {
                anyhow::bail!("{failures} import(s) failed");
            }
            Ok(())
        }
        CaAction::Reset { yes } => {
            if !yes {
                eprint!(
                    "This deletes the CA in {} and every client will need to trust the new one. Continue? [y/N] ",
                    ca_dir.display()
                );
                let mut line = String::new();
                std::io::stdin()
                    .read_line(&mut line)
                    .context("reading confirmation")?;
                if !matches!(line.trim(), "y" | "Y" | "yes") {
                    println!("Aborted.");
                    return Ok(());
                }
            }
            let ca = CaManager::reset(ca_dir)?;
            println!("New CA written to {}", ca.cert_path().display());
            println!("SHA-256: {}", ca.fingerprint_sha256());
            Ok(())
        }
    }
}

fn run(data_dir: PathBuf, args: RunArgs) -> Result<()> {
    let config = ProxyConfig {
        listen: args.listen,
        data_dir,
        upstream_tls: if args.insecure_upstream {
            UpstreamTlsMode::AcceptInvalid
        } else {
            UpstreamTlsMode::Verify
        },
        max_capture_bytes: args.max_capture_bytes,
        passthrough_hosts: args.passthrough_hosts,
        drop_out_of_scope: false,
        chromium_path: None,
        github_token: String::new(),
        intruder_require_scope: true,
        request_timeout_ms: 30_000,
        history_max_rows: 0,
        ..ProxyConfig::default()
    };

    let (ca, created) = CaManager::load_or_create(&config.ca_dir())?;
    let ca = Arc::new(ca);

    let runtime = tokio::runtime::Runtime::new().context("starting tokio runtime")?;
    runtime.block_on(async move {
        let listener = proxy::bind(&config).await?;
        let local = listener.local_addr()?;

        eprintln!("shrike proxy");
        eprintln!("  listening on      http://{local}");
        eprintln!(
            "  CA certificate    {}{}",
            ca.cert_path().display(),
            if created { "  (newly generated)" } else { "" }
        );
        eprintln!("  CA fingerprint    {}", ca.fingerprint_sha256());
        eprintln!("  install the CA    run `shrike ca trust` (Firefox/Chrome), or browse to http://{}/ through the proxy", proxy::LANDING_HOSTS[0]);
        eprintln!("                    until then browsers will refuse HTTPS through this proxy");
        if config.upstream_tls == UpstreamTlsMode::AcceptInvalid {
            eprintln!("  upstream TLS      NOT VERIFIED (-k)");
        }
        if !config.passthrough_hosts.is_empty() {
            eprintln!("  passthrough       {}", config.passthrough_hosts.join(", "));
        }
        eprintln!("  stop with         Ctrl+C\n");

        let sinks: Vec<Box<dyn TrafficSink>> = vec![Box::new(StdoutSink {
            verbose: args.verbose,
            ..StdoutSink::default()
        })];
        let (bus, bus_task) = EventBus::start(sinks);

        let shutdown = async {
            let _ = tokio::signal::ctrl_c().await;
            eprintln!("\nshutting down…");
        };
        // The headless CLI has no scope editor yet: run with an empty (permissive-by-config) scope.
        let scope = Arc::new(std::sync::RwLock::new(shrike_engine::scope::Scope::empty()));
        // The headless CLI never interactively intercepts; interception stays off.
        let interceptor = Arc::new(shrike_engine::intercept::Interceptor::new());
        // The headless CLI has no match & replace editor yet: run with no rules.
        let match_replace =
            Arc::new(std::sync::RwLock::new(shrike_engine::match_replace::MatchReplace::empty()));
        proxy::serve(listener, config, ca, bus, scope, interceptor, match_replace, shutdown).await?;
        // all handler clones are gone once serve() returns; let the bus drain.
        let _ = bus_task.await;
        Ok::<(), anyhow::Error>(())
    })
}
