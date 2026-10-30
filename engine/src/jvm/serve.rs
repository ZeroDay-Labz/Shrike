//! Persistent "serve" host: a long-lived JVM running an extension in serve mode,
//! driven over a framed stdin/stdout protocol so the extension's HTTP handlers
//! can process live traffic.
//!
//! The Java side (`jvm-host/src/shrike/host/Host.java`, serve mode) reads
//! `@REQ\t<id>\t<request|response>\t<host>\t<port>\t<secure>\t<base64 raw>` from
//! stdin, runs the bytes through every registered `HttpHandler`, and writes
//! `@RES\t<id>\t<continue|drop>\t<base64 raw>` back. Base64 keeps binary bodies
//! intact. Everything else the host prints (the load-summary JSON, `@OUT:`/
//! `@ERR:` log lines) is forwarded to `on_line` for the extension's console.

use anyhow::{Context, Result, anyhow};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tracing::warn;

use super::{JvmRuntime, RunningBapp};

/// Which leg of a transaction a frame carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Request,
    Response,
}

impl Phase {
    fn tag(self) -> &'static str {
        match self {
            Phase::Request => "request",
            Phase::Response => "response",
        }
    }
}

/// The upstream a message is bound for — the handler sees it as the HTTP service.
#[derive(Clone, Copy, Debug)]
pub struct Target<'a> {
    pub host: &'a str,
    pub port: u16,
    pub secure: bool,
}

/// What the extension chain decided for a message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HandlerAction {
    /// Forward these (possibly modified) bytes.
    Continue(Vec<u8>),
    /// Drop the message — an extension returned a drop action.
    Drop,
}

struct Res {
    drop: bool,
    raw: Vec<u8>,
}

/// A running extension in serve mode. Thread-safe; shared via `Arc`.
pub struct ServeHost {
    stdin: Mutex<ChildStdin>,
    child: Mutex<Child>,
    pending: Arc<Mutex<HashMap<u64, Sender<Res>>>>,
    next_id: AtomicU64,
}

impl ServeHost {
    /// Spawn `Host <ext> serve`, wiring a reader thread that routes `@RES` frames
    /// to waiters and forwards every other line (load summary, `@OUT`/`@ERR`) to
    /// `on_line` so the extension's console keeps working.
    pub fn spawn(
        rt: &JvmRuntime,
        ext: &Path,
        on_line: impl Fn(String) + Send + 'static,
    ) -> Result<Arc<ServeHost>> {
        let mut child = Command::new(&rt.java)
            .args(super::JVM_ADD_OPENS)
            .arg("-cp")
            .arg(super::classpath(rt))
            .arg("shrike.host.Host")
            .arg(ext)
            .arg("serve")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("launching serve host for {}", ext.display()))?;

        let stdin = child.stdin.take().context("capturing host stdin")?;
        let stdout = child.stdout.take().context("capturing host stdout")?;
        let pending: Arc<Mutex<HashMap<u64, Sender<Res>>>> = Arc::new(Mutex::new(HashMap::new()));

        let pending_r = Arc::clone(&pending);
        std::thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines().map_while(Result::ok) {
                if let Some(rest) = line.strip_prefix("@RES\t") {
                    route_result(&pending_r, rest);
                } else {
                    on_line(line);
                }
            }
        });

        Ok(Arc::new(ServeHost {
            stdin: Mutex::new(stdin),
            child: Mutex::new(child),
            pending,
            next_id: AtomicU64::new(1),
        }))
    }

    /// Send one message through the extension's handlers and wait for the result.
    /// A timeout (or a write failure) is an error the caller can treat as
    /// fail-open, so a wedged extension never blocks traffic forever.
    pub fn round_trip(
        &self,
        phase: Phase,
        target: Target<'_>,
        raw: &[u8],
        timeout: Duration,
    ) -> Result<HandlerAction> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel();
        self.pending.lock().expect("pending lock").insert(id, tx);

        let frame = format!(
            "@REQ\t{id}\t{}\t{}\t{}\t{}\t{}\n",
            phase.tag(),
            target.host,
            target.port,
            if target.secure { 1 } else { 0 },
            B64.encode(raw),
        );
        let write = {
            let mut stdin = self.stdin.lock().expect("stdin lock");
            stdin
                .write_all(frame.as_bytes())
                .and_then(|_| stdin.flush())
        };
        if let Err(e) = write {
            self.pending.lock().expect("pending lock").remove(&id);
            return Err(anyhow!("writing to serve host: {e}"));
        }

        match rx.recv_timeout(timeout) {
            Ok(res) if res.drop => Ok(HandlerAction::Drop),
            Ok(res) => Ok(HandlerAction::Continue(res.raw)),
            Err(_) => {
                self.pending.lock().expect("pending lock").remove(&id);
                Err(anyhow!("serve host did not respond within {timeout:?}"))
            }
        }
    }

    /// Whether the JVM process is still alive.
    pub fn is_alive(&self) -> bool {
        matches!(self.child.lock().expect("child lock").try_wait(), Ok(None))
    }

    /// Terminate the JVM process.
    pub fn kill(&self) {
        let mut child = self.child.lock().expect("child lock");
        let _ = child.kill();
        let _ = child.wait();
    }
}

/// Run a message through a chain of serve hosts in order. A `Drop` from any host
/// short-circuits. A host that errors or times out is skipped (fail-open) via
/// `on_error`, so one misbehaving extension never blocks or corrupts traffic.
pub fn process_chain(
    hosts: &[Arc<ServeHost>],
    phase: Phase,
    target: Target<'_>,
    raw: &[u8],
    timeout: Duration,
    mut on_error: impl FnMut(&str),
) -> HandlerAction {
    let mut cur = raw.to_vec();
    for h in hosts {
        match h.round_trip(phase, target, &cur, timeout) {
            Ok(HandlerAction::Continue(b)) => cur = b,
            Ok(HandlerAction::Drop) => return HandlerAction::Drop,
            Err(e) => on_error(&format!("{e:#}")),
        }
    }
    HandlerAction::Continue(cur)
}

/// Routes live proxy traffic through the running extensions' HTTP handlers.
///
/// Holds shared handles to the engine's running-host and state maps, so it
/// always reflects the extensions running right now (started or stopped live,
/// with no proxy restart). Constructed once and shared with the proxy handler.
pub struct BappBridge {
    hosts: Arc<Mutex<HashMap<String, Arc<ServeHost>>>>,
    state: Arc<Mutex<HashMap<String, Arc<Mutex<RunningBapp>>>>>,
    timeout: Duration,
}

impl BappBridge {
    pub fn new(
        hosts: Arc<Mutex<HashMap<String, Arc<ServeHost>>>>,
        state: Arc<Mutex<HashMap<String, Arc<Mutex<RunningBapp>>>>>,
        timeout: Duration,
    ) -> Self {
        Self {
            hosts,
            state,
            timeout,
        }
    }

    /// A bridge with no extensions — for proxy callers that don't run BApps
    /// (the CLI, tests). `active()` is always false, so traffic is never touched.
    pub fn disabled() -> Self {
        Self::new(
            Arc::new(Mutex::new(HashMap::new())),
            Arc::new(Mutex::new(HashMap::new())),
            Duration::from_secs(10),
        )
    }

    /// Running hosts that registered an HTTP handler, in a stable (sha-sorted)
    /// order so the chain is deterministic across requests.
    fn chain(&self) -> Vec<Arc<ServeHost>> {
        let state = self.state.lock().expect("bapp state lock");
        let hosts = self.hosts.lock().expect("bapp hosts lock");
        let mut shas: Vec<&String> = hosts.keys().collect();
        shas.sort();
        shas.into_iter()
            .filter(|sha| {
                state
                    .get(*sha)
                    .map(|s| {
                        s.lock()
                            .expect("running bapp lock")
                            .registered
                            .iter()
                            .any(|r| r == "registerHttpHandler")
                    })
                    .unwrap_or(false)
            })
            .filter_map(|sha| hosts.get(sha).map(Arc::clone))
            .collect()
    }

    /// Whether any running extension will process traffic. Cheap gate the proxy
    /// checks before doing any work.
    pub fn active(&self) -> bool {
        !self.chain().is_empty()
    }

    /// Run a message through the extension chain; fail-open on any error so a
    /// wedged extension never blocks or corrupts traffic.
    pub fn process(&self, phase: Phase, target: Target<'_>, raw: &[u8]) -> HandlerAction {
        let chain = self.chain();
        if chain.is_empty() {
            return HandlerAction::Continue(raw.to_vec());
        }
        process_chain(&chain, phase, target, raw, self.timeout, |e| {
            warn!(error = e, "extension handler failed; forwarding unchanged");
        })
    }
}

fn route_result(pending: &Mutex<HashMap<u64, Sender<Res>>>, rest: &str) {
    // <id>\t<continue|drop>\t<base64>
    let mut it = rest.splitn(3, '\t');
    let id = match it.next().and_then(|s| s.parse::<u64>().ok()) {
        Some(i) => i,
        None => return,
    };
    let action = it.next().unwrap_or("continue");
    let raw = it
        .next()
        .map(|b| B64.decode(b).unwrap_or_default())
        .unwrap_or_default();
    if let Some(tx) = pending.lock().expect("pending lock").remove(&id) {
        let _ = tx.send(Res {
            drop: action == "drop",
            raw,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_result_decodes_and_dispatches_by_id() {
        let pending: Arc<Mutex<HashMap<u64, Sender<Res>>>> = Arc::new(Mutex::new(HashMap::new()));
        let (tx, rx) = mpsc::channel();
        pending.lock().unwrap().insert(42, tx);
        // id 7 has no waiter → ignored; id 42 is delivered.
        route_result(&pending, &format!("7\tcontinue\t{}", B64.encode("x")));
        route_result(&pending, &format!("42\tcontinue\t{}", B64.encode("hello")));
        let res = rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(!res.drop);
        assert_eq!(res.raw, b"hello");
        assert!(pending.lock().unwrap().is_empty(), "waiter is consumed");
    }

    #[test]
    fn route_result_marks_drop() {
        let pending: Arc<Mutex<HashMap<u64, Sender<Res>>>> = Arc::new(Mutex::new(HashMap::new()));
        let (tx, rx) = mpsc::channel();
        pending.lock().unwrap().insert(1, tx);
        route_result(&pending, "1\tdrop\t");
        assert!(rx.recv().unwrap().drop);
    }

    // Spawns a real JVM; opt-in via `cargo test -p shrike-engine -- --ignored`.
    // Requires a dev checkout with the host jar built (jvm-host/build.sh) and a
    // JDK (javac) to compile the fixture extension.
    #[test]
    #[ignore]
    fn serve_host_round_trips_a_handler_edit() {
        use std::path::PathBuf;
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf();
        let host_jar = root.join("jvm-host/build/shrike-host.jar");
        let montoya = std::fs::read_dir(root.join("jvm-host/lib"))
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.path()))
            .find(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with("montoya-api") && n.ends_with(".jar"))
                    .unwrap_or(false)
            })
            .expect("montoya jar");
        let java = super::super::find_java(None).expect("java");
        let javac = java.with_file_name("javac");
        assert!(host_jar.is_file(), "run jvm-host/build.sh first");

        // Compile a fixture extension whose HttpHandler adds a header.
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("Fixture.java");
        std::fs::write(
            &src,
            r#"import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
public class Fixture implements BurpExtension {
  public void initialize(MontoyaApi api) {
    api.http().registerHttpHandler(new HttpHandler() {
      public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent r) {
        return RequestToBeSentAction.continueWith(r.withAddedHeader("X-Serve", "ok"));
      }
      public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived r) {
        return ResponseReceivedAction.continueWith(r);
      }
    });
  }
}
"#,
        )
        .unwrap();
        let classes = tmp.path().join("classes");
        std::fs::create_dir_all(&classes).unwrap();
        let ok = Command::new(&javac)
            .arg("-cp")
            .arg(&montoya)
            .arg("-d")
            .arg(&classes)
            .arg(&src)
            .status()
            .unwrap()
            .success();
        assert!(ok, "javac compiled the fixture");
        let ext_jar = tmp.path().join("fixture.jar");
        let ok = Command::new(java.with_file_name("jar"))
            .arg("cf")
            .arg(&ext_jar)
            .arg("-C")
            .arg(&classes)
            .arg(".")
            .status()
            .unwrap()
            .success();
        assert!(ok, "jarred the fixture");

        let rt = JvmRuntime {
            java,
            host_jar,
            montoya_jar: montoya,
            jython_jar: None,
            legacy_api_jar: None,
        };
        let host = ServeHost::spawn(&rt, &ext_jar, |_| {}).unwrap();
        let raw = b"GET /p HTTP/1.1\r\nHost: t.example\r\n\r\n";
        let action = host
            .round_trip(
                Phase::Request,
                Target {
                    host: "t.example",
                    port: 443,
                    secure: true,
                },
                raw,
                Duration::from_secs(10),
            )
            .unwrap();
        host.kill();
        match action {
            HandlerAction::Continue(b) => {
                let s = String::from_utf8_lossy(&b);
                assert!(s.contains("X-Serve: ok"), "handler edit returned: {s}");
            }
            HandlerAction::Drop => panic!("unexpected drop"),
        }
    }
}
