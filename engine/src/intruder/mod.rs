//! Intruder: configurable automated request testing (fuzzing).
//!
//! A request *template* carries payload positions marked with `§…§`; the text
//! between a pair of markers is that position's base value. The four classic
//! attack types decide how payloads are placed across positions. Requests run
//! with bounded concurrency and an optional per-request delay, and the attack
//! is cancellable. Generation is capped so an attack can never be unbounded.

use crate::{
    core::HttpService,
    sender::{RequestSpec, Sender},
};
pub mod generators;
pub mod payload;

use crate::core::Header;
use payload::{Processor, apply_all};
use serde::{Deserialize, Serialize};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::{sync::Semaphore, task::JoinSet, time::Duration};

/// Hard ceiling on generated requests, so a cluster-bomb cannot run away.
pub const MAX_REQUESTS: usize = 50_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackType {
    /// One payload set; each position is fuzzed in turn, others at their base value.
    Sniper,
    /// One payload set; the same payload goes into every position at once.
    BatteringRam,
    /// One set per position; sets advance together (zip).
    Pitchfork,
    /// One set per position; every combination (cartesian product).
    ClusterBomb,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IntruderConfig {
    pub service: HttpService,
    /// Raw request with `§…§` markers around each payload position.
    pub template: String,
    pub attack: AttackType,
    /// Payload sets. Sniper/BatteringRam use the first; Pitchfork/ClusterBomb use one per position.
    pub payload_sets: Vec<Vec<String>>,
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    #[serde(default)]
    pub delay_ms: u64,
    /// Transformations applied to every payload before insertion, in order.
    #[serde(default)]
    pub processors: Vec<Processor>,
}

fn default_concurrency() -> usize {
    10
}

/// Predicted number of requests for an attack, or `None` if it overflows u64.
/// `set_sizes` is one size per payload set (per position for pitchfork/cluster).
pub fn expected_count(attack: AttackType, n_positions: usize, set_sizes: &[u64]) -> Option<u64> {
    match attack {
        AttackType::Sniper => (n_positions as u64).checked_mul(*set_sizes.first().unwrap_or(&0)),
        AttackType::BatteringRam => Some(*set_sizes.first().unwrap_or(&0)),
        AttackType::Pitchfork => Some(
            (0..n_positions)
                .map(|i| set_sizes.get(i).copied().unwrap_or(0))
                .min()
                .unwrap_or(0),
        ),
        AttackType::ClusterBomb => {
            if n_positions == 0 {
                return Some(0);
            }
            let mut total: u64 = 1;
            for i in 0..n_positions {
                let sz = set_sizes.get(i).copied().unwrap_or(0);
                total = total.checked_mul(sz)?;
            }
            Some(total)
        }
    }
}

/// Recalculate the `Content-Length` header to match the actual body length.
/// Used for preview display; the transport layer sets it on the wire itself.
pub fn recalc_content_length(raw: &str) -> String {
    let norm = raw.replace("\r\n", "\n");
    let Some(sep) = norm.find("\n\n") else {
        return raw.to_string();
    };
    let body_len = norm[sep + 2..].len();
    let head = &norm[..sep];
    let mut out_lines: Vec<String> = Vec::new();
    let mut had = false;
    for line in head.split('\n') {
        if let Some((name, _)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("content-length")
        {
            out_lines.push(format!("{}: {}", name.trim(), body_len));
            had = true;
            continue;
        }
        out_lines.push(line.to_string());
    }
    let _ = had;
    format!("{}\n\n{}", out_lines.join("\n"), &norm[sep + 2..])
}

#[derive(Debug, Clone, Serialize)]
pub struct AttackResult {
    pub index: u64,
    pub payloads: Vec<String>,
    pub status: Option<u16>,
    pub length: usize,
    pub duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AttackEvent {
    Started {
        attack_id: u64,
        total: u64,
        capped: bool,
    },
    /// A single result. Retained for compatibility; `run` emits [`AttackEvent::Results`].
    Result(AttackResult),
    /// A coalesced batch of results. Emitting results in batches (rather than one
    /// event per request) keeps a 50k-request attack from flooding the UI transport.
    Results(Vec<AttackResult>),
    Done {
        attack_id: u64,
        completed: u64,
        stopped: bool,
    },
}

/// Parse `§…§` markers: returns the request without markers and, for each
/// position, its start offset (bytes) in that clean text and its base value.
pub fn parse_template(marked: &str) -> (String, Vec<(usize, String)>) {
    let parts: Vec<&str> = marked.split('§').collect();
    let mut clean = String::new();
    let mut positions = Vec::new();
    // Even parts are outside markers; odd parts are inside a §…§ pair.
    // A trailing unmatched marker (even number of parts) is treated as literal text.
    let balanced = parts.len() % 2 == 1;
    for (i, part) in parts.iter().enumerate() {
        let inside = i % 2 == 1 && (balanced || i != parts.len() - 1);
        if inside {
            let start = clean.len();
            clean.push_str(part);
            positions.push((start, part.to_string()));
        } else {
            clean.push_str(part);
        }
    }
    (clean, positions)
}

/// Splice one replacement per position into the clean template.
fn build(clean: &str, positions: &[(usize, String)], repls: &[String]) -> String {
    let mut out = String::with_capacity(clean.len());
    let mut last = 0;
    for (i, (start, base)) in positions.iter().enumerate() {
        out.push_str(&clean[last..*start]);
        out.push_str(repls.get(i).map(|s| s.as_str()).unwrap_or(base));
        last = start + base.len();
    }
    out.push_str(&clean[last..]);
    out
}

struct Job {
    repls: Vec<String>,
    display: Vec<String>,
}

/// Build the (capped) list of jobs for an attack. `bases` are the positions'
/// original values, used by Sniper for the positions it is not currently fuzzing.
fn generate(
    attack: AttackType,
    bases: &[String],
    sets: &[Vec<String>],
    processors: &[Processor],
    limit: usize,
) -> (Vec<Job>, bool) {
    let n = bases.len();
    let mut jobs = Vec::new();
    let mut capped = false;
    let proc = |v: &str| apply_all(processors, v);
    let push = |jobs: &mut Vec<Job>, job: Job| -> bool {
        if jobs.len() >= limit {
            return false;
        }
        jobs.push(job);
        true
    };

    match attack {
        AttackType::Sniper => {
            let set = sets.first().cloned().unwrap_or_default();
            'outer: for pos in 0..n {
                for v in &set {
                    let pv = proc(v);
                    let mut repls = bases.to_vec();
                    repls[pos] = pv.clone();
                    if !push(
                        &mut jobs,
                        Job {
                            repls,
                            display: vec![pv],
                        },
                    ) {
                        capped = true;
                        break 'outer;
                    }
                }
            }
        }
        AttackType::BatteringRam => {
            let set = sets.first().cloned().unwrap_or_default();
            for v in &set {
                let pv = proc(v);
                let repls = vec![pv.clone(); n];
                if !push(
                    &mut jobs,
                    Job {
                        repls,
                        display: vec![pv],
                    },
                ) {
                    capped = true;
                    break;
                }
            }
        }
        AttackType::Pitchfork => {
            let len = (0..n)
                .map(|i| sets.get(i).map(|s| s.len()).unwrap_or(0))
                .min()
                .unwrap_or(0);
            #[allow(clippy::needless_range_loop)] // k indexes every set in lock-step
            for k in 0..len {
                let repls: Vec<String> = (0..n).map(|i| proc(&sets[i][k])).collect();
                let display = repls.clone();
                if !push(&mut jobs, Job { repls, display }) {
                    capped = true;
                    break;
                }
            }
        }
        AttackType::ClusterBomb => {
            // odometer over the sets
            if n > 0 && (0..n).all(|i| sets.get(i).map(|s| !s.is_empty()).unwrap_or(false)) {
                let mut idx = vec![0usize; n];
                'cluster: loop {
                    let repls: Vec<String> = (0..n).map(|i| proc(&sets[i][idx[i]])).collect();
                    let display = repls.clone();
                    if !push(&mut jobs, Job { repls, display }) {
                        capped = true;
                        break 'cluster;
                    }
                    // increment odometer
                    let mut i = 0;
                    loop {
                        idx[i] += 1;
                        if idx[i] < sets[i].len() {
                            break;
                        }
                        idx[i] = 0;
                        i += 1;
                        if i == n {
                            break 'cluster;
                        }
                    }
                }
            }
        }
    }
    (jobs, capped)
}

/// Parse a raw HTTP/1.1 request into a [`RequestSpec`] for the given service.
fn parse_request(raw: &str, service: HttpService) -> RequestSpec {
    let norm = raw.replace("\r\n", "\n");
    let (head, body) = match norm.split_once("\n\n") {
        Some((h, b)) => (h, b.to_string()),
        None => (norm.as_str(), String::new()),
    };
    let mut lines = head.split('\n');
    let start = lines.next().unwrap_or("").trim();
    let mut sp = start.split_whitespace();
    let method = sp.next().unwrap_or("GET").to_string();
    let target = sp.next().unwrap_or("/").to_string();
    let headers = lines
        .filter_map(|l| {
            l.split_once(':').map(|(n, v)| Header {
                name: n.trim().to_string(),
                value: v.trim().to_string(),
            })
        })
        .collect();
    RequestSpec {
        service,
        method,
        target,
        headers,
        body,
    }
}

/// Upper bound on in-flight requests. The concurrency the caller asks for is
/// honoured up to this ceiling so a mistyped thread count can't fan out absurdly.
pub const MAX_CONCURRENCY: usize = 512;
/// Flush a batch once this many results have accumulated (under high load).
const BATCH_FLUSH_EVERY: usize = 250;
/// Flush whatever has accumulated at least this often (for a slow trickle / tail).
const BATCH_FLUSH_INTERVAL_MS: u64 = 100;

/// Drain per-request results off `rx` and emit them to `sink` in coalesced
/// [`AttackEvent::Results`] batches — every `flush_every` results or every
/// `interval`, whichever comes first. Returns once the channel is closed, after
/// flushing any remainder. This decouples request completion (tens of thousands
/// of events/sec at peak) from UI delivery (tens of events/sec).
async fn batch_results(
    mut rx: tokio::sync::mpsc::UnboundedReceiver<AttackResult>,
    sink: Arc<dyn Fn(AttackEvent) + Send + Sync>,
    flush_every: usize,
    interval: Duration,
) {
    let mut buf: Vec<AttackResult> = Vec::new();
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            maybe = rx.recv() => match maybe {
                Some(r) => {
                    buf.push(r);
                    if buf.len() >= flush_every {
                        sink(AttackEvent::Results(std::mem::take(&mut buf)));
                    }
                }
                None => {
                    if !buf.is_empty() {
                        sink(AttackEvent::Results(std::mem::take(&mut buf)));
                    }
                    return;
                }
            },
            _ = tick.tick() => {
                if !buf.is_empty() {
                    sink(AttackEvent::Results(std::mem::take(&mut buf)));
                }
            }
        }
    }
}

/// Run an attack to completion (or until `stop`), reporting through `sink`.
pub async fn run(
    attack_id: u64,
    config: IntruderConfig,
    sender: Arc<Sender>,
    sink: Arc<dyn Fn(AttackEvent) + Send + Sync>,
    stop: Arc<AtomicBool>,
) {
    let (clean, positions) = parse_template(&config.template);
    let bases: Vec<String> = positions.iter().map(|(_, b)| b.clone()).collect();
    let (jobs, capped) = generate(
        config.attack,
        &bases,
        &config.payload_sets,
        &config.processors,
        MAX_REQUESTS,
    );

    sink(AttackEvent::Started {
        attack_id,
        total: jobs.len() as u64,
        capped,
    });

    let sem = Arc::new(Semaphore::new(config.concurrency.clamp(1, MAX_CONCURRENCY)));
    let clean = Arc::new(clean);
    let positions = Arc::new(positions);
    let mut set = JoinSet::new();
    let mut completed: u64 = 0;

    // Results flow through a channel to a single collector that emits coalesced
    // batches, so emission rate is bounded no matter how fast requests complete.
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<AttackResult>();
    let collector = tokio::spawn(batch_results(
        rx,
        Arc::clone(&sink),
        BATCH_FLUSH_EVERY,
        Duration::from_millis(BATCH_FLUSH_INTERVAL_MS),
    ));

    for (index, job) in jobs.into_iter().enumerate() {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let permit = match Arc::clone(&sem).acquire_owned().await {
            Ok(p) => p,
            Err(_) => break,
        };
        if config.delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(config.delay_ms)).await;
        }
        let raw = build(&clean, &positions, &job.repls);
        let spec = parse_request(&raw, config.service.clone());
        let sender = Arc::clone(&sender);
        let tx = tx.clone();
        let display = job.display;
        set.spawn(async move {
            let _permit = permit;
            let result = match sender.send(spec).await {
                Ok(out) => AttackResult {
                    index: index as u64,
                    payloads: display,
                    status: Some(out.response.status),
                    length: out.response.body.wire_len,
                    duration_ms: out.duration_ms,
                    error: None,
                },
                Err(e) => AttackResult {
                    index: index as u64,
                    payloads: display,
                    status: None,
                    length: 0,
                    duration_ms: 0,
                    error: Some(e.to_string()),
                },
            };
            let _ = tx.send(result);
        });
    }

    while set.join_next().await.is_some() {
        completed += 1;
    }
    // Close the channel so the collector flushes its remainder and finishes.
    drop(tx);
    let _ = collector.await;

    let stopped = stop.load(Ordering::Relaxed);
    sink(AttackEvent::Done {
        attack_id,
        completed,
        stopped,
    });
}

/// A preflight preview: the predicted total and the first `limit` generated requests.
#[derive(Debug, Clone, Serialize)]
pub struct PreviewResult {
    pub positions: usize,
    pub total: Option<u64>,
    pub capped_at: u64,
    pub requests: Vec<String>,
}

/// Build the predicted count and the first `limit` fully-generated raw requests
/// (payloads processed and inserted, Content-Length recalculated) without sending.
pub fn preview(config: &IntruderConfig, limit: usize) -> PreviewResult {
    let (clean, positions) = parse_template(&config.template);
    let bases: Vec<String> = positions.iter().map(|(_, b)| b.clone()).collect();
    let set_sizes: Vec<u64> = config.payload_sets.iter().map(|s| s.len() as u64).collect();
    let total = expected_count(config.attack, positions.len(), &set_sizes);
    let (jobs, _) = generate(
        config.attack,
        &bases,
        &config.payload_sets,
        &config.processors,
        limit,
    );
    let requests = jobs
        .iter()
        .map(|j| recalc_content_length(&build(&clean, &positions, &j.repls)))
        .collect();
    PreviewResult {
        positions: positions.len(),
        total,
        capped_at: MAX_REQUESTS as u64,
        requests,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bases(marked: &str) -> (String, Vec<String>) {
        let (clean, pos) = parse_template(marked);
        (clean, pos.iter().map(|(_, b)| b.clone()).collect())
    }

    #[test]
    fn template_markers_and_build() {
        let (clean, positions) = parse_template("GET /u?id=§1§&t=§x§ HTTP/1.1");
        assert_eq!(clean, "GET /u?id=1&t=x HTTP/1.1");
        assert_eq!(positions.len(), 2);
        let built = build(&clean, &positions, &["999".into(), "ABC".into()]);
        assert_eq!(built, "GET /u?id=999&t=ABC HTTP/1.1");
    }

    #[test]
    fn sniper_counts_and_isolates_positions() {
        let (_c, b) = bases("a=§1§&b=§2§");
        let (jobs, capped) = generate(
            AttackType::Sniper,
            &b,
            &[vec!["X".into(), "Y".into()]],
            &[],
            MAX_REQUESTS,
        );
        assert!(!capped);
        assert_eq!(jobs.len(), 4); // 2 positions * 2 payloads
        // first job fuzzes position 0, position 1 keeps its base "2"
        assert_eq!(jobs[0].repls, vec!["X".to_string(), "2".to_string()]);
        assert_eq!(jobs[2].repls, vec!["1".to_string(), "X".to_string()]);
    }

    #[test]
    fn battering_ram_fills_all_positions() {
        let (_c, b) = bases("§1§-§2§");
        let (jobs, _) = generate(
            AttackType::BatteringRam,
            &b,
            &[vec!["Z".into()]],
            &[],
            MAX_REQUESTS,
        );
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].repls, vec!["Z".to_string(), "Z".to_string()]);
    }

    #[test]
    fn pitchfork_zips_sets() {
        let (_c, b) = bases("§1§-§2§");
        let (jobs, _) = generate(
            AttackType::Pitchfork,
            &b,
            &[
                vec!["a".into(), "b".into()],
                vec!["1".into(), "2".into(), "3".into()],
            ],
            &[],
            MAX_REQUESTS,
        );
        assert_eq!(jobs.len(), 2); // min(2,3)
        assert_eq!(jobs[1].repls, vec!["b".to_string(), "2".to_string()]);
    }

    #[test]
    fn cluster_bomb_is_cartesian() {
        let (_c, b) = bases("§1§-§2§");
        let (jobs, _) = generate(
            AttackType::ClusterBomb,
            &b,
            &[vec!["a".into(), "b".into()], vec!["1".into(), "2".into()]],
            &[],
            MAX_REQUESTS,
        );
        assert_eq!(jobs.len(), 4);
        let combos: Vec<_> = jobs.iter().map(|j| j.repls.clone()).collect();
        assert!(combos.contains(&vec!["a".to_string(), "1".to_string()]));
        assert!(combos.contains(&vec!["b".to_string(), "2".to_string()]));
    }

    #[test]
    fn parse_request_splits_head_and_body() {
        let spec = parse_request(
            "POST /x HTTP/1.1\nHost: h\nContent-Type: text/plain\n\nhello=1",
            HttpService {
                host: "h".into(),
                port: 80,
                secure: false,
            },
        );
        assert_eq!(spec.method, "POST");
        assert_eq!(spec.target, "/x");
        assert_eq!(spec.body, "hello=1");
        assert_eq!(spec.headers.len(), 2);
    }

    #[test]
    fn expected_counts_are_checked() {
        assert_eq!(expected_count(AttackType::Sniper, 2, &[100]), Some(200));
        assert_eq!(expected_count(AttackType::BatteringRam, 3, &[50]), Some(50));
        assert_eq!(expected_count(AttackType::Pitchfork, 2, &[5, 8]), Some(5));
        assert_eq!(
            expected_count(AttackType::ClusterBomb, 2, &[100, 100]),
            Some(10_000)
        );
        // overflow is reported, not panicked
        assert_eq!(
            expected_count(AttackType::ClusterBomb, 3, &[u64::MAX, 2, 2]),
            None
        );
    }

    #[test]
    fn adjacent_positions() {
        let (clean, positions) = parse_template("\u{00a7}a\u{00a7}\u{00a7}b\u{00a7}");
        assert_eq!(clean, "ab");
        assert_eq!(positions.len(), 2);
        assert_eq!(build(&clean, &positions, &["X".into(), "Y".into()]), "XY");
    }

    #[test]
    fn empty_insertion_position() {
        // a zero-width position between characters
        let (clean, positions) = parse_template("a\u{00a7}\u{00a7}b");
        assert_eq!(clean, "ab");
        assert_eq!(positions.len(), 1);
        assert_eq!(positions[0].1, "", "base value is empty");
        assert_eq!(build(&clean, &positions, &["INJ".into()]), "aINJb");
    }

    #[test]
    fn unicode_multibyte_offsets() {
        let (clean, positions) =
            parse_template("n=\u{00a7}caf\u{00e9}\u{00a7}&x=\u{00a7}2\u{00a7}");
        assert_eq!(clean, "n=caf\u{00e9}&x=2");
        assert_eq!(positions.len(), 2);
        // replace the accented base and keep the second
        let built = build(&clean, &positions, &["na\u{00ef}ve".into(), "2".into()]);
        assert_eq!(built, "n=na\u{00ef}ve&x=2");
    }

    #[test]
    fn repeated_value_at_different_positions_are_independent() {
        // same base "1" at two spots; sniper fuzzes them separately
        let (_c, b) = bases("a=\u{00a7}1\u{00a7}&b=\u{00a7}1\u{00a7}");
        let (jobs, _) = generate(
            AttackType::Sniper,
            &b,
            &[vec!["X".into()]],
            &[],
            MAX_REQUESTS,
        );
        assert_eq!(jobs.len(), 2);
        assert_eq!(jobs[0].repls, vec!["X".to_string(), "1".to_string()]);
        assert_eq!(jobs[1].repls, vec!["1".to_string(), "X".to_string()]);
    }

    #[test]
    fn golden_fixture_only_marked_regions_change() {
        let tpl = "POST /s HTTP/1.1\nHost: h\nContent-Type: application/x-www-form-urlencoded\n\nq=\u{00a7}widget\u{00a7}&c=\u{00a7}tools\u{00a7}";
        let (clean, positions) = parse_template(tpl);
        let built = build(&clean, &positions, &["shovel".into(), "garden".into()]);
        assert_eq!(
            built,
            "POST /s HTTP/1.1\nHost: h\nContent-Type: application/x-www-form-urlencoded\n\nq=shovel&c=garden"
        );
    }

    #[test]
    fn content_length_is_recalculated() {
        let raw = "POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\nhello=world";
        let out = recalc_content_length(raw);
        assert!(out.contains("Content-Length: 11"), "got: {out}");
        assert!(out.ends_with("\n\nhello=world"));
    }

    #[tokio::test]
    async fn collector_batches_without_losing_results() {
        use std::sync::Mutex;
        use std::sync::atomic::AtomicUsize;

        let received = Arc::new(Mutex::new(Vec::<AttackResult>::new()));
        let calls = Arc::new(AtomicUsize::new(0));
        let r2 = Arc::clone(&received);
        let c2 = Arc::clone(&calls);
        let sink: Arc<dyn Fn(AttackEvent) + Send + Sync> = Arc::new(move |ev| {
            if let AttackEvent::Results(batch) = ev {
                c2.fetch_add(1, Ordering::Relaxed);
                r2.lock().unwrap().extend(batch);
            } else {
                panic!("collector must only emit Results batches");
            }
        });

        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let handle = tokio::spawn(batch_results(
            rx,
            sink,
            BATCH_FLUSH_EVERY,
            Duration::from_millis(BATCH_FLUSH_INTERVAL_MS),
        ));

        let total = 1000usize;
        for i in 0..total {
            tx.send(AttackResult {
                index: i as u64,
                payloads: vec![],
                status: Some(200),
                length: 0,
                duration_ms: 0,
                error: None,
            })
            .unwrap();
        }
        drop(tx);
        handle.await.unwrap();

        // Every result is delivered exactly once...
        assert_eq!(received.lock().unwrap().len(), total);
        // ...but coalesced into far fewer events than results (vs. 1000 individually).
        let n_calls = calls.load(Ordering::Relaxed);
        assert!(
            n_calls <= total / BATCH_FLUSH_EVERY + 2,
            "expected coalesced batches, got {n_calls} events for {total} results"
        );
    }

    #[test]
    fn preview_reports_count_and_first_requests() {
        let config = IntruderConfig {
            service: crate::core::HttpService {
                host: "h".into(),
                port: 80,
                secure: false,
            },
            template: "GET /q?v=\u{00a7}1\u{00a7} HTTP/1.1\nHost: h\n\n".into(),
            attack: AttackType::Sniper,
            payload_sets: vec![vec!["a".into(), "b".into(), "c".into()]],
            concurrency: 1,
            delay_ms: 0,
            processors: vec![],
        };
        let pv = preview(&config, 2);
        assert_eq!(pv.positions, 1);
        assert_eq!(pv.total, Some(3));
        assert_eq!(pv.requests.len(), 2, "only first 2 generated for preview");
        assert!(pv.requests[0].contains("v=a"));
        assert!(pv.requests[1].contains("v=b"));
    }

    #[test]
    fn preview_applies_processing_pipeline() {
        let config = IntruderConfig {
            service: crate::core::HttpService {
                host: "h".into(),
                port: 80,
                secure: false,
            },
            template: "GET /q?v=\u{00a7}x\u{00a7} HTTP/1.1\nHost: h\n\n".into(),
            attack: AttackType::Sniper,
            payload_sets: vec![vec!["a b".into()]],
            concurrency: 1,
            delay_ms: 0,
            processors: vec![payload::Processor::UrlEncode],
        };
        let pv = preview(&config, 1);
        assert!(
            pv.requests[0].contains("v=a%20b"),
            "processed payload inserted: {}",
            pv.requests[0]
        );
    }
}
