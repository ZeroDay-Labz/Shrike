//! Allocator for transaction (history row) ids.
//!
//! Every producer that records traffic — the proxy, the crawler and imports —
//! draws ids from one shared allocator owned by the [`Store`](crate::store::Store),
//! seeded past every id the project already uses. A proxy or crawl restart
//! therefore continues the sequence instead of starting over at 1, which used to
//! overwrite older history.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

/// Hands out unique, increasing transaction ids. Cheap to clone; clones share
/// one counter.
#[derive(Clone, Debug)]
pub struct TransactionIds(Arc<AtomicU64>);

impl TransactionIds {
    /// An allocator whose first id is `last + 1` (so `starting_after(0)` yields
    /// 1, 2, 3, …; id 0 is never handed out — it marks unrecorded sends).
    pub fn starting_after(last: u64) -> Self {
        Self(Arc::new(AtomicU64::new(last + 1)))
    }

    /// The next unused id. Unique across every clone and thread.
    pub fn next(&self) -> u64 {
        self.0.fetch_add(1, Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clones_share_one_sequence_across_threads() {
        let ids = TransactionIds::starting_after(41);
        assert_eq!(ids.next(), 42);
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let ids = ids.clone();
                std::thread::spawn(move || (0..1000).map(|_| ids.next()).collect::<Vec<_>>())
            })
            .collect();
        let mut all: Vec<u64> = handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), 8000, "every id is unique");
        assert!(all[0] > 42);
    }
}
