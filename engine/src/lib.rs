//! shrike: an original, clean-room web security testing suite.
//!
//! Milestone 1 ships the foundation every later module plugs into:
//! a persistent local root CA, per-host leaf certificate minting, and an
//! intercepting HTTPS proxy that decrypts, records and forwards traffic.

pub mod bapp;
pub mod browser;
pub mod ca;
pub mod config;
pub mod core;
pub mod crawler;
pub mod diagnostics;
pub mod engine;
pub mod extras;
pub mod findings;
pub mod import;
pub mod intercept;
pub mod intruder;
pub mod jvm;
pub mod match_replace;
pub mod oob;
pub mod plugins;
pub mod proxy;
pub mod query;
pub mod scanner;
pub mod scope;
pub mod sender;
pub mod store;
pub mod tools;
pub use engine::Engine;
