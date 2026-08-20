//! SmartFuzz — Intelligent adaptive web content discovery
//! For authorized security testing only.
//!
//! 100% free & open source — no paid APIs, no cloud dependencies.

pub mod api;
pub mod cli;
pub mod events;
pub mod filter;
pub mod fingerprint;
pub mod http;
pub mod js;
pub mod output;
pub mod plugin;
pub mod rate;
pub mod recursive;
pub mod report;
pub mod response;
pub mod spider;
pub mod vhost;
pub mod wordlist;

pub use cli::{Args, ScanMode};
pub use recursive::ScanEngine;
