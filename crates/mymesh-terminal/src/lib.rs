//! Remote terminal over MyMesh channels.
//!
//! Host side spawns a PTY via `portable-pty` (wezterm lineage).
//! Client side is a thin stdin/stdout bridge with resize support.

mod client;
mod host;

pub use client::TerminalClient;
pub use host::TerminalHost;
