//! Remote desktop subsystem.
//!
//! ## Platform matrix (production targets)
//!
//! | OS | Capture | Input |
//! |----|---------|-------|
//! | Linux X11 | `xcap` / XShm | `enigo` / XTest |
//! | Linux Wayland | PipeWire + xdg-desktop-portal | `uinput` / portal |
//! | macOS | ScreenCaptureKit / `xcap` | CGEvent |
//! | Windows | DXGI Desktop Duplication | `enigo` |
//!
//! Encoding path: raw frames → VP8/VP9/AV1 (`vpx` / `rav1e`) or hardware encoders.
//!
//! This crate ships a **null backend** plus the message-level controller so the
//! rest of MyMesh builds everywhere; enable `capture` feature on real hosts.

mod controller;
mod null;

pub use controller::DesktopController;
pub use null::NullCapture;
