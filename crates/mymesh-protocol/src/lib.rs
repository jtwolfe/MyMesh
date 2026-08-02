//! Application protocol spoken on top of a P2P transport.
//!
//! Design:
//! - One QUIC connection per peer pair
//! - Multiplexed logical channels (control / terminal / files / desktop / tcp)
//! - Length-prefixed bincode frames (max 16 MiB per frame)

mod channel;
mod frame;
mod messages;
mod ser_fixed;

pub use channel::{ChannelId, ChannelKind};
pub use frame::{decode_msg, encode_msg, read_frame, write_frame, Frame, MAX_FRAME_BYTES};
pub use messages::*;
