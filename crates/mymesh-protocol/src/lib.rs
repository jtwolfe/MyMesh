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
pub use frame::{
    decode_json_msg, decode_msg, encode_json_msg, encode_msg, read_frame, read_json_msg,
    write_frame, write_json_msg, Frame, MAX_FRAME_BYTES, MAX_JSON_MSG_BYTES,
};
pub use messages::*;
