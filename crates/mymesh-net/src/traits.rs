use async_trait::async_trait;
use mymesh_core::{DeviceId, Result};
use mymesh_protocol::Frame;

#[async_trait]
pub trait PeerConnection: Send + Sync {
    fn peer_id(&self) -> DeviceId;
    async fn send_frame(&self, frame: Frame) -> Result<()>;
    async fn recv_frame(&self) -> Result<Frame>;
    async fn close(&self) -> Result<()>;

    /// Send raw bytes directly on the stream (no frame header).
    /// Used by the enrollment protocol for length-prefixed JSON framing.
    async fn send_raw(&self, data: &[u8]) -> Result<()>;

    /// Receive raw bytes directly from the stream (no frame header).
    /// Used by the enrollment protocol for length-prefixed JSON framing.
    /// Reads a 4-byte big-endian length prefix, then that many bytes of payload.
    async fn recv_raw(&self) -> Result<Vec<u8>>;
}

#[async_trait]
pub trait Transport: Send + Sync {
    fn local_id(&self) -> DeviceId;
    async fn connect(&self, peer: DeviceId) -> Result<Box<dyn PeerConnection>>;
    async fn accept(&self) -> Result<Box<dyn PeerConnection>>;
}
