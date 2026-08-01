use async_trait::async_trait;
use mymesh_core::{DeviceId, Result};
use mymesh_protocol::Frame;

#[async_trait]
pub trait PeerConnection: Send + Sync {
    fn peer_id(&self) -> DeviceId;
    async fn send_frame(&self, frame: Frame) -> Result<()>;
    async fn recv_frame(&self) -> Result<Frame>;
    async fn close(&self) -> Result<()>;
}

#[async_trait]
pub trait Transport: Send + Sync {
    fn local_id(&self) -> DeviceId;
    async fn connect(&self, peer: DeviceId) -> Result<Box<dyn PeerConnection>>;
    async fn accept(&self) -> Result<Box<dyn PeerConnection>>;
}
