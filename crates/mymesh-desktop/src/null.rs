use mymesh_core::Result;
use mymesh_protocol::{DesktopCodec, DesktopMessage};

/// Placeholder capture used until platform backends are linked.
pub struct NullCapture {
    width: u32,
    height: u32,
    frame: u64,
}

impl Default for NullCapture {
    fn default() -> Self {
        Self {
            width: 1280,
            height: 720,
            frame: 0,
        }
    }
}

impl NullCapture {
    pub fn start(&mut self, _fps: u8, _quality: u8, _monitor: Option<u32>) -> Result<()> {
        Ok(())
    }

    pub fn stop(&mut self) {}

    /// Emits a tiny solid-color RGBA frame so clients can exercise the pipeline.
    pub fn next_frame(&mut self) -> Result<DesktopMessage> {
        self.frame += 1;
        let px = ((self.frame as u8).wrapping_mul(3), 40, 80, 255);
        let mut data = Vec::with_capacity((self.width * self.height * 4) as usize);
        for _ in 0..(self.width * self.height) {
            data.extend_from_slice(&[px.0, px.1, px.2, px.3]);
        }
        Ok(DesktopMessage::Frame {
            width: self.width,
            height: self.height,
            codec: DesktopCodec::Rgba,
            data,
            pts_ms: self.frame * 33,
        })
    }
}
