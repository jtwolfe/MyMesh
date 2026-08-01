use crate::NullCapture;
use mymesh_core::Result;
use mymesh_protocol::{DesktopInput, DesktopMessage};
use tracing::debug;

#[derive(Default)]
pub struct DesktopController {
    capture: NullCapture,
    running: bool,
}


impl DesktopController {
    pub fn handle(&mut self, msg: DesktopMessage) -> Result<Vec<DesktopMessage>> {
        match msg {
            DesktopMessage::Start {
                fps,
                quality,
                monitor,
            } => {
                self.capture.start(fps, quality, monitor)?;
                self.running = true;
                // Push one sample frame immediately.
                Ok(vec![self.capture.next_frame()?])
            }
            DesktopMessage::Stop => {
                self.capture.stop();
                self.running = false;
                Ok(vec![])
            }
            DesktopMessage::Input(input) => {
                self.inject(input)?;
                Ok(vec![])
            }
            DesktopMessage::Clipboard { mime, data } => {
                debug!(%mime, len = data.len(), "clipboard set (stub)");
                Ok(vec![])
            }
            other => Ok(vec![DesktopMessage::Error {
                message: format!("unsupported: {other:?}"),
            }]),
        }
    }

    pub fn tick(&mut self) -> Result<Option<DesktopMessage>> {
        if self.running {
            Ok(Some(self.capture.next_frame()?))
        } else {
            Ok(None)
        }
    }

    fn inject(&self, input: DesktopInput) -> Result<()> {
        debug!(
            ?input,
            "input inject (stub — wire enigo/uinput in capture feature)"
        );
        Ok(())
    }
}
