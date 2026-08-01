use mymesh_core::{Error, Result};
use mymesh_protocol::TerminalMessage;
use portable_pty::{native_pty_system, CommandBuilder, MasterPty, PtySize};
use std::io::{Read, Write};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error};

pub struct TerminalHost {
    master: Box<dyn MasterPty + Send>,
    writer: Box<dyn Write + Send>,
    child_killer: Arc<parking_lot_stub::ChildHolder>,
}

// Avoid extra parking_lot dep here — use std mutex
mod parking_lot_stub {
    use portable_pty::Child;
    use std::sync::Mutex;

    pub struct ChildHolder {
        child: Mutex<Option<Box<dyn Child + Send + Sync>>>,
    }

    impl ChildHolder {
        pub fn new(child: Box<dyn Child + Send + Sync>) -> Self {
            Self {
                child: Mutex::new(Some(child)),
            }
        }

        pub fn kill(&self) {
            if let Ok(mut g) = self.child.lock() {
                if let Some(mut c) = g.take() {
                    let _ = c.kill();
                }
            }
        }
    }
}

impl TerminalHost {
    pub fn spawn(
        cols: u16,
        rows: u16,
        shell: Option<&str>,
    ) -> Result<(Self, mpsc::Receiver<TerminalMessage>)> {
        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| Error::Session(format!("pty open: {e}")))?;

        let shell = shell
            .map(|s| s.to_string())
            .or_else(|| std::env::var("SHELL").ok())
            .unwrap_or_else(|| "/bin/bash".into());

        let mut cmd = CommandBuilder::new(&shell);
        cmd.env("TERM", "xterm-256color");
        cmd.env("COLORTERM", "truecolor");
        let child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| Error::Session(format!("spawn shell: {e}")))?;

        let mut reader = pair
            .master
            .try_clone_reader()
            .map_err(|e| Error::Session(format!("pty reader: {e}")))?;
        let writer = pair
            .master
            .take_writer()
            .map_err(|e| Error::Session(format!("pty writer: {e}")))?;

        let (tx, rx) = mpsc::channel(64);
        let killer = Arc::new(parking_lot_stub::ChildHolder::new(child));
        let killer_bg = killer.clone();

        std::thread::Builder::new()
            .name("mymesh-pty-reader".into())
            .spawn(move || {
                let mut buf = [0u8; 8192];
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) => {
                            let _ = tx.blocking_send(TerminalMessage::Exit { code: 0 });
                            break;
                        }
                        Ok(n) => {
                            if tx
                                .blocking_send(TerminalMessage::Output(buf[..n].to_vec()))
                                .is_err()
                            {
                                break;
                            }
                        }
                        Err(e) => {
                            error!(%e, "pty read error");
                            let _ = tx.blocking_send(TerminalMessage::Exit { code: 1 });
                            break;
                        }
                    }
                }
                killer_bg.kill();
            })
            .map_err(|e| Error::Io(e))?;

        Ok((
            Self {
                master: pair.master,
                writer,
                child_killer: killer,
            },
            rx,
        ))
    }

    pub fn handle(&mut self, msg: TerminalMessage) -> Result<()> {
        match msg {
            TerminalMessage::Input(data) => {
                self.writer
                    .write_all(&data)
                    .map_err(|e| Error::Session(format!("pty write: {e}")))?;
                self.writer.flush().ok();
            }
            TerminalMessage::Resize { cols, rows } => {
                self.master
                    .resize(PtySize {
                        rows,
                        cols,
                        pixel_width: 0,
                        pixel_height: 0,
                    })
                    .map_err(|e| Error::Session(format!("pty resize: {e}")))?;
                debug!(cols, rows, "pty resized");
            }
            TerminalMessage::Open { .. } => {}
            TerminalMessage::Output(_) | TerminalMessage::Exit { .. } => {}
        }
        Ok(())
    }

    pub fn kill(&self) {
        self.child_killer.kill();
    }
}
