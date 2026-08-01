use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use mymesh_core::Result;
use mymesh_protocol::TerminalMessage;
use std::io::{self, Read, Write};

/// Local interactive side of a remote terminal.
pub struct TerminalClient {
    raw: bool,
}

impl TerminalClient {
    pub fn attach() -> Result<Self> {
        enable_raw_mode().map_err(|e| mymesh_core::Error::Session(e.to_string()))?;
        Ok(Self { raw: true })
    }

    pub fn handle_host_msg(&self, msg: TerminalMessage) -> Result<bool> {
        match msg {
            TerminalMessage::Output(data) => {
                let mut out = io::stdout();
                out.write_all(&data)?;
                out.flush()?;
                Ok(true)
            }
            TerminalMessage::Exit { code } => {
                eprintln!("\r\n[mymesh] remote shell exited ({code})\r");
                Ok(false)
            }
            _ => Ok(true),
        }
    }

    pub fn read_input(&self, buf: &mut [u8]) -> Result<usize> {
        let n = io::stdin().read(buf).map_err(mymesh_core::Error::Io)?;
        Ok(n)
    }
}

impl Drop for TerminalClient {
    fn drop(&mut self) {
        if self.raw {
            let _ = disable_raw_mode();
        }
    }
}
