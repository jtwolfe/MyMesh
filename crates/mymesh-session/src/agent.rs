//! Background agent: accept sessions and host terminal/files channels.
use mymesh_core::{Capability, Config, DeviceStore, Result};
use mymesh_crypto::Identity;
use mymesh_files::{apply_host_message, FileTransferEngine, PathSandbox};
use mymesh_net::Transport;
use mymesh_protocol::{
    decode_msg, encode_msg, ChannelId, ChannelKind, FileMessage, Frame, TerminalMessage,
};
use mymesh_terminal::TerminalHost;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::session::Session;

#[derive(Clone)]
pub struct Agent {
    secret: [u8; 32],
    label: String,
    devices_path: PathBuf,
    config: Config,
    files: Arc<FileTransferEngine>,
    put_paths: Arc<Mutex<HashMap<String, String>>>,
}

impl Agent {
    pub fn new(
        identity: &Identity,
        label: String,
        devices_path: PathBuf,
        config: Config,
    ) -> Result<Self> {
        let sandbox = PathSandbox::new(config.effective_sandbox_root())?;
        Ok(Self {
            secret: identity.to_secret_bytes(),
            label,
            devices_path,
            config,
            files: Arc::new(FileTransferEngine::new(sandbox)),
            put_paths: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    fn identity(&self) -> Identity {
        Identity::from_secret_bytes(self.secret)
    }

    fn store(&self) -> Result<DeviceStore> {
        DeviceStore::open(&self.devices_path)
    }

    pub async fn run<T: Transport + ?Sized>(&self, transport: &T) -> Result<()> {
        let id = self.identity();
        info!(
            id = %id.device_id().short(),
            label = %self.label,
            sandbox = %self.config.effective_sandbox_root().display(),
            "agent accepting sessions"
        );
        loop {
            let conn = transport.accept().await?;
            let peer = conn.peer_id();
            let store = self.store()?;
            if !store.is_trusted(&peer) {
                warn!(peer = %peer.short(), "rejecting untrusted peer");
                let _ = conn.close().await;
                continue;
            }
            let agent = self.clone();
            tokio::spawn(async move {
                if let Err(e) = agent.handle_connection(conn).await {
                    warn!(peer = %peer.short(), %e, "session ended with error");
                }
            });
        }
    }

    async fn handle_connection(
        &self,
        conn: Box<dyn mymesh_net::PeerConnection>,
    ) -> Result<()> {
        let identity = self.identity();
        let store = self.store()?;
        let mut offered = Vec::new();
        if self.config.daemon.enable_terminal {
            offered.push(Capability::Terminal);
        }
        if self.config.daemon.enable_files {
            offered.push(Capability::Files);
        }
        if self.config.daemon.enable_desktop {
            offered.push(Capability::Desktop);
        }

        let session =
            Session::handshake_acceptor(conn, &identity, &self.label, &store, offered).await?;
        let peer = session.peer_id();
        info!(peer = %peer.short(), "session established");

        let mut term: Option<TerminalHost> = None;
        let mut term_out: Option<tokio::sync::mpsc::Receiver<TerminalMessage>> = None;
        let mut active_put: Option<String> = None;
        let conn = session.into_conn();

        loop {
            tokio::select! {
                frame = conn.recv_frame() => {
                    let frame = frame?;
                    match frame.channel.kind {
                        ChannelKind::Terminal => {
                            if !store.allows(&peer, &Capability::Terminal) {
                                warn!("terminal denied for peer");
                                continue;
                            }
                            let msg: TerminalMessage = decode_msg(&frame.payload)?;
                            match msg {
                                TerminalMessage::Open { cols, rows, shell, .. } => {
                                    let (host, rx) = TerminalHost::spawn(
                                        cols,
                                        rows,
                                        shell.as_deref(),
                                    )?;
                                    term = Some(host);
                                    term_out = Some(rx);
                                }
                                other => {
                                    if let Some(h) = term.as_mut() {
                                        h.handle(other)?;
                                    }
                                }
                            }
                        }
                        ChannelKind::Files => {
                            if !store.allows(&peer, &Capability::Files) {
                                warn!("files denied for peer");
                                continue;
                            }
                            let msg: FileMessage = decode_msg(&frame.payload)?;
                            match msg {
                                FileMessage::Put { path, .. } => {
                                    active_put = Some(path.clone());
                                    let replies = apply_host_message(&self.files, FileMessage::Put {
                                        path: path.clone(),
                                        size: 0,
                                        mode: 0o644,
                                        resume_from: 0,
                                    })?;
                                    for r in replies {
                                        conn.send_frame(Frame {
                                            channel: ChannelId::files(1),
                                            payload: encode_msg(&r)?,
                                        }).await?;
                                    }
                                }
                                FileMessage::Chunk { offset, data } => {
                                    if let Some(path) = active_put.as_deref() {
                                        self.files.write_chunk(path, offset, &data)?;
                                    }
                                }
                                FileMessage::Done { path, bytes } => {
                                    conn.send_frame(Frame {
                                        channel: ChannelId::files(1),
                                        payload: encode_msg(&FileMessage::Done { path, bytes })?,
                                    }).await?;
                                    active_put = None;
                                }
                                other => {
                                    let replies = apply_host_message(&self.files, other)?;
                                    for r in replies {
                                        conn.send_frame(Frame {
                                            channel: ChannelId::files(1),
                                            payload: encode_msg(&r)?,
                                        }).await?;
                                    }
                                }
                            }
                        }
                        ChannelKind::Control => {
                            let msg: mymesh_protocol::ControlMessage = decode_msg(&frame.payload)?;
                            if matches!(msg, mymesh_protocol::ControlMessage::Ping { .. }) {
                                // ignore/pong optional
                            }
                        }
                        ChannelKind::Desktop => {
                            warn!("desktop not enabled in M1–M3");
                        }
                    }
                }
                maybe_out = async {
                    match term_out.as_mut() {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    match maybe_out {
                        Some(TerminalMessage::Output(data)) => {
                            conn.send_frame(Frame {
                                channel: ChannelId::terminal(1),
                                payload: encode_msg(&TerminalMessage::Output(data))?,
                            }).await?;
                        }
                        Some(TerminalMessage::Exit { code }) => {
                            conn.send_frame(Frame {
                                channel: ChannelId::terminal(1),
                                payload: encode_msg(&TerminalMessage::Exit { code })?,
                            }).await?;
                            if let Some(h) = term.take() {
                                h.kill();
                            }
                            term_out = None;
                        }
                        Some(_) => {}
                        None => {
                            term_out = None;
                        }
                    }
                }
            }
        }
    }
}
