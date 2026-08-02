//! Background agent: join requests + authenticated sessions + mesh gossip/kick.
use mymesh_core::{ArmState, Capability, Config, DeviceStore, MeshState, Result};
use mymesh_crypto::Identity;
use mymesh_files::{apply_host_message, FileTransferEngine, PathSandbox};
use mymesh_net::Transport;
use mymesh_protocol::{
    decode_msg, encode_msg, ChannelId, ChannelKind, ControlMessage, FileMessage, Frame,
    TerminalMessage,
};
use mymesh_terminal::TerminalHost;
use std::path::PathBuf;
use tracing::{info, warn};

use crate::join::handle_join_as_host;
use crate::mesh_sync::{
    apply_kick_notice_local, apply_kick_target, apply_membership, build_snapshot, verify_kick,
    verify_membership,
};
use crate::session::Session;

#[derive(Clone)]
pub struct Agent {
    secret: [u8; 32],
    label: String,
    devices_path: PathBuf,
    arm_path: PathBuf,
    join_dir: PathBuf,
    mesh_path: PathBuf,
    kick_notice_path: PathBuf,
    config: Config,
    files: std::sync::Arc<FileTransferEngine>,
}

impl Agent {
    pub fn new(
        identity: &Identity,
        label: String,
        devices_path: PathBuf,
        arm_path: PathBuf,
        join_dir: PathBuf,
        mesh_path: PathBuf,
        kick_notice_path: PathBuf,
        config: Config,
    ) -> Result<Self> {
        let sandbox = PathSandbox::new(config.effective_sandbox_root())?;
        Ok(Self {
            secret: identity.to_secret_bytes(),
            label,
            devices_path,
            arm_path,
            join_dir,
            mesh_path,
            kick_notice_path,
            config,
            files: std::sync::Arc::new(FileTransferEngine::new(sandbox)),
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
            let agent = self.clone();
            if store.is_trusted(&peer) {
                tokio::spawn(async move {
                    if let Err(e) = agent.handle_session(conn).await {
                        warn!(peer = %peer.short(), %e, "session ended with error");
                    }
                });
            } else {
                let arm = ArmState::load(&self.arm_path)?;
                if arm.is_effectively_armed() {
                    tokio::spawn(async move {
                        if let Err(e) = agent.handle_join(conn).await {
                            warn!(peer = %peer.short(), %e, "join handling failed");
                        }
                    });
                } else {
                    warn!(
                        peer = %peer.short(),
                        "rejecting untrusted peer (not armed for joins)"
                    );
                    let _ = conn.close().await;
                }
            }
        }
    }

    async fn handle_join(
        &self,
        conn: Box<dyn mymesh_net::PeerConnection>,
    ) -> Result<()> {
        let identity = self.identity();
        handle_join_as_host(
            conn,
            &identity,
            &self.label,
            &self.devices_path,
            &self.arm_path,
            &self.join_dir,
            &self.mesh_path,
            self.config.limits.arm_timeout_secs,
        )
        .await
    }

    async fn handle_session(
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

        // best-effort initial gossip
        if let Ok(mesh) = MeshState::load(&self.mesh_path) {
            if let Ok(store) = self.store() {
                let snap = build_snapshot(&identity, &self.label, &store, &mesh, 0);
                let _ = conn
                    .send_frame(Frame {
                        channel: ChannelId::control(),
                        payload: encode_msg(&snap)?,
                    })
                    .await;
            }
        }

        loop {
            tokio::select! {
                frame = conn.recv_frame() => {
                    let frame = frame?;
                    match frame.channel.kind {
                        ChannelKind::Terminal => {
                            let store = self.store()?;
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
                            let store = self.store()?;
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
                            let msg: ControlMessage = decode_msg(&frame.payload)?;
                            match msg {
                                ControlMessage::Ping { nonce } => {
                                    conn.send_frame(Frame {
                                        channel: ChannelId::control(),
                                        payload: encode_msg(&ControlMessage::Pong { nonce })?,
                                    }).await?;
                                }
                                ControlMessage::HostMetricsRequest { nonce } => {
                                    let report = crate::host_metrics::sample_metrics(nonce).await;
                                    conn.send_frame(Frame {
                                        channel: ChannelId::control(),
                                        payload: encode_msg(&report)?,
                                    }).await?;
                                }
                                ControlMessage::MembershipRequest { nonce } => {
                                    let mesh = MeshState::load(&self.mesh_path)?;
                                    let store = self.store()?;
                                    let snap = build_snapshot(&identity, &self.label, &store, &mesh, nonce);
                                    conn.send_frame(Frame {
                                        channel: ChannelId::control(),
                                        payload: encode_msg(&snap)?,
                                    }).await?;
                                }
                                ControlMessage::MembershipSnapshot {
                                    mesh_id,
                                    from_id,
                                    members,
                                    ts,
                                    signature,
                                    ..
                                }
                                | ControlMessage::MembershipAnnounce {
                                    mesh_id,
                                    from_id,
                                    members,
                                    ts,
                                    signature,
                                    ..
                                } => {
                                    let store = self.store()?;
                                    if !store.is_trusted(&from_id) && from_id != peer {
                                        warn!(from = %from_id.short(), "ignore membership from untrusted");
                                        continue;
                                    }
                                    // peer is trusted; from_id should match peer for safety
                                    if from_id != peer {
                                        warn!("membership from_id != session peer");
                                        continue;
                                    }
                                    if let Err(e) = verify_membership(&from_id, &mesh_id, ts, &members, &signature) {
                                        warn!(%e, "bad membership signature");
                                        continue;
                                    }
                                    let mut store = self.store()?;
                                    let n = apply_membership(
                                        &mut store,
                                        &self.mesh_path,
                                        &from_id,
                                        &mesh_id,
                                        &members,
                                        identity.device_id(),
                                    )?;
                                    if n > 0 {
                                        info!(added = n, "mesh membership updated via gossip");
                                    }
                                }
                                ControlMessage::KickAnnounce {
                                    mesh_id,
                                    target_id,
                                    by_id,
                                    by_label,
                                    message,
                                    ts,
                                    signature,
                                } => {
                                    let store = self.store()?;
                                    if !store.is_trusted(&by_id) || by_id != peer {
                                        warn!("ignore kick announce from untrusted");
                                        continue;
                                    }
                                    if let Err(e) = verify_kick(&mesh_id, &target_id, &by_id, ts, &signature) {
                                        warn!(%e, "bad kick signature");
                                        continue;
                                    }
                                    if target_id == identity.device_id() {
                                        // we are the target
                                        let mut store = self.store()?;
                                        apply_kick_notice_local(
                                            &mut store,
                                            &self.mesh_path,
                                            &self.kick_notice_path,
                                            by_id,
                                            &by_label,
                                            &message,
                                        )?;
                                        info!("this node was kicked from the mesh by {by_label}");
                                        conn.send_frame(Frame {
                                            channel: ChannelId::control(),
                                            payload: encode_msg(&ControlMessage::KickAck { accepted: true })?,
                                        }).await?;
                                        let _ = conn.close().await;
                                        return Ok(());
                                    } else {
                                        let mut store = self.store()?;
                                        apply_kick_target(&mut store, &target_id)?;
                                        info!(target = %target_id.short(), by = %by_label, "applied kick announce");
                                    }
                                }
                                ControlMessage::KickNotice {
                                    mesh_id,
                                    by_id,
                                    by_label,
                                    message,
                                    ts,
                                    signature,
                                } => {
                                    // Direct notice: verify by_id was trusted
                                    let store = self.store()?;
                                    if !store.is_trusted(&by_id) {
                                        warn!("kick notice from untrusted — ignoring");
                                        continue;
                                    }
                                    if let Err(e) = verify_kick(
                                        &mesh_id,
                                        &identity.device_id(),
                                        &by_id,
                                        ts,
                                        &signature,
                                    ) {
                                        warn!(%e, "bad kick notice signature");
                                        continue;
                                    }
                                    let mut store = self.store()?;
                                    apply_kick_notice_local(
                                        &mut store,
                                        &self.mesh_path,
                                        &self.kick_notice_path,
                                        by_id,
                                        &by_label,
                                        &message,
                                    )?;
                                    println!(
                                        "you were kicked from the mesh by {by_label} host"
                                    );
                                    conn.send_frame(Frame {
                                        channel: ChannelId::control(),
                                        payload: encode_msg(&ControlMessage::KickAck { accepted: true })?,
                                    }).await?;
                                    let _ = conn.close().await;
                                    return Ok(());
                                }
                                ControlMessage::MetricsPollEnable { .. }
                                | ControlMessage::MetricsPollDisable
                                | ControlMessage::KickAck { .. } => {}
                                _ => {}
                            }
                        }
                        ChannelKind::Desktop => {
                            warn!("desktop not enabled yet");
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
