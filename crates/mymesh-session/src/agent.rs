//! Background agent: join, sessions, mesh gossip, pending kicks, periodic sync.
use mymesh_core::{
    allows, AdminNonceStore, ArmState, Capability, Config, DeviceStore, EnrollmentStore,
    GrantStore, MeshState, Paths, PendingKick, PendingKickStore, Result,
};
use mymesh_crypto::Identity;
use mymesh_files::{apply_host_message, FileTransferEngine, PathSandbox};
use mymesh_net::Transport;
use mymesh_protocol::{
    decode_msg, encode_msg, ChannelId, ChannelKind, ControlMessage, FileMessage, Frame,
    TerminalMessage,
};
use mymesh_terminal::TerminalHost;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tracing::{info, warn};

use crate::join::handle_join_as_host_with_grants;
use crate::mesh_sync::{
    apply_grant_revoke, apply_kick_notice_local, apply_kick_target, apply_membership,
    build_announce, build_snapshot, sign_leave_ack, verify_grant_announce, verify_grant_revoke,
    verify_kick, verify_leave_ack, verify_membership,
};
use crate::session::Session;
use crate::tcp_tunnel;

const MESH_VALIDATE_SECS: u64 = 60;
const DIRTY_POLL_SECS: u64 = 2;

#[derive(Clone)]
pub struct Agent {
    secret: [u8; 32],
    label: String,
    devices_path: PathBuf,
    grants_path: PathBuf,
    arm_path: PathBuf,
    join_dir: PathBuf,
    mesh_path: PathBuf,
    kick_notice_path: PathBuf,
    pending_kicks_path: PathBuf,
    mesh_dirty_path: PathBuf,
    pair_sessions_dir: PathBuf,
    config: Config,
    files: std::sync::Arc<FileTransferEngine>,
}

impl Agent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identity: &Identity,
        label: String,
        devices_path: PathBuf,
        arm_path: PathBuf,
        join_dir: PathBuf,
        mesh_path: PathBuf,
        kick_notice_path: PathBuf,
        pending_kicks_path: PathBuf,
        mesh_dirty_path: PathBuf,
        config: Config,
    ) -> Result<Self> {
        // Derive pair-sessions / grants from join_dir parent (data_dir/join → data_dir/…).
        let data_dir = join_dir
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        let pair_sessions_dir = data_dir.join("pair-sessions");
        let grants_path = data_dir.join("grants.json");
        Self::new_with_pair_dir(
            identity,
            label,
            devices_path,
            grants_path,
            arm_path,
            join_dir,
            mesh_path,
            kick_notice_path,
            pending_kicks_path,
            mesh_dirty_path,
            pair_sessions_dir,
            config,
        )
    }

    /// Construct agent with explicit Paths (preferred).
    pub fn from_paths(identity: &Identity, paths: &Paths, config: Config) -> Result<Self> {
        Self::new_with_pair_dir(
            identity,
            config.device_label.clone(),
            paths.devices_file(),
            paths.grants_file(),
            paths.arm_file(),
            paths.join_dir(),
            paths.mesh_file(),
            paths.kick_notice_file(),
            paths.pending_kicks_file(),
            paths.mesh_dirty_file(),
            paths.pair_sessions_dir(),
            config,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_pair_dir(
        identity: &Identity,
        label: String,
        devices_path: PathBuf,
        grants_path: PathBuf,
        arm_path: PathBuf,
        join_dir: PathBuf,
        mesh_path: PathBuf,
        kick_notice_path: PathBuf,
        pending_kicks_path: PathBuf,
        mesh_dirty_path: PathBuf,
        pair_sessions_dir: PathBuf,
        config: Config,
    ) -> Result<Self> {
        let sandbox = PathSandbox::new(config.effective_sandbox_root())?;
        // Load empty enrollments.json if missing. Pair/decide write is F4.
        let data_dir = grants_path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        let _ = EnrollmentStore::open_or_create(data_dir.join("enrollments.json"))?;
        // Serve owns admin-nonces.json (F4p). Replay consume is F4 AdminEnvelope.
        let _ = AdminNonceStore::open_or_create(data_dir.join("admin-nonces.json"))?;
        Ok(Self {
            secret: identity.to_secret_bytes(),
            label,
            devices_path,
            grants_path,
            arm_path,
            join_dir,
            mesh_path,
            kick_notice_path,
            pending_kicks_path,
            mesh_dirty_path,
            pair_sessions_dir,
            config,
            files: std::sync::Arc::new(FileTransferEngine::new(sandbox)),
        })
    }

    fn identity(&self) -> Identity {
        Identity::from_secret_bytes(self.secret)
    }

    /// KD-F16: bind pair/v2 + mesh/v1 in-process. Serve owns `:17878`.
    pub async fn spawn_pair_http(
        &self,
        paths: &Paths,
        port: u16,
    ) -> anyhow::Result<crate::carrier::PairHttpHandle> {
        crate::carrier::start_pair_http(
            paths.clone(),
            &self.identity(),
            self.label.clone(),
            port,
            None,
        )
        .await
    }

    fn store(&self) -> Result<DeviceStore> {
        DeviceStore::open(&self.devices_path)
    }

    fn grants(&self) -> Result<GrantStore> {
        GrantStore::open(&self.grants_path)
    }

    fn pending(&self) -> Result<PendingKickStore> {
        PendingKickStore::open(&self.pending_kicks_path)
    }

    pub async fn run<T: Transport + ?Sized>(&self, transport: &T) -> Result<()> {
        let id = self.identity();
        info!(
            id = %id.device_id().short(),
            label = %self.label,
            "agent accepting sessions (mesh validate {}s)",
            MESH_VALIDATE_SECS
        );

        let mut last_validate = Instant::now() - Duration::from_secs(MESH_VALIDATE_SECS);
        let mut last_dirty_check = Instant::now();
        let mut last_dirty_mtime = mymesh_core::mesh_dirty_mtime(&self.mesh_dirty_path);

        loop {
            tokio::select! {
                conn = transport.accept() => {
                    let conn = conn?;
                    let peer = conn.peer_id();
                    let store = self.store()?;
                    let agent = self.clone();
                    if store.is_trusted(&peer) || self.pending()?.get(&peer).is_some() {
                        tokio::spawn(async move {
                            if let Err(e) = agent.handle_inbound(conn, peer).await {
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
                            // still try: peer might be connecting as kicked target still in their list
                            warn!(peer = %peer.short(), "rejecting untrusted peer (not armed)");
                            let _ = conn.close().await;
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(1)) => {
                    // dirty sync
                    if last_dirty_check.elapsed() >= Duration::from_secs(DIRTY_POLL_SECS) {
                        last_dirty_check = Instant::now();
                        let mt = mymesh_core::mesh_dirty_mtime(&self.mesh_dirty_path);
                        if mt != last_dirty_mtime {
                            last_dirty_mtime = mt;
                            if let Err(e) = self.push_mesh_to_all(transport).await {
                                warn!(%e, "dirty mesh push failed");
                            }
                        }
                    }
                    // periodic validate
                    if last_validate.elapsed() >= Duration::from_secs(MESH_VALIDATE_SECS) {
                        last_validate = Instant::now();
                        if let Err(e) = self.validate_mesh(transport).await {
                            warn!(%e, "periodic mesh validate failed");
                        }
                        let _ = self.pending()?.gc_completed();
                    }
                }
            }
        }
    }

    async fn handle_join(&self, conn: Box<dyn mymesh_net::PeerConnection>) -> Result<()> {
        let identity = self.identity();
        let outcome = handle_join_as_host_with_grants(
            conn,
            &identity,
            &self.label,
            &self.devices_path,
            &self.grants_path,
            &self.arm_path,
            &self.join_dir,
            &self.mesh_path,
            self.config.limits.arm_timeout_secs,
            Some(&self.pair_sessions_dir),
        )
        .await?;
        // Only full members change mesh-wide roster (guest joins stay local).
        if matches!(outcome, crate::join::JoinHostOutcome::MemberAccepted) {
            let _ = crate::mesh_sync::bump_mesh_dirty(&self.mesh_path, &self.mesh_dirty_path);
        }
        Ok(())
    }

    /// Inbound connection from peer (trusted or pending-kick target).
    async fn handle_inbound(
        &self,
        conn: Box<dyn mymesh_net::PeerConnection>,
        peer: mymesh_core::DeviceId,
    ) -> Result<()> {
        // Deliver pending kick on this live connection if needed
        if let Some(kick) = self.pending()?.get(&peer).cloned() {
            if !kick.delivered_to_target {
                let notice = ControlMessage::KickNotice {
                    mesh_id: kick.mesh_id.clone(),
                    by_id: kick.by_id,
                    by_label: kick.by_label.clone(),
                    message: kick.message.clone(),
                    ts: kick.ts,
                    force: kick.force,
                    signature: kick.signature,
                };
                let _ = conn
                    .send_frame(Frame {
                        channel: ChannelId::control(),
                        payload: encode_msg(&notice)?,
                    })
                    .await;
                // If we still have them trusted, continue session; else close after notice
            }
        }

        let store = self.store()?;
        if !store.is_trusted(&peer) {
            // only pending-kick delivery path
            tokio::time::sleep(Duration::from_millis(400)).await;
            let _ = conn.close().await;
            return Ok(());
        }

        self.handle_session(conn).await
    }

    async fn handle_session(&self, conn: Box<dyn mymesh_net::PeerConnection>) -> Result<()> {
        let identity = self.identity();
        let store = self.store()?;
        let grants = self.grants()?;
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
        // Always offer TCP tunnels when agent is up (magic / proxy-ssh / expose).
        offered.push(Capability::Tcp);

        let session = Session::handshake_acceptor_with_grants(
            conn,
            &identity,
            &self.label,
            &store,
            Some(&grants),
            offered,
        )
        .await?;
        let peer = session.peer_id();
        info!(peer = %peer.short(), "session established");

        let mut term: Option<TerminalHost> = None;
        let mut term_out: Option<tokio::sync::mpsc::Receiver<TerminalMessage>> = None;
        let mut active_put: Option<String> = None;
        let conn = session.into_conn();

        // Mesh-wide roster / kick gossip is for full members only (GUEST.md).
        // Guests are Trusted bilaterally but must never receive MembershipSnapshot.
        let peer_gets_gossip = crate::mesh_sync::peer_receives_mesh_gossip(&store, &peer);
        if peer_gets_gossip {
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
        }
        if peer_gets_gossip {
            if let Ok(pk) = self.pending() {
                for kick in pk.list() {
                    let ann = ControlMessage::KickAnnounce {
                        mesh_id: kick.mesh_id.clone(),
                        target_id: kick.target_id,
                        target_label: kick.target_label.clone(),
                        by_id: kick.by_id,
                        by_label: kick.by_label.clone(),
                        message: kick.message.clone(),
                        ts: kick.ts,
                        force: kick.force,
                        expected: kick.expected.clone(),
                        signature: kick.signature,
                    };
                    let _ = conn
                        .send_frame(Frame {
                            channel: ChannelId::control(),
                            payload: encode_msg(&ann)?,
                        })
                        .await;
                    // if this peer IS the target, send notice
                    if kick.target_id == peer && !kick.delivered_to_target {
                        let notice = ControlMessage::KickNotice {
                            mesh_id: kick.mesh_id.clone(),
                            by_id: kick.by_id,
                            by_label: kick.by_label.clone(),
                            message: kick.message.clone(),
                            ts: kick.ts,
                            force: kick.force,
                            signature: kick.signature,
                        };
                        let _ = conn
                            .send_frame(Frame {
                                channel: ChannelId::control(),
                                payload: encode_msg(&notice)?,
                            })
                            .await;
                    }
                }
            }
        }

        loop {
            tokio::select! {
                frame = conn.recv_frame() => {
                    let frame = frame?;
                    match frame.channel.kind {
                        ChannelKind::Terminal => {
                            let store = self.store()?;
                            let grants = self.grants()?;
                            let local = self.identity().device_id();
                            if !allows(&store, &grants, &local, &peer, &Capability::Terminal) {
                                continue;
                            }
                            let msg: TerminalMessage = decode_msg(&frame.payload)?;
                            match msg {
                                TerminalMessage::Open { cols, rows, shell, .. } => {
                                    let (host, rx) = TerminalHost::spawn(cols, rows, shell.as_deref())?;
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
                            let grants = self.grants()?;
                            let local = self.identity().device_id();
                            if !allows(&store, &grants, &local, &peer, &Capability::Files) {
                                continue;
                            }
                            let msg: FileMessage = decode_msg(&frame.payload)?;
                            match msg {
                                FileMessage::Put { path, .. } => {
                                    active_put = Some(path.clone());
                                    let replies = apply_host_message(&self.files, FileMessage::Put {
                                        path: path.clone(), size: 0, mode: 0o644, resume_from: 0,
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
                            self.handle_control(&conn, &identity, peer, decode_msg(&frame.payload)?).await?;
                        }
                        ChannelKind::Desktop => {
                            warn!("desktop not enabled yet");
                        }
                        ChannelKind::Tcp => {
                            // Trusted peers may open TCP tunnels (magic plane).
                            if !self.store()?.is_trusted(&peer) {
                                continue;
                            }
                            if let Some(h) = term.take() {
                                h.kill();
                            }
                            let _ = term_out.take();
                            return tcp_tunnel::host_bridge(conn, &frame.payload).await;
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
                            if let Some(h) = term.take() { h.kill(); }
                            term_out = None;
                        }
                        Some(_) => {}
                        None => { term_out = None; }
                    }
                }
            }
        }
    }

    async fn handle_control(
        &self,
        conn: &Box<dyn mymesh_net::PeerConnection>,
        identity: &Identity,
        peer: mymesh_core::DeviceId,
        msg: ControlMessage,
    ) -> Result<()> {
        match msg {
            ControlMessage::Ping { nonce } => {
                conn.send_frame(Frame {
                    channel: ChannelId::control(),
                    payload: encode_msg(&ControlMessage::Pong { nonce })?,
                })
                .await?;
            }
            ControlMessage::HostMetricsRequest { nonce } => {
                let report = crate::host_metrics::sample_metrics(nonce).await;
                conn.send_frame(Frame {
                    channel: ChannelId::control(),
                    payload: encode_msg(&report)?,
                })
                .await?;
            }
            ControlMessage::MembershipRequest { nonce } => {
                let store = self.store()?;
                // Guests must not pull mesh-wide roster (GUEST.md fail closed).
                if store
                    .get(&peer)
                    .map(|d| d.mesh_role == mymesh_core::MeshRole::Guest)
                    .unwrap_or(false)
                {
                    return Ok(());
                }
                let mesh = MeshState::load(&self.mesh_path)?;
                let snap = build_snapshot(identity, &self.label, &store, &mesh, nonce);
                conn.send_frame(Frame {
                    channel: ChannelId::control(),
                    payload: encode_msg(&snap)?,
                })
                .await?;
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
                if !store.is_trusted(&from_id) || from_id != peer {
                    return Ok(());
                }
                if verify_membership(&from_id, &mesh_id, ts, &members, &signature).is_err() {
                    return Ok(());
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
                    info!(added = n, "mesh membership updated");
                }
            }
            ControlMessage::KickAnnounce {
                mesh_id,
                target_id,
                target_label,
                by_id,
                by_label,
                message,
                ts,
                force,
                expected,
                signature,
            } => {
                let store = self.store()?;
                if !store.is_trusted(&by_id) || by_id != peer {
                    return Ok(());
                }
                if verify_kick(&mesh_id, &target_id, &by_id, ts, &signature).is_err() {
                    return Ok(());
                }
                // store pending
                let mut pk = self.pending()?;
                let mut exp = expected;
                if exp.is_empty() {
                    exp = store
                        .list()
                        .into_iter()
                        .filter(|d| {
                            d.trust == mymesh_core::TrustState::Trusted && d.id != target_id
                        })
                        .map(|d| d.id)
                        .collect();
                }
                pk.upsert(PendingKick {
                    target_id,
                    target_label: target_label.clone(),
                    by_id,
                    by_label: by_label.clone(),
                    mesh_id: mesh_id.clone(),
                    message: message.clone(),
                    ts,
                    signature,
                    force,
                    created_at: chrono::Utc::now(),
                    delivered_to_target: false,
                    acks: vec![],
                    expected: exp,
                })?;
                // apply locally immediately (force or normal — leave mesh)
                if target_id == identity.device_id() {
                    // we are target via announce (rare) — treat as notice
                    let mut store = self.store()?;
                    apply_kick_notice_local(
                        &mut store,
                        &self.mesh_path,
                        &self.kick_notice_path,
                        by_id,
                        &by_label,
                        &message,
                    )?;
                    pk.mark_delivered(&target_id)?;
                } else {
                    let mut store = self.store()?;
                    apply_kick_target(&mut store, &target_id)?;
                    // member ack
                    conn.send_frame(Frame {
                        channel: ChannelId::control(),
                        payload: encode_msg(&ControlMessage::KickMemberAck {
                            mesh_id,
                            target_id,
                            from_id: identity.device_id(),
                            ts: chrono::Utc::now().timestamp(),
                        })?,
                    })
                    .await?;
                }
            }
            ControlMessage::KickNotice {
                mesh_id,
                by_id,
                by_label,
                message,
                ts,
                force: _,
                signature,
            } => {
                let store = self.store()?;
                if !store.is_trusted(&by_id) {
                    return Ok(());
                }
                if verify_kick(&mesh_id, &identity.device_id(), &by_id, ts, &signature).is_err() {
                    return Ok(());
                }
                // Collect peers to ack BEFORE clearing
                let peers: Vec<_> = store
                    .list()
                    .into_iter()
                    .filter(|d| d.trust == mymesh_core::TrustState::Trusted)
                    .map(|d| d.id)
                    .collect();
                let mut store = self.store()?;
                apply_kick_notice_local(
                    &mut store,
                    &self.mesh_path,
                    &self.kick_notice_path,
                    by_id,
                    &by_label,
                    &message,
                )?;
                println!("you were kicked from the mesh by {by_label} host");
                conn.send_frame(Frame {
                    channel: ChannelId::control(),
                    payload: encode_msg(&ControlMessage::KickAck { accepted: true })?,
                })
                .await?;
                // Leave acks will be sent by outer agent maintenance when possible;
                // send leave-ack payload on this connection for kicker
                let ts2 = chrono::Utc::now().timestamp();
                let sig = sign_leave_ack(identity, &mesh_id, &by_id, ts2);
                conn.send_frame(Frame {
                    channel: ChannelId::control(),
                    payload: encode_msg(&ControlMessage::KickLeaveAck {
                        mesh_id: mesh_id.clone(),
                        target_id: identity.device_id(),
                        by_id,
                        ts: ts2,
                        signature: sig,
                    })?,
                })
                .await?;
                // Persist a leave-ack-outbox of peers for maintenance
                write_leave_outbox(
                    &self.mesh_path,
                    &peers,
                    &mesh_id,
                    identity.device_id(),
                    by_id,
                    ts2,
                    &sig,
                )?;
                let _ = conn.close().await;
            }
            ControlMessage::KickLeaveAck {
                mesh_id,
                target_id,
                by_id,
                ts,
                signature,
            } => {
                if verify_leave_ack(&mesh_id, &target_id, &by_id, ts, &signature).is_err() {
                    return Ok(());
                }
                let mut store = self.store()?;
                apply_kick_target(&mut store, &target_id)?;
                let mut pk = self.pending()?;
                pk.mark_delivered(&target_id)?;
                pk.add_ack(&target_id, target_id)?; // target self-ack
                pk.add_ack(&target_id, peer)?;
                info!(target = %target_id.short(), "kick leave-ack received");
                let _ = pk.gc_completed();
            }
            ControlMessage::KickMemberAck {
                target_id, from_id, ..
            } => {
                let mut pk = self.pending()?;
                pk.add_ack(&target_id, from_id)?;
                let _ = pk.gc_completed();
            }
            ControlMessage::KickAck { .. }
            | ControlMessage::MetricsPollEnable { .. }
            | ControlMessage::MetricsPollDisable => {}
            ControlMessage::GrantRevoke {
                grant_id,
                mesh_id,
                subject_device_id,
                object_device_id,
                by_id,
                ts,
                signature,
            } => {
                // Trusted full members only — guests must not mutate grants (fail closed).
                let store = self.store()?;
                if !crate::mesh_sync::peer_may_mutate_grants(&store, &by_id) || by_id != peer {
                    return Ok(());
                }
                let local_mesh = MeshState::load(&self.mesh_path)?;
                if !mesh_id.is_empty() && mesh_id != local_mesh.mesh_id {
                    return Ok(());
                }
                let now = chrono::Utc::now().timestamp();
                if (now - ts).abs() > 3600 {
                    return Ok(());
                }
                if verify_grant_revoke(
                    &mesh_id,
                    &grant_id,
                    &subject_device_id,
                    &object_device_id,
                    &by_id,
                    ts,
                    &signature,
                )
                .is_err()
                {
                    return Ok(());
                }
                // Only apply if we are the object host or already hold the grant.
                let local = identity.device_id();
                if object_device_id != local && self.grants()?.get(&grant_id).is_none() {
                    return Ok(());
                }
                let mut grants = self.grants()?;
                match apply_grant_revoke(&mut grants, &grant_id) {
                    Ok(g) => {
                        info!(
                            grant = %g.grant_id,
                            subject = %g.subject_device_id.short(),
                            "applied GrantRevoke"
                        );
                    }
                    Err(e) => {
                        // Unknown grant id is not an error on replicas that never held it.
                        warn!(%e, grant = %grant_id, "GrantRevoke apply skipped");
                    }
                }
            }
            ControlMessage::GrantAnnounce {
                grant_id,
                mesh_id,
                subject_device_id,
                object_device_id,
                by_id,
                ts,
                signature,
                ..
            } => {
                let store = self.store()?;
                if !crate::mesh_sync::peer_may_mutate_grants(&store, &by_id) || by_id != peer {
                    return Ok(());
                }
                let local_mesh = MeshState::load(&self.mesh_path)?;
                if !mesh_id.is_empty() && mesh_id != local_mesh.mesh_id {
                    return Ok(());
                }
                let now = chrono::Utc::now().timestamp();
                if (now - ts).abs() > 3600 {
                    return Ok(());
                }
                if verify_grant_announce(
                    &mesh_id,
                    &grant_id,
                    &subject_device_id,
                    &object_device_id,
                    &by_id,
                    ts,
                    &signature,
                )
                .is_err()
                {
                    return Ok(());
                }
                // Announce is informational for S5; object host already has the grant
                // from local create. Log only (no full guest identity flood).
                info!(
                    grant = %grant_id,
                    subject = %subject_device_id.short(),
                    object = %object_device_id.short(),
                    "GrantAnnounce received"
                );
            }
            _ => {}
        }
        Ok(())
    }

    async fn push_mesh_to_all<T: Transport + ?Sized>(&self, transport: &T) -> Result<()> {
        let identity = self.identity();
        let cfg_label = self.label.clone();
        let store = self.store()?;
        let mesh = MeshState::load(&self.mesh_path)?;
        let peers: Vec<_> = store
            .list()
            .into_iter()
            .filter(|d| {
                d.trust == mymesh_core::TrustState::Trusted
                    && d.mesh_role != mymesh_core::MeshRole::Guest
            })
            .map(|d| d.id)
            .collect();
        let announce = build_announce(&identity, &cfg_label, &store, &mesh);
        for peer in peers {
            if let Err(e) = self.dial_send(transport, peer, announce.clone()).await {
                warn!(peer = %peer.short(), %e, "mesh push failed");
            }
        }
        // also retry pending kick delivery
        self.flush_pending_kicks(transport).await?;
        self.flush_leave_outbox(transport).await?;
        Ok(())
    }

    async fn validate_mesh<T: Transport + ?Sized>(&self, transport: &T) -> Result<()> {
        info!("mesh validate (60s)");
        let identity = self.identity();
        let store = self.store()?;
        let peers: Vec<_> = store
            .list()
            .into_iter()
            .filter(|d| {
                d.trust == mymesh_core::TrustState::Trusted
                    && d.mesh_role != mymesh_core::MeshRole::Guest
            })
            .map(|d| d.id)
            .collect();
        for peer in peers {
            if let Err(e) = self
                .dial_request_membership(transport, &identity, peer)
                .await
            {
                warn!(peer = %peer.short(), %e, "mesh validate peer failed");
            }
        }
        self.flush_pending_kicks(transport).await?;
        self.flush_leave_outbox(transport).await?;
        Ok(())
    }

    async fn dial_send<T: Transport + ?Sized>(
        &self,
        transport: &T,
        peer: mymesh_core::DeviceId,
        msg: ControlMessage,
    ) -> Result<()> {
        let identity = self.identity();
        let store = self.store()?;
        if !store.is_trusted(&peer) {
            return Ok(());
        }
        let conn = transport.connect(peer).await?;
        let session =
            Session::handshake_dialer(conn, &identity, &self.label, &store, Capability::all())
                .await?;
        let conn = session.into_conn();
        conn.send_frame(Frame {
            channel: ChannelId::control(),
            payload: encode_msg(&msg)?,
        })
        .await?;
        let _ = tokio::time::timeout(Duration::from_secs(3), conn.recv_frame()).await;
        let _ = conn.close().await;
        Ok(())
    }

    async fn dial_request_membership<T: Transport + ?Sized>(
        &self,
        transport: &T,
        identity: &Identity,
        peer: mymesh_core::DeviceId,
    ) -> Result<()> {
        let store = self.store()?;
        let conn = transport.connect(peer).await?;
        let session =
            Session::handshake_dialer(conn, identity, &self.label, &store, Capability::all())
                .await?;
        let conn = session.into_conn();
        // push ours + request theirs
        let mesh = MeshState::load(&self.mesh_path)?;
        let store = self.store()?;
        let ann = build_announce(identity, &self.label, &store, &mesh);
        conn.send_frame(Frame {
            channel: ChannelId::control(),
            payload: encode_msg(&ann)?,
        })
        .await?;
        conn.send_frame(Frame {
            channel: ChannelId::control(),
            payload: encode_msg(&ControlMessage::MembershipRequest { nonce: 1 })?,
        })
        .await?;
        let deadline = Instant::now() + Duration::from_secs(8);
        while Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_secs(3), conn.recv_frame()).await {
                Ok(Ok(frame)) if frame.channel.kind == ChannelKind::Control => {
                    let msg: ControlMessage = decode_msg(&frame.payload)?;
                    if let ControlMessage::MembershipSnapshot {
                        mesh_id,
                        from_id,
                        members,
                        ts,
                        signature,
                        ..
                    } = msg
                    {
                        if verify_membership(&from_id, &mesh_id, ts, &members, &signature).is_ok() {
                            let mut store = self.store()?;
                            apply_membership(
                                &mut store,
                                &self.mesh_path,
                                &from_id,
                                &mesh_id,
                                &members,
                                identity.device_id(),
                            )?;
                        }
                        break;
                    }
                }
                _ => break,
            }
        }
        let _ = conn.close().await;
        Ok(())
    }

    async fn flush_pending_kicks<T: Transport + ?Sized>(&self, transport: &T) -> Result<()> {
        let pk = self.pending()?;
        let kicks: Vec<_> = pk.list().into_iter().cloned().collect();
        for kick in kicks {
            if kick.delivered_to_target {
                continue;
            }
            // try dial target — may still be trusted on their side
            let notice = ControlMessage::KickNotice {
                mesh_id: kick.mesh_id.clone(),
                by_id: kick.by_id,
                by_label: kick.by_label.clone(),
                message: kick.message.clone(),
                ts: kick.ts,
                force: kick.force,
                signature: kick.signature,
            };
            // connect without local trust check: temporarily re-add revoked?
            // Target was removed from our store. Need dial that skips trust.
            // Use special path: handshake with temporary trust insert.
            if let Err(e) = self
                .dial_kick_notice(transport, kick.target_id, notice)
                .await
            {
                warn!(target = %kick.target_id.short(), %e, "pending kick delivery deferred");
            } else {
                let mut pk = self.pending()?;
                pk.mark_delivered(&kick.target_id)?;
                info!(target = %kick.target_id.short(), "pending kick delivered");
            }
        }
        Ok(())
    }

    async fn dial_kick_notice<T: Transport + ?Sized>(
        &self,
        transport: &T,
        target: mymesh_core::DeviceId,
        notice: ControlMessage,
    ) -> Result<()> {
        // Temporarily ensure target is trusted for handshake, then remove again
        let mut store = self.store()?;
        let had = store.get(&target).cloned();
        if had.is_none() {
            let kick = self.pending()?.get(&target).cloned();
            if let Some(k) = kick {
                store.upsert(mymesh_core::DeviceRecord {
                    id: target,
                    label: mymesh_core::DeviceLabel::new(k.target_label),
                    fingerprint: mymesh_core::NodeFingerprint::from_device_id(&target)
                        .as_str()
                        .to_string(),
                    capabilities: Capability::all(),
                    trust: mymesh_core::TrustState::Trusted,
                    linked_at: chrono::Utc::now(),
                    last_seen: None,
                    endpoint_hint: None,
                    mesh_id: Some(k.mesh_id),

                    aliases: Vec::new(),
                    groups: Vec::new(),
                    mesh_role: mymesh_core::MeshRole::Member,
                })?;
            }
        }
        let identity = self.identity();
        let store = self.store()?;
        let conn = transport.connect(target).await?;
        let session =
            Session::handshake_dialer(conn, &identity, &self.label, &store, Capability::all())
                .await?;
        let conn = session.into_conn();
        conn.send_frame(Frame {
            channel: ChannelId::control(),
            payload: encode_msg(&notice)?,
        })
        .await?;
        let _ = tokio::time::timeout(Duration::from_secs(5), conn.recv_frame()).await;
        let _ = conn.close().await;
        // re-remove target
        let mut store = self.store()?;
        let _ = store.remove(&target);
        Ok(())
    }

    async fn flush_leave_outbox<T: Transport + ?Sized>(&self, transport: &T) -> Result<()> {
        let path = leave_outbox_path(&self.mesh_path);
        if !path.exists() {
            return Ok(());
        }
        let raw = std::fs::read_to_string(&path)?;
        let box_: LeaveOutbox = serde_json::from_str(&raw).unwrap_or(LeaveOutbox { items: vec![] });
        if box_.items.is_empty() {
            return Ok(());
        }
        let mut remaining = Vec::new();
        for item in box_.items {
            let sig_bytes = hex::decode(&item.signature_hex).unwrap_or_default();
            if sig_bytes.len() != 64 {
                remaining.push(item);
                continue;
            }
            let mut signature = [0u8; 64];
            signature.copy_from_slice(&sig_bytes);
            let msg = ControlMessage::KickLeaveAck {
                mesh_id: item.mesh_id.clone(),
                target_id: item.target_id,
                by_id: item.by_id,
                ts: item.ts,
                signature,
            };
            match self.dial_send(transport, item.peer, msg).await {
                Ok(()) => info!(peer = %item.peer.short(), "leave-ack delivered"),
                Err(_) => remaining.push(item),
            }
        }
        if remaining.is_empty() {
            let _ = std::fs::remove_file(&path);
        } else {
            std::fs::write(
                &path,
                serde_json::to_string_pretty(&LeaveOutbox { items: remaining })?,
            )?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct LeaveOutbox {
    items: Vec<LeaveOutboxItem>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct LeaveOutboxItem {
    peer: mymesh_core::DeviceId,
    mesh_id: String,
    target_id: mymesh_core::DeviceId,
    by_id: mymesh_core::DeviceId,
    ts: i64,
    signature_hex: String,
}

fn leave_outbox_path(mesh_path: &std::path::Path) -> PathBuf {
    mesh_path
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .join("leave-outbox.json")
}

fn write_leave_outbox(
    mesh_path: &std::path::Path,
    peers: &[mymesh_core::DeviceId],
    mesh_id: &str,
    target_id: mymesh_core::DeviceId,
    by_id: mymesh_core::DeviceId,
    ts: i64,
    signature: &[u8; 64],
) -> Result<()> {
    let path = leave_outbox_path(mesh_path);
    let items = peers
        .iter()
        .map(|peer| LeaveOutboxItem {
            peer: *peer,
            mesh_id: mesh_id.to_string(),
            target_id,
            by_id,
            ts,
            signature_hex: hex::encode(signature),
        })
        .collect();
    std::fs::write(&path, serde_json::to_string_pretty(&LeaveOutbox { items })?)?;
    Ok(())
}
