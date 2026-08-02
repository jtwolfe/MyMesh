//! Local agent dial proxy.
//!
//! Only one iroh Endpoint may exist per MyMesh identity. The long-lived `mymesh serve`
//! process owns that endpoint. CLI/TUI must dial *through* the agent over a Unix socket
//! instead of calling `IrohTransport::bind` again (which steals the EndpointId and
//! causes `connection lost` / connect timeouts).
use crate::iroh_transport::IrohTransport;
use crate::traits::{PeerConnection, Transport};
use async_trait::async_trait;
use mymesh_core::{DeviceId, Error, Result};
use mymesh_protocol::{read_frame, write_frame, Frame};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tracing::{info, warn};

/// Wire magic for the dial-proxy protocol.
pub const DIAL_MAGIC: &[u8; 4] = b"MMD1";
const OK: u8 = 0;
const ERR: u8 = 1;

/// Default socket path (same as config daemon.control_socket).
pub fn default_control_socket() -> PathBuf {
    if let Ok(p) = std::env::var("MYMESH_CONTROL_SOCK") {
        return PathBuf::from(p);
    }
    let runtime = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(runtime).join("mymesh.sock")
}

/// Serve dial-proxy on `path`. Uses the agent's single iroh transport.
pub async fn serve_dial_proxy(path: PathBuf, transport: Arc<IrohTransport>) -> Result<()> {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).map_err(|e| {
        Error::Session(format!("bind control socket {}: {e}", path.display()))
    })?;
    // Best-effort private socket
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    info!(path = %path.display(), "local dial proxy listening");
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .map_err(|e| Error::Session(format!("control accept: {e}")))?;
        let t = transport.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_proxy_client(stream, t).await {
                warn!(%e, "dial proxy client ended");
            }
        });
    }
}

async fn handle_proxy_client(mut stream: UnixStream, transport: Arc<IrohTransport>) -> Result<()> {
    let mut hdr = [0u8; 4 + 32];
    stream
        .read_exact(&mut hdr)
        .await
        .map_err(|e| Error::Session(format!("proxy handshake read: {e}")))?;
    if &hdr[0..4] != DIAL_MAGIC {
        return Err(Error::Session("bad dial proxy magic".into()));
    }
    let mut idb = [0u8; 32];
    idb.copy_from_slice(&hdr[4..36]);
    let peer = DeviceId::from_bytes(idb);

    match transport.connect(peer).await {
        Ok(conn) => {
            stream
                .write_all(&[OK])
                .await
                .map_err(|e| Error::Session(format!("proxy ok write: {e}")))?;
            relay_frames(stream, conn).await
        }
        Err(e) => {
            let msg = e.to_string();
            let bytes = msg.as_bytes();
            let len = (bytes.len() as u32).min(2048);
            let mut out = Vec::with_capacity(1 + 4 + len as usize);
            out.push(ERR);
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(&bytes[..len as usize]);
            let _ = stream.write_all(&out).await;
            Err(e)
        }
    }
}

async fn relay_frames(stream: UnixStream, conn: Box<dyn PeerConnection>) -> Result<()> {
    let (rh, wh) = stream.into_split();
    let read_half = Arc::new(Mutex::new(rh));
    let write_half = Arc::new(Mutex::new(wh));
    let conn: Arc<dyn PeerConnection> = Arc::from(conn);

    let c1 = conn.clone();
    let w1 = write_half.clone();
    let up = async move {
        loop {
            let frame = match c1.recv_frame().await {
                Ok(f) => f,
                Err(_) => break,
            };
            let mut w = w1.lock().await;
            if write_frame(&mut *w, &frame).await.is_err() {
                break;
            }
        }
    };

    let c2 = conn.clone();
    let r2 = read_half.clone();
    let down = async move {
        loop {
            let frame = {
                let mut r = r2.lock().await;
                match read_frame(&mut *r).await {
                    Ok(f) => f,
                    Err(_) => break,
                }
            };
            if c2.send_frame(frame).await.is_err() {
                break;
            }
        }
    };

    tokio::select! {
        _ = up => {}
        _ = down => {}
    }
    let _ = conn.close().await;
    Ok(())
}

/// True if the agent dial proxy socket exists and looks live.
pub fn agent_proxy_available(path: &Path) -> bool {
    path.exists()
}

/// Dial a peer via the local agent (no second iroh bind).
pub async fn connect_via_agent(path: &Path, peer: DeviceId) -> Result<Box<dyn PeerConnection>> {
    let mut stream = UnixStream::connect(path).await.map_err(|e| {
        Error::Session(format!(
            "connect control socket {}: {e} (is `mymesh serve` / user unit running?)",
            path.display()
        ))
    })?;
    let mut req = Vec::with_capacity(4 + 32);
    req.extend_from_slice(DIAL_MAGIC);
    req.extend_from_slice(peer.as_bytes());
    stream
        .write_all(&req)
        .await
        .map_err(|e| Error::Session(format!("proxy dial write: {e}")))?;

    let mut status = [0u8; 1];
    stream
        .read_exact(&mut status)
        .await
        .map_err(|e| Error::Session(format!("proxy dial status: {e}")))?;
    if status[0] == ERR {
        let mut lenb = [0u8; 4];
        stream.read_exact(&mut lenb).await.ok();
        let len = u32::from_be_bytes(lenb) as usize;
        let mut msg = vec![0u8; len.min(2048)];
        let _ = stream.read_exact(&mut msg).await;
        return Err(Error::Session(format!(
            "agent dial failed: {}",
            String::from_utf8_lossy(&msg)
        )));
    }
    if status[0] != OK {
        return Err(Error::Session("bad proxy status".into()));
    }
    Ok(Box::new(UdsFrameConn {
        peer,
        stream: Mutex::new(stream),
    }))
}

struct UdsFrameConn {
    peer: DeviceId,
    stream: Mutex<UnixStream>,
}

#[async_trait]
impl PeerConnection for UdsFrameConn {
    fn peer_id(&self) -> DeviceId {
        self.peer
    }

    async fn send_frame(&self, frame: Frame) -> Result<()> {
        let mut s = self.stream.lock().await;
        write_frame(&mut *s, &frame)
            .await
            .map_err(|e| Error::Session(format!("proxy send: {e}")))
    }

    async fn recv_frame(&self) -> Result<Frame> {
        let mut s = self.stream.lock().await;
        read_frame(&mut *s)
            .await
            .map_err(|e| Error::Session(format!("proxy recv: {e}")))
    }

    async fn close(&self) -> Result<()> {
        // Dropping the stream is enough; optional shutdown
        Ok(())
    }
}

/// Prefer agent proxy; only direct-bind if no agent (with a clear log risk).
pub async fn connect_mesh(
    identity: &mymesh_crypto::Identity,
    peer: DeviceId,
    control_sock: &Path,
) -> Result<(Box<dyn PeerConnection>, Option<IrohTransport>)> {
    if agent_proxy_available(control_sock) {
        match connect_via_agent(control_sock, peer).await {
            Ok(c) => return Ok((c, None)),
            Err(e) => {
                warn!(
                    %e,
                    "agent dial proxy failed — falling back to direct bind (may conflict with serve)"
                );
            }
        }
    } else {
        warn!(
            "no agent dial proxy at {} — direct iroh bind (start `mymesh serve` for stable mesh)",
            control_sock.display()
        );
    }
    let transport = IrohTransport::bind(identity).await?;
    let conn = transport.connect(peer).await?;
    Ok((conn, Some(transport)))
}
