//! Local agent dial proxy + MMA1 admin.
//!
//! Only one iroh Endpoint may exist per MyMesh identity. The long-lived `mymesh serve`
//! process owns that endpoint. CLI/TUI must dial *through* the agent over a Unix socket
//! instead of calling `IrohTransport::bind` again (which steals the EndpointId and
//! causes `connection lost` / connect timeouts).
//!
//! Accept loop reads **4 magic bytes first**, then branches (KD-F16 / F4p):
//! - `MMD1` || device_id_32 → existing dial proxy (unchanged after the 4-byte split)
//! - `MMA1` || u32le(len) || json → local admin; never a frame bridge
//! - unknown magic → close (do not attempt MMD1 did-read)
use crate::iroh_transport::IrohTransport;
use crate::traits::{PeerConnection, Transport};
use async_trait::async_trait;
use mymesh_core::{DeviceId, Error, Result};
use mymesh_protocol::{read_frame, write_frame, Frame};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tracing::{info, warn};

/// Wire magic for the dial-proxy protocol (MMD1 || 32-byte device id).
pub const DIAL_MAGIC: &[u8; 4] = b"MMD1";
/// Wire magic for local admin (MMA1 || u32le length || JSON). Never a frame bridge.
pub const ADMIN_MAGIC: &[u8; 4] = b"MMA1";
const OK: u8 = 0;
const ERR: u8 = 1;
const MAX_ADMIN_BODY: usize = 64 * 1024;

/// Default socket path (same as config daemon.control_socket).
pub fn default_control_socket() -> PathBuf {
    if let Ok(p) = std::env::var("MYMESH_CONTROL_SOCK") {
        return PathBuf::from(p);
    }
    let runtime = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(runtime).join("mymesh.sock")
}

/// Local admin over the control socket (MMA1). Not a frame bridge.
#[async_trait]
pub trait LocalAdmin: Send + Sync {
    async fn handle(&self, request: serde_json::Value) -> serde_json::Value;
}

/// Serve dial-proxy on `path` (MMD1 only). Uses the agent's single iroh transport.
pub async fn serve_dial_proxy(path: PathBuf, transport: Arc<IrohTransport>) -> Result<()> {
    let t: Arc<dyn Transport> = transport;
    serve_control_socket(path, t, None).await
}

/// Serve MMD1 dial-proxy and optional MMA1 admin on `path` (mode 0600).
pub async fn serve_control_socket(
    path: PathBuf,
    transport: Arc<dyn Transport>,
    admin: Option<Arc<dyn LocalAdmin>>,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)
        .map_err(|e| Error::Session(format!("bind control socket {}: {e}", path.display())))?;
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
        let admin = admin.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_proxy_client(stream, t, admin).await {
                warn!(%e, "dial proxy client ended");
            }
        });
    }
}

async fn handle_proxy_client(
    mut stream: UnixStream,
    transport: Arc<dyn Transport>,
    admin: Option<Arc<dyn LocalAdmin>>,
) -> Result<()> {
    // Read 4-byte magic first — do not consume a device-id on MMA1 / unknown.
    let mut magic = [0u8; 4];
    stream
        .read_exact(&mut magic)
        .await
        .map_err(|e| Error::Session(format!("proxy handshake read: {e}")))?;
    if &magic == ADMIN_MAGIC {
        return handle_admin_client(stream, admin).await;
    }
    if &magic != DIAL_MAGIC {
        // Unknown magic → close. Do not attempt MMD1 did-read.
        return Err(Error::Session("bad control socket magic".into()));
    }

    let mut idb = [0u8; 32];
    stream
        .read_exact(&mut idb)
        .await
        .map_err(|e| Error::Session(format!("proxy handshake read: {e}")))?;
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

async fn handle_admin_client(
    mut stream: UnixStream,
    admin: Option<Arc<dyn LocalAdmin>>,
) -> Result<()> {
    let mut lenb = [0u8; 4];
    stream
        .read_exact(&mut lenb)
        .await
        .map_err(|e| Error::Session(format!("mma1 length read: {e}")))?;
    let len = u32::from_le_bytes(lenb) as usize;
    if len == 0 || len > MAX_ADMIN_BODY {
        let resp = serde_json::json!({
            "ok": false,
            "code": "bad_request",
            "error": "invalid length"
        });
        let _ = write_admin_response(&mut stream, &resp).await;
        return Ok(());
    }
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| Error::Session(format!("mma1 body read: {e}")))?;
    let req: serde_json::Value = match serde_json::from_slice(&buf) {
        Ok(v) => v,
        Err(e) => {
            let resp = serde_json::json!({
                "ok": false,
                "code": "bad_request",
                "error": format!("invalid json: {e}")
            });
            let _ = write_admin_response(&mut stream, &resp).await;
            return Ok(());
        }
    };
    let resp = match admin {
        Some(admin) => admin.handle(req).await,
        None => serde_json::json!({
            "ok": false,
            "code": "unavailable",
            "error": "no local admin"
        }),
    };
    write_admin_response(&mut stream, &resp).await
}

async fn write_admin_response(stream: &mut UnixStream, v: &serde_json::Value) -> Result<()> {
    let bytes = serde_json::to_vec(v)
        .unwrap_or_else(|_| br#"{"ok":false,"code":"internal","error":"serialize"}"#.to_vec());
    let len = bytes.len().min(MAX_ADMIN_BODY) as u32;
    stream
        .write_all(&len.to_le_bytes())
        .await
        .map_err(|e| Error::Session(format!("mma1 response write: {e}")))?;
    stream
        .write_all(&bytes[..len as usize])
        .await
        .map_err(|e| Error::Session(format!("mma1 response write: {e}")))?;
    Ok(())
}

async fn relay_frames(stream: UnixStream, conn: Box<dyn PeerConnection>) -> Result<()> {
    let (rh, wh) = stream.into_split();
    let write_half = Arc::new(Mutex::new(wh));
    let conn: Arc<dyn PeerConnection> = Arc::from(conn);

    // iroh → uds
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

    // uds → iroh
    let c2 = conn.clone();
    let down = async move {
        let mut r = rh;
        loop {
            let frame = match read_frame(&mut r).await {
                Ok(f) => f,
                Err(_) => break,
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

/// True if the control socket exists and accepts a Unix connect (serve is up).
pub fn agent_control_live(path: &Path) -> bool {
    if !path.exists() {
        return false;
    }
    std::os::unix::net::UnixStream::connect(path).is_ok()
}

/// True if something is accepting TCP on `127.0.0.1:port` (pair HTTP bind).
pub fn pair_http_port_live(port: u16) -> bool {
    std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_millis(150),
    )
    .is_ok()
}

/// Serve owns pair HTTP when the control socket is live or `:port` is already bound.
pub fn serve_owns_pair_http(port: u16, control_sock: &Path) -> bool {
    pair_http_port_live(port) || agent_control_live(control_sock)
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

    let (rh, wh) = stream.into_split();
    Ok(Box::new(UdsFrameConn {
        peer,
        read: Mutex::new(rh),
        write: Mutex::new(wh),
    }))
}

/// Send one MMA1 JSON request and read the framed JSON response.
pub async fn admin_request(path: &Path, body: &serde_json::Value) -> Result<serde_json::Value> {
    let bytes = serde_json::to_vec(body).map_err(|e| Error::Serialize(e.to_string()))?;
    if bytes.is_empty() || bytes.len() > MAX_ADMIN_BODY {
        return Err(Error::Session("mma1 request too large".into()));
    }
    let mut stream = UnixStream::connect(path).await.map_err(|e| {
        Error::Session(format!(
            "connect control socket {}: {e} (is `mymesh serve` / user unit running?)",
            path.display()
        ))
    })?;
    stream
        .write_all(ADMIN_MAGIC)
        .await
        .map_err(|e| Error::Session(format!("mma1 write: {e}")))?;
    stream
        .write_all(&(bytes.len() as u32).to_le_bytes())
        .await
        .map_err(|e| Error::Session(format!("mma1 write: {e}")))?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|e| Error::Session(format!("mma1 write: {e}")))?;

    let mut lenb = [0u8; 4];
    stream
        .read_exact(&mut lenb)
        .await
        .map_err(|e| Error::Session(format!("mma1 response length: {e}")))?;
    let len = u32::from_le_bytes(lenb) as usize;
    if len == 0 || len > MAX_ADMIN_BODY {
        return Err(Error::Session("mma1 response length invalid".into()));
    }
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| Error::Session(format!("mma1 response body: {e}")))?;
    serde_json::from_slice(&buf).map_err(|e| Error::Serialize(e.to_string()))
}

/// MMA1 `arm_pair_qr` response (subset used by TUI / tests).
#[derive(Debug, Clone, Deserialize)]
pub struct ArmPairQrResponse {
    pub ok: bool,
    #[serde(default)]
    pub qr: Option<String>,
    #[serde(default)]
    pub sid: Option<String>,
    #[serde(default)]
    pub host_base: Option<String>,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

/// Ask a live serve process to mint QR_A via MMA1 (does not bind HTTP).
pub async fn arm_pair_qr_via_agent(path: &Path, ttl_secs: u64) -> Result<ArmPairQrResponse> {
    let v = admin_request(
        path,
        &serde_json::json!({
            "cmd": "arm_pair_qr",
            "ttl_secs": ttl_secs
        }),
    )
    .await?;
    let parsed: ArmPairQrResponse =
        serde_json::from_value(v).map_err(|e| Error::Serialize(e.to_string()))?;
    if !parsed.ok {
        let detail = parsed
            .error
            .clone()
            .or_else(|| parsed.code.clone())
            .unwrap_or_else(|| "error".into());
        return Err(Error::Session(format!("arm_pair_qr: {detail}")));
    }
    Ok(parsed)
}

/// Full-duplex frame conn over a split UnixStream (send ∥ recv without deadlock).
struct UdsFrameConn {
    peer: DeviceId,
    read: Mutex<OwnedReadHalf>,
    write: Mutex<OwnedWriteHalf>,
}

#[async_trait]
impl PeerConnection for UdsFrameConn {
    fn peer_id(&self) -> DeviceId {
        self.peer
    }

    async fn send_frame(&self, frame: Frame) -> Result<()> {
        let mut w = self.write.lock().await;
        write_frame(&mut *w, &frame)
            .await
            .map_err(|e| Error::Session(format!("proxy send: {e}")))
    }

    async fn recv_frame(&self) -> Result<Frame> {
        let mut r = self.read.lock().await;
        read_frame(&mut *r)
            .await
            .map_err(|e| Error::Session(format!("proxy recv: {e}")))
    }

    async fn close(&self) -> Result<()> {
        Ok(())
    }

    async fn send_raw(&self, data: &[u8]) -> Result<()> {
        let mut w = self.write.lock().await;
        w.write_all(data)
            .await
            .map_err(|e| Error::Session(format!("proxy send raw: {e}")))?;
        w.flush()
            .await
            .map_err(|e| Error::Session(format!("proxy flush raw: {e}")))
    }

    async fn recv_raw(&self) -> Result<Vec<u8>> {
        let mut r = self.read.lock().await;
        let mut len_buf = [0u8; 4];
        r.read_exact(&mut len_buf)
            .await
            .map_err(|e| Error::Session(format!("proxy recv raw len: {e}")))?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > mymesh_protocol::MAX_JSON_MSG_BYTES {
            return Err(Error::Protocol("message too large".into()));
        }
        let mut payload = vec![0u8; len];
        r.read_exact(&mut payload)
            .await
            .map_err(|e| Error::Session(format!("proxy recv raw payload: {e}")))?;
        let mut full = Vec::with_capacity(4 + len);
        full.extend_from_slice(&len_buf);
        full.extend_from_slice(&payload);
        Ok(full)
    }
}

/// Prefer agent proxy; only direct-bind if no agent (with a clear log risk).
fn control_sock_candidates(preferred: &Path) -> Vec<PathBuf> {
    let mut out = vec![preferred.to_path_buf()];
    out.push(default_control_socket());
    if let Ok(runtime) = std::env::var("XDG_RUNTIME_DIR") {
        out.push(PathBuf::from(runtime).join("mymesh.sock"));
    }
    // OpenSSH ProxyCommand often has no XDG_RUNTIME_DIR — probe common user runtimes.
    if let Ok(uid) = std::env::var("UID") {
        out.push(PathBuf::from(format!("/run/user/{uid}/mymesh.sock")));
    }
    #[cfg(unix)]
    {
        if let Ok(rd) = std::fs::read_dir("/run/user") {
            for e in rd.flatten() {
                out.push(e.path().join("mymesh.sock"));
            }
        }
    }
    out.push(PathBuf::from("/tmp/mymesh.sock"));
    out.sort();
    out.dedup();
    // keep preferred first
    let mut ordered = vec![preferred.to_path_buf()];
    for p in out {
        if p != preferred {
            ordered.push(p);
        }
    }
    ordered
}

pub async fn connect_mesh(
    identity: &mymesh_crypto::Identity,
    peer: DeviceId,
    control_sock: &Path,
) -> Result<(Box<dyn PeerConnection>, Option<IrohTransport>)> {
    for sock in control_sock_candidates(control_sock) {
        if !agent_proxy_available(&sock) {
            continue;
        }
        match connect_via_agent(&sock, peer).await {
            Ok(c) => return Ok((c, None)),
            Err(e) => {
                warn!(%e, path = %sock.display(), "agent dial proxy failed — try next");
            }
        }
    }
    warn!(
        "no working agent dial proxy (tried {}) — direct iroh bind (may conflict with serve)",
        control_sock.display()
    );
    let transport = IrohTransport::bind(identity).await?;
    let conn = transport.connect(peer).await?;
    Ok((conn, Some(transport)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LocalFabric;
    use bytes::Bytes;
    use mymesh_crypto::Identity;
    use mymesh_protocol::ChannelId;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    struct TestAdmin;

    #[async_trait]
    impl LocalAdmin for TestAdmin {
        async fn handle(&self, request: serde_json::Value) -> serde_json::Value {
            match request.get("cmd").and_then(|c| c.as_str()) {
                Some("arm_pair_qr") => serde_json::json!({
                    "ok": true,
                    "qr": "carrier://pair?v=2&sid=testsid",
                    "sid": "testsid",
                    "host_base": "http://127.0.0.1:17878"
                }),
                _ => serde_json::json!({
                    "ok": false,
                    "code": "bad_request",
                    "error": "unknown cmd"
                }),
            }
        }
    }

    fn tmp_sock() -> PathBuf {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "mmd1-{}-{}-{n}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ))
    }

    async fn wait_sock(path: &Path) {
        for _ in 0..100 {
            if path.exists() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("control socket did not appear: {}", path.display());
    }

    async fn spawn_proxy(
        path: PathBuf,
        transport: Arc<dyn Transport>,
        admin: Option<Arc<dyn LocalAdmin>>,
    ) {
        tokio::spawn(async move {
            let _ = serve_control_socket(path, transport, admin).await;
        });
        // serve_control_socket binds before accept loop
        tokio::task::yield_now().await;
    }

    #[tokio::test]
    async fn connect_mesh_still_works_after_mma1_arm_pair_qr() {
        let fabric = LocalFabric::new();
        let id_a = Identity::generate();
        let id_b = Identity::generate();
        let ep_a = fabric.endpoint(id_a.device_id());
        let ep_b = fabric.endpoint(id_b.device_id());

        let sock = tmp_sock();
        spawn_proxy(sock.clone(), Arc::new(ep_a), Some(Arc::new(TestAdmin))).await;
        wait_sock(&sock).await;

        let armed = arm_pair_qr_via_agent(&sock, 600).await.expect("mma1 arm");
        assert!(armed.ok);
        assert_eq!(armed.sid.as_deref(), Some("testsid"));
        assert_eq!(armed.qr.as_deref(), Some("carrier://pair?v=2&sid=testsid"));

        // MMD1 / connect_mesh must still work after MMA1 (do not overload handshake).
        let accept = tokio::spawn(async move { ep_b.accept().await });
        let (conn, direct) = connect_mesh(&id_a, id_b.device_id(), &sock)
            .await
            .expect("connect_mesh after MMA1");
        assert!(
            direct.is_none(),
            "must use agent MMD1 proxy, not direct bind"
        );
        conn.send_frame(Frame {
            channel: ChannelId::control(),
            payload: Bytes::from_static(b"ping"),
        })
        .await
        .expect("send via MMD1");
        let peer = accept.await.expect("join").expect("accept");
        let frame = peer.recv_frame().await.expect("recv");
        assert_eq!(&frame.payload[..], b"ping");
        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn mmd1_path_unchanged_without_mma1() {
        let fabric = LocalFabric::new();
        let id_a = Identity::generate();
        let id_b = Identity::generate();
        let ep_a = fabric.endpoint(id_a.device_id());
        let ep_b = fabric.endpoint(id_b.device_id());
        let sock = tmp_sock();
        spawn_proxy(sock.clone(), Arc::new(ep_a), Some(Arc::new(TestAdmin))).await;
        wait_sock(&sock).await;

        let accept = tokio::spawn(async move { ep_b.accept().await });
        let conn = connect_via_agent(&sock, id_b.device_id())
            .await
            .expect("MMD1 dial");
        conn.send_frame(Frame {
            channel: ChannelId::control(),
            payload: Bytes::from_static(b"mmd1"),
        })
        .await
        .unwrap();
        let peer = accept.await.unwrap().unwrap();
        let frame = peer.recv_frame().await.unwrap();
        assert_eq!(&frame.payload[..], b"mmd1");
        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn unknown_magic_closes_without_did_read() {
        let fabric = LocalFabric::new();
        let id_a = Identity::generate();
        let sock = tmp_sock();
        spawn_proxy(
            sock.clone(),
            Arc::new(fabric.endpoint(id_a.device_id())),
            Some(Arc::new(TestAdmin)),
        )
        .await;
        wait_sock(&sock).await;

        let mut stream = UnixStream::connect(&sock).await.unwrap();
        stream.write_all(b"XXXX").await.unwrap();
        // leftover would be interpreted as did if we did not branch on magic
        let _ = stream.write_all(&[0u8; 32]).await;
        let mut buf = [0u8; 1];
        let n = stream.read(&mut buf).await;
        match n {
            Ok(0) => {}
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
            other => panic!("unknown magic must close, not return MMD1 status: {other:?}"),
        }
        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn unknown_mma1_cmd_is_bad_request() {
        let fabric = LocalFabric::new();
        let id_a = Identity::generate();
        let sock = tmp_sock();
        spawn_proxy(
            sock.clone(),
            Arc::new(fabric.endpoint(id_a.device_id())),
            Some(Arc::new(TestAdmin)),
        )
        .await;
        wait_sock(&sock).await;

        let v = admin_request(&sock, &serde_json::json!({"cmd": "not_a_cmd"}))
            .await
            .unwrap();
        assert_eq!(v["ok"], false);
        assert_eq!(v["code"], "bad_request");
        let _ = std::fs::remove_file(&sock);
    }

    #[test]
    fn serve_owns_pair_http_false_when_nothing_listens() {
        let sock = tmp_sock();
        assert!(!agent_control_live(&sock));
        assert!(!serve_owns_pair_http(1, &sock));
    }
}
