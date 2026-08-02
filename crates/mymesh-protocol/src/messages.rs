use mymesh_core::{Capability, DeviceId};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// ALPN identifier for MyMesh over QUIC/iroh.
pub const ALPN: &[u8] = b"mymesh/1";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ControlMessage {
    Hello {
        protocol_version: u16,
        device_id: DeviceId,
        label: String,
        capabilities: Vec<Capability>,
        /// Ed25519 signature over canonical hello bytes.
        #[serde(with = "crate::ser_fixed::array64")]
        signature: [u8; 64],
    },
    HelloAck {
        device_id: DeviceId,
        label: String,
        accepted_capabilities: Vec<Capability>,
        #[serde(with = "crate::ser_fixed::array64")]
        signature: [u8; 64],
    },
    Ping {
        nonce: u64,
    },
    Pong {
        nonce: u64,
    },
    Error {
        code: u16,
        message: String,
    },
    OpenChannel {
        request_id: Uuid,
        kind: crate::ChannelKind,
    },
    ChannelReady {
        request_id: Uuid,
        stream: u32,
    },
    CloseChannel {
        stream: u32,
        reason: String,
    },
    /// Joiner → host: request to be added (host must be armed).
    JoinRequest {
        protocol_version: u16,
        device_id: DeviceId,
        label: String,
        verifying_key: [u8; 32],
        capabilities: Vec<Capability>,
        ts: i64,
        #[serde(with = "crate::ser_fixed::array64")]
        signature: [u8; 64],
    },
    JoinPending {
        host_id: DeviceId,
        host_label: String,
        message: String,
    },
    JoinAccept {
        device_id: DeviceId,
        label: String,
        capabilities: Vec<Capability>,
        #[serde(with = "crate::ser_fixed::array64")]
        signature: [u8; 64],
    },
    JoinDeny {
        reason: String,
    },
    /// Client → host: request one-shot host resource snapshot
    HostMetricsRequest {
        nonce: u64,
    },
    /// Host → client
    HostMetrics {
        nonce: u64,
        cpu_pct: f32,
        mem_used_bytes: u64,
        mem_total_bytes: u64,
        disk_used_bytes: u64,
        disk_total_bytes: u64,
        net_rx_bytes: u64,
        net_tx_bytes: u64,
        load_1: f32,
        uptime_secs: u64,
        hostname: String,
        ts_unix: i64,
    },
    /// Client enables remote metrics streaming on this session
    MetricsPollEnable {
        interval_secs: u32,
        duration_secs: u32,
    },
    MetricsPollDisable,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TerminalMessage {
    /// Client → host: spawn a shell.
    Open {
        cols: u16,
        rows: u16,
        shell: Option<String>,
        env: Vec<(String, String)>,
    },
    Resize {
        cols: u16,
        rows: u16,
    },
    /// Client → host: stdin bytes.
    Input(Vec<u8>),
    /// Host → client: stdout/stderr bytes.
    Output(Vec<u8>),
    Exit {
        code: i32,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FileMessage {
    /// List directory
    List {
        path: String,
    },
    ListResult {
        entries: Vec<FileEntry>,
    },
    Stat {
        path: String,
    },
    StatResult {
        entry: FileEntry,
    },
    /// Pull file from host to client
    Get {
        path: String,
        offset: u64,
        length: Option<u64>,
    },
    /// Push file from client to host
    Put {
        path: String,
        size: u64,
        mode: u32,
        resume_from: u64,
    },
    /// Raw chunk (either direction after Get/Put setup)
    Chunk {
        offset: u64,
        data: Vec<u8>,
    },
    Done {
        path: String,
        bytes: u64,
    },
    Mkdir {
        path: String,
    },
    Remove {
        path: String,
        recursive: bool,
    },
    Rename {
        from: String,
        to: String,
    },
    Error {
        message: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified: Option<i64>,
    pub mode: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DesktopMessage {
    /// Client requests desktop stream.
    Start {
        fps: u8,
        quality: u8,
        monitor: Option<u32>,
    },
    Stop,
    /// Host → client video sample (encoded frame or raw for v0).
    Frame {
        width: u32,
        height: u32,
        codec: DesktopCodec,
        data: Vec<u8>,
        pts_ms: u64,
    },
    /// Client → host input events.
    Input(DesktopInput),
    Clipboard {
        mime: String,
        data: Vec<u8>,
    },
    Error {
        message: String,
    },
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopCodec {
    /// Lossless raw RGBA (dev only).
    Rgba,
    /// VP8/VP9/AV1 to be selected at runtime.
    Vp8,
    Vp9,
    Av1,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DesktopInput {
    MouseMove {
        x: f32,
        y: f32,
    },
    MouseButton {
        button: u8,
        pressed: bool,
    },
    MouseWheel {
        dx: f32,
        dy: f32,
    },
    Key {
        keycode: u32,
        pressed: bool,
        text: Option<String>,
    },
}

/// Messages exchanged during the short-code pairing ceremony (before permanent link).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PairingMessage {
    /// SPAKE2 message blob.
    Spake(Vec<u8>),
    /// After SPAKE2: exchange long-term identity + capabilities + signature.
    IdentityOffer {
        device_id: DeviceId,
        label: String,
        verifying_key: [u8; 32],
        capabilities: Vec<Capability>,
        /// Signature over device_id||label with the long-term key.
        #[serde(with = "crate::ser_fixed::array64")]
        signature: [u8; 64],
        /// MAC with SPAKE2-derived key binding the offer.
        binder: [u8; 32],
    },
    IdentityAccept {
        device_id: DeviceId,
        label: String,
        verifying_key: [u8; 32],
        accepted_capabilities: Vec<Capability>,
        #[serde(with = "crate::ser_fixed::array64")]
        signature: [u8; 64],
        binder: [u8; 32],
    },
    Reject {
        reason: String,
    },
}
