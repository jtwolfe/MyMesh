//! Connect-by-carrier: local web page for phone-assisted join (no phone mesh node).
use axum::extract::State;
use axum::response::Html;
use axum::routing::{get, post};
use axum::{Json, Router};
use mymesh_core::{ArmState, Paths};
use mymesh_crypto::{device_join_uri, Identity};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;
use tracing::info;

#[derive(Clone)]
struct CarrierState {
    paths: Paths,
    secret: [u8; 32],
    label: String,
    pending_peer: Arc<Mutex<Option<String>>>,
    status: Arc<Mutex<String>>,
}

impl CarrierState {
    fn identity(&self) -> Identity {
        Identity::from_secret_bytes(self.secret)
    }
}

#[derive(Deserialize)]
struct PeerBody {
    uri: String,
}

#[derive(Serialize)]
struct StatusBody {
    status: String,
    local_uri: String,
    local_label: String,
}

pub struct CarrierHandle {
    pub url: String,
    pub bind: SocketAddr,
}

pub async fn start_carrier(
    paths: Paths,
    identity: Identity,
    label: String,
    port: u16,
    lan_ip: Option<String>,
) -> anyhow::Result<CarrierHandle> {
    let st = CarrierState {
        paths,
        secret: identity.to_secret_bytes(),
        label: label.clone(),
        pending_peer: Arc::new(Mutex::new(None)),
        status: Arc::new(Mutex::new("waiting for phone".into())),
    };

    let app = Router::new()
        .route("/", get(page))
        .route("/api/status", get(api_status))
        .route("/api/peer", post(api_peer))
        .route("/api/local", get(api_local))
        .layer(CorsLayer::permissive())
        .with_state(st);

    let bind: SocketAddr = format!("0.0.0.0:{port}").parse()?;
    let listener = tokio::net::TcpListener::bind(bind).await?;
    let actual = listener.local_addr()?;
    let host = lan_ip.unwrap_or_else(|| local_ipv4().unwrap_or_else(|| "127.0.0.1".into()));
    let url = format!("http://{host}:{}/", actual.port());
    info!(%url, "carrier page listening");

    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::warn!(%e, "carrier server exit");
        }
    });

    Ok(CarrierHandle { url, bind: actual })
}

async fn page(State(st): State<CarrierState>) -> Html<String> {
    let local_uri = device_join_uri(&st.identity().device_id()).unwrap_or_default();
    let label = html_escape(&st.label);
    let local = html_escape(&local_uri);
    let html = format!(
        concat!(
            "<!doctype html><html><head>",
            "<meta name=viewport content=\"width=device-width,initial-scale=1\"/>",
            "<title>MyMesh carrier</title>",
            "<style>body{{font-family:system-ui;background:#111;color:#eee;margin:1rem}}</style>",
            "</head><body>",
            "<h1>MyMesh connect by carrier</h1>",
            "<p>Phone is only a scanner. It does not join the mesh.</p>",
            "<p><b>Host:</b> {label}<br/><code>{local}</code></p>",
            "<p>Paste the other device URI from <code>mymesh id --uri</code>:</p>",
            "<input id=uri style=\"width:100%;padding:8px\"/>",
            "<button onclick=\"send()\" style=\"margin-top:8px;padding:8px 16px\">Link them</button>",
            "<p id=st>ready</p>",
            "<script>",
            "async function send(){{",
            "var uri=document.getElementById('uri').value.trim();",
            "if(!uri)return;",
            "document.getElementById('st').textContent='sending';",
            "var r=await fetch('/api/peer',{{method:'POST',headers:{{'content-type':'application/json'}},body:JSON.stringify({{uri:uri}})}});",
            "var j=await r.json().catch(function(){{return {{}}}});",
            "document.getElementById('st').textContent=j.status||r.statusText;",
            "}}",
            "</script></body></html>"
        ),
        label = label,
        local = local
    );
    Html(html)
}

async fn api_status(State(st): State<CarrierState>) -> Json<StatusBody> {
    let status = st.status.lock().await.clone();
    let local_uri = device_join_uri(&st.identity().device_id()).unwrap_or_default();
    Json(StatusBody {
        status,
        local_uri,
        local_label: st.label.clone(),
    })
}

async fn api_local(State(st): State<CarrierState>) -> Json<serde_json::Value> {
    let uri = device_join_uri(&st.identity().device_id()).unwrap_or_default();
    Json(serde_json::json!({ "uri": uri, "label": st.label }))
}

async fn api_peer(
    State(st): State<CarrierState>,
    Json(body): Json<PeerBody>,
) -> Json<serde_json::Value> {
    *st.pending_peer.lock().await = Some(body.uri.clone());
    *st.status.lock().await = format!("received peer ({} bytes) - host will dial", body.uri.len());
    let _ = ArmState::arm(st.paths.arm_file(), 600);
    let path = carrier_pending_path(&st.paths);
    let _ = std::fs::write(&path, body.uri.as_bytes());
    Json(serde_json::json!({
        "status": "ok - keep page open; host completes join"
    }))
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str(concat!("&", "amp;")),
            '<' => out.push_str(concat!("&", "lt;")),
            '>' => out.push_str(concat!("&", "gt;")),
            '"' => out.push_str(concat!("&", "quot;")),
            _ => out.push(c),
        }
    }
    out
}

fn local_ipv4() -> Option<String> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("1.1.1.1:80").ok()?;
    Some(sock.local_addr().ok()?.ip().to_string())
}

pub fn carrier_pending_path(paths: &Paths) -> std::path::PathBuf {
    paths.data_dir.join("carrier-pending.txt")
}
