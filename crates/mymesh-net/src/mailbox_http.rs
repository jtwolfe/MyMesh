//! HTTP pairing mailbox (self-host with `mymesh mailbox`).
use crate::rendezvous::Rendezvous;
use async_trait::async_trait;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use mymesh_core::{Error, Result};
use mymesh_protocol::PairingMessage;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use tower_http::trace::TraceLayer;
use tracing::info;

#[derive(Clone)]
pub struct HttpMailbox {
    base: String,
    client: reqwest::Client,
    ttl_ms: u64,
}

impl HttpMailbox {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base: base_url.into().trim_end_matches('/').to_string(),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("reqwest client"),
            ttl_ms: 600_000,
        }
    }

    fn url(&self, code: &str, lane: &str) -> String {
        let safe: String = code
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        format!("{}/v1/box/{safe}/{lane}", self.base)
    }

    fn lane(as_host: bool, outbound: bool) -> &'static str {
        match (as_host, outbound) {
            (true, true) | (false, false) => "h2g",
            (true, false) | (false, true) => "g2h",
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    msg: PairingMessage,
}

#[async_trait]
impl Rendezvous for HttpMailbox {
    async fn send(&self, code: &str, as_host: bool, msg: PairingMessage) -> Result<()> {
        let url = self.url(code, Self::lane(as_host, true));
        let res = self
            .client
            .post(&url)
            .json(&Envelope { msg })
            .send()
            .await
            .map_err(|e| Error::Session(format!("mailbox send: {e}")))?;
        if !res.status().is_success() {
            return Err(Error::Session(format!(
                "mailbox send status {}",
                res.status()
            )));
        }
        Ok(())
    }

    async fn recv(&self, code: &str, as_host: bool) -> Result<PairingMessage> {
        let url = self.url(code, Self::lane(as_host, false));
        let deadline = Instant::now() + Duration::from_millis(self.ttl_ms);
        loop {
            if Instant::now() > deadline {
                return Err(Error::Pairing("mailbox recv timeout".into()));
            }
            let res = self
                .client
                .get(&url)
                .query(&[("wait_ms", "5000")])
                .send()
                .await
                .map_err(|e| Error::Session(format!("mailbox recv: {e}")))?;
            if res.status().as_u16() == 204 {
                continue;
            }
            if !res.status().is_success() {
                return Err(Error::Session(format!(
                    "mailbox recv status {}",
                    res.status()
                )));
            }
            let env: Envelope = res
                .json()
                .await
                .map_err(|e| Error::Protocol(e.to_string()))?;
            return Ok(env.msg);
        }
    }
}

// --- Server ---

struct Lane {
    queue: VecDeque<PairingMessage>,
    waiters: VecDeque<oneshot::Sender<PairingMessage>>,
    last: Instant,
}

impl Default for Lane {
    fn default() -> Self {
        Self {
            queue: VecDeque::new(),
            waiters: VecDeque::new(),
            last: Instant::now(),
        }
    }
}

impl Lane {
    fn push(&mut self, msg: PairingMessage) {
        self.last = Instant::now();
        if let Some(w) = self.waiters.pop_front() {
            let _ = w.send(msg);
        } else {
            self.queue.push_back(msg);
        }
    }
}

#[derive(Clone, Default)]
struct MailboxState {
    boxes: Arc<Mutex<HashMap<String, Lane>>>,
}

pub async fn run_mailbox_server(bind: SocketAddr) -> Result<()> {
    let state = MailboxState::default();
    let gc_state = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            let mut g = gc_state.boxes.lock();
            g.retain(|_, lane| lane.last.elapsed() < Duration::from_secs(900));
        }
    });

    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/box/{code}/{lane}", post(post_msg).get(get_msg))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    info!(%bind, "mymesh mailbox listening");
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(Error::Io)?;
    axum::serve(listener, app)
        .await
        .map_err(|e| Error::Session(format!("mailbox serve: {e}")))
}

async fn post_msg(
    State(state): State<MailboxState>,
    Path((code, lane)): Path<(String, String)>,
    Json(env): Json<Envelope>,
) -> std::result::Result<StatusCode, StatusCode> {
    if lane != "h2g" && lane != "g2h" {
        return Err(StatusCode::BAD_REQUEST);
    }
    let key = format!("{code}/{lane}");
    let mut g = state.boxes.lock();
    g.entry(key).or_default().push(env.msg);
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct WaitQuery {
    wait_ms: Option<u64>,
}

async fn get_msg(
    State(state): State<MailboxState>,
    Path((code, lane)): Path<(String, String)>,
    Query(q): Query<WaitQuery>,
) -> std::result::Result<Json<Envelope>, StatusCode> {
    if lane != "h2g" && lane != "g2h" {
        return Err(StatusCode::BAD_REQUEST);
    }
    let key = format!("{code}/{lane}");
    let wait_ms = q.wait_ms.unwrap_or(0).min(30_000);

    let rx = {
        let mut g = state.boxes.lock();
        let lane_ent = g.entry(key).or_default();
        if let Some(msg) = lane_ent.queue.pop_front() {
            lane_ent.last = Instant::now();
            return Ok(Json(Envelope { msg }));
        }
        if wait_ms == 0 {
            return Err(StatusCode::NO_CONTENT);
        }
        let (tx, rx) = oneshot::channel();
        lane_ent.waiters.push_back(tx);
        rx
    };

    match tokio::time::timeout(Duration::from_millis(wait_ms), rx).await {
        Ok(Ok(msg)) => Ok(Json(Envelope { msg })),
        _ => Err(StatusCode::NO_CONTENT),
    }
}
