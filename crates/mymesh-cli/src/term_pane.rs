//! TUI embedded shell: peer picker + vt100 screen with real cursor.
use anyhow::Result;
use crossterm::event::KeyCode;
use mymesh_core::{DeviceStore, Paths, TrustState};
use mymesh_protocol::{decode_msg, encode_msg, ChannelId, Frame, TerminalMessage};
use mymesh_session::Session;
use mymesh_core::{Capability, Config};
use mymesh_crypto::Identity;
use mymesh_net::{IrohTransport, Transport};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame as TuiFrame;
use tokio::sync::mpsc;

const C_BORDER: Color = Color::Rgb(70, 70, 95);
const C_ACCENT: Color = Color::Rgb(120, 180, 255);
const C_OK: Color = Color::Rgb(100, 220, 150);
const C_MUTED: Color = Color::Rgb(130, 130, 150);
const C_TEXT: Color = Color::Rgb(230, 230, 240);
const C_BTN: Color = Color::Rgb(40, 44, 60);

pub struct TermPeer {
    pub id: String,
    pub label: String,
}

pub struct TermPane {
    pub peers: Vec<TermPeer>,
    pub peer_idx: usize,
    pub pick_peer: bool,
    pub active: bool,
    pub connected: bool,
    pub parser: vt100::Parser,
    pub cols: u16,
    pub rows: u16,
    pub scroll: u16,
    pub status_msg: String,
    pub peer_rect: Rect,
    pub screen_rect: Rect,
    pub tx_out: Option<mpsc::UnboundedSender<Vec<u8>>>,
    pub rx_in: Option<mpsc::UnboundedReceiver<Vec<u8>>>,
    pub _shutdown: Option<mpsc::Sender<()>>,
}

impl TermPane {
    pub fn new() -> Self {
        let cols = 80u16;
        let rows = 24u16;
        Self {
            peers: vec![],
            peer_idx: 0,
            pick_peer: true,
            active: false,
            connected: false,
            parser: vt100::Parser::new(rows, cols, 5000),
            cols,
            rows,
            scroll: 0,
            status_msg: "pick a system · Enter connect".into(),
            peer_rect: Rect::default(),
            screen_rect: Rect::default(),
            tx_out: None,
            rx_in: None,
            _shutdown: None,
        }
    }

    pub fn peer_id(&self) -> Option<&str> {
        self.peers.get(self.peer_idx).map(|p| p.id.as_str())
    }

    pub fn peer_title(&self) -> String {
        self.peers
            .get(self.peer_idx)
            .map(|p| {
                let short = &p.id[..8.min(p.id.len())];
                format!("{} ({short})", p.label)
            })
            .unwrap_or_else(|| "(no peers)".into())
    }

    pub fn process_output(&mut self, data: &[u8]) {
        self.parser.process(data);
    }

    pub fn send(&self, data: &[u8]) {
        if let Some(tx) = &self.tx_out {
            let _ = tx.send(data.to_vec());
        }
    }

    pub fn send_resize(&self) {
        if let Some(tx) = &self.tx_out {
            let mut v = b"__RESIZE__:".to_vec();
            v.extend_from_slice(format!("{}x{}", self.cols, self.rows).as_bytes());
            let _ = tx.send(v);
        }
    }
}

pub fn refresh_peers(paths: &Paths, term: &mut TermPane) {
    let mut peers = Vec::new();
    if let Ok(store) = DeviceStore::open(paths.devices_file()) {
        for d in store.list() {
            if d.trust == TrustState::Trusted {
                peers.push(TermPeer {
                    id: d.id.to_string(),
                    label: d.label.as_str().to_string(),
                });
            }
        }
    }
    let cur = term.peer_id().map(|s| s.to_string());
    term.peers = peers;
    if let Some(cur) = cur {
        if let Some(i) = term.peers.iter().position(|p| p.id == cur) {
            term.peer_idx = i;
        } else {
            term.peer_idx = 0;
        }
    } else if term.peer_idx >= term.peers.len() {
        term.peer_idx = 0;
    }
}

pub fn cycle_peer(paths: &Paths, term: &mut TermPane, delta: i32) {
    refresh_peers(paths, term);
    let n = term.peers.len();
    if n == 0 {
        term.status_msg = "no trusted peers".into();
        return;
    }
    if term.connected {
        disconnect(term);
    }
    let cur = term.peer_idx as i32;
    term.peer_idx = ((cur + delta).rem_euclid(n as i32)) as usize;
    term.pick_peer = true;
    term.status_msg = format!("target → {}", term.peer_title());
}

pub fn disconnect(term: &mut TermPane) {
    term.active = false;
    term.connected = false;
    term.pick_peer = true;
    term.tx_out = None;
    term.rx_in = None;
    term._shutdown = None;
    term.parser = vt100::Parser::new(term.rows, term.cols, 5000);
    term.status_msg = "disconnected".into();
}

pub async fn connect(paths: &Paths, term: &mut TermPane) -> Result<()> {
    refresh_peers(paths, term);
    let Some(peer) = term.peer_id().map(|s| s.to_string()) else {
        term.status_msg = "no peer — link devices first".into();
        return Ok(());
    };
    if term.connected {
        disconnect(term);
    }
    term.parser = vt100::Parser::new(term.rows, term.cols, 5000);
    term.status_msg = format!("connecting {}…", term.peer_title());

    let paths = paths.clone();
    let cols = term.cols;
    let rows = term.rows;
    let (tx_out, mut rx_out) = mpsc::unbounded_channel::<Vec<u8>>();
    let (tx_in, rx_in) = mpsc::unbounded_channel::<Vec<u8>>();
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

    tokio::spawn(async move {
        let err_tx = tx_in.clone();
        if let Err(e) = session_task(paths, peer, cols, rows, tx_in, &mut rx_out, &mut shutdown_rx).await
        {
            let _ = err_tx.send(format!("\r\n[session error: {e}]\r\n").into_bytes());
        }
    });

    term.tx_out = Some(tx_out);
    term.rx_in = Some(rx_in);
    term._shutdown = Some(shutdown_tx);
    term.connected = true;
    term.active = true;
    term.pick_peer = false;
    term.scroll = 0;
    term.status_msg = "connected".into();
    Ok(())
}

async fn session_task(
    paths: Paths,
    device: String,
    cols: u16,
    rows: u16,
    tx_in: mpsc::UnboundedSender<Vec<u8>>,
    rx_out: &mut mpsc::UnboundedReceiver<Vec<u8>>,
    shutdown: &mut mpsc::Receiver<()>,
) -> Result<()> {
    let identity = Identity::load_or_create(paths.identity_file())?;
    let cfg = Config::load(paths.config_file())?;
    let store = DeviceStore::open(paths.devices_file())?;
    let peer = crate::resolve_device(&store, &device)?;
    let transport = IrohTransport::bind(&identity).await?;
    let conn = transport.connect(peer).await?;
    let session = Session::handshake_dialer(
        conn,
        &identity,
        &cfg.device_label,
        &store,
        Capability::all(),
    )
    .await?;
    session
        .send_raw(
            ChannelId::terminal(1),
            encode_msg(&TerminalMessage::Open {
                cols,
                rows,
                shell: None,
                env: vec![],
            })?,
        )
        .await?;
    let conn = session.into_conn();
    loop {
        tokio::select! {
            _ = shutdown.recv() => break,
            frame = conn.recv_frame() => {
                let frame = frame?;
                if frame.channel.kind != mymesh_protocol::ChannelKind::Terminal {
                    continue;
                }
                let msg: TerminalMessage = decode_msg(&frame.payload)?;
                match msg {
                    TerminalMessage::Output(data) => { let _ = tx_in.send(data); }
                    TerminalMessage::Exit { code } => {
                        let _ = tx_in.send(format!("\r\n[exit {code}]\r\n").into_bytes());
                        break;
                    }
                    _ => {}
                }
            }
            inp = rx_out.recv() => {
                match inp {
                    Some(data) => {
                        if data.starts_with(b"__RESIZE__:") {
                            let s = String::from_utf8_lossy(&data[11..]);
                            if let Some((c, r)) = s.split_once('x') {
                                if let (Ok(c), Ok(r)) = (c.parse::<u16>(), r.parse::<u16>()) {
                                    conn.send_frame(Frame {
                                        channel: ChannelId::terminal(1),
                                        payload: encode_msg(&TerminalMessage::Resize { cols: c, rows: r })?,
                                    }).await?;
                                }
                            }
                            continue;
                        }
                        conn.send_frame(Frame {
                            channel: ChannelId::terminal(1),
                            payload: encode_msg(&TerminalMessage::Input(data))?,
                        }).await?;
                    }
                    None => break,
                }
            }
        }
    }
    let _ = conn.close().await;
    transport.shutdown().await;
    Ok(())
}

pub fn maybe_resize(term: &mut TermPane) {
    if term.screen_rect.width <= 2 || term.screen_rect.height <= 2 {
        return;
    }
    let cols = term.screen_rect.width.saturating_sub(2).max(20);
    let rows = term.screen_rect.height.saturating_sub(2).max(5);
    if cols == term.cols && rows == term.rows {
        return;
    }
    term.cols = cols;
    term.rows = rows;
    term.parser = vt100::Parser::new(rows, cols, 5000);
    if term.connected {
        term.send_resize();
    }
}

pub fn drain_output(term: &mut TermPane) {
    let mut chunks = Vec::new();
    if let Some(rx) = term.rx_in.as_mut() {
        while let Ok(chunk) = rx.try_recv() {
            chunks.push(chunk);
        }
    }
    for chunk in chunks {
        term.process_output(&chunk);
    }
}

pub fn key_to_bytes(code: KeyCode) -> Option<Vec<u8>> {
    Some(match code {
        KeyCode::Enter => b"\r".to_vec(),
        KeyCode::Backspace => vec![0x7f],
        KeyCode::Delete => b"\x1b[3~".to_vec(),
        KeyCode::Tab => b"\t".to_vec(),
        KeyCode::Up => b"\x1b[A".to_vec(),
        KeyCode::Down => b"\x1b[B".to_vec(),
        KeyCode::Right => b"\x1b[C".to_vec(),
        KeyCode::Left => b"\x1b[D".to_vec(),
        KeyCode::Home => b"\x1b[H".to_vec(),
        KeyCode::End => b"\x1b[F".to_vec(),
        KeyCode::Char(c) => c.to_string().into_bytes(),
        _ => return None,
    })
}

pub fn draw(f: &mut TuiFrame, area: Rect, term: &mut TermPane) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(2),
        ])
        .split(area);

    term.peer_rect = chunks[0];
    term.screen_rect = chunks[1];

    let peer_hot = term.pick_peer || !term.connected;
    let title = term.peer_title();
    let peer_line = format!(
        "SYSTEM  [ {title} ]  · n/[ ] cycle · click · {}",
        if term.connected {
            "connected"
        } else {
            "idle"
        }
    );
    f.render_widget(
        Paragraph::new(peer_line).style(
            Style::default()
                .fg(if peer_hot { Color::Black } else { C_TEXT })
                .bg(if peer_hot { C_ACCENT } else { C_BTN }),
        ).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(if peer_hot { C_ACCENT } else { C_BORDER }))
                .title(Span::styled(" shell target ", Style::default().fg(C_MUTED))),
        ),
        chunks[0],
    );

    let focus = term.active && !term.pick_peer;
    f.render_widget(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(if focus { C_OK } else { C_BORDER }))
            .title(Span::styled(
                format!(
                    " PTY {}×{} · {} · {} ",
                    term.cols,
                    term.rows,
                    if focus { "FOCUS" } else { "view" },
                    term.status_msg
                ),
                Style::default().fg(C_ACCENT),
            ))
            .style(Style::default().bg(Color::Black).fg(C_TEXT)),
        chunks[1],
    );

    let inner = Rect {
        x: chunks[1].x + 1,
        y: chunks[1].y + 1,
        width: chunks[1].width.saturating_sub(2),
        height: chunks[1].height.saturating_sub(2),
    };

    let screen = term.parser.screen();
    let rows = inner.height.min(term.rows);
    let cols = inner.width.min(term.cols);
    let (cx, cy) = screen.cursor_position();

    for row in 0..rows {
        let mut line = String::with_capacity(cols as usize);
        for col in 0..cols {
            let ch = screen
                .cell(row, col)
                .map(|c| {
                    let s = c.contents();
                    if s.is_empty() {
                        ' '
                    } else {
                        s.chars().next().unwrap_or(' ')
                    }
                })
                .unwrap_or(' ');
            line.push(ch);
        }
        f.render_widget(
            Paragraph::new(line).style(Style::default().fg(C_TEXT).bg(Color::Black)),
            Rect {
                x: inner.x,
                y: inner.y + row,
                width: cols,
                height: 1,
            },
        );
    }

    // cursor
    if focus && term.scroll == 0 && cy < rows && (cx as u16) < cols {
        let ch = screen
            .cell(cy, cx)
            .map(|c| {
                let s = c.contents();
                if s.is_empty() {
                    ' '
                } else {
                    s.chars().next().unwrap_or(' ')
                }
            })
            .unwrap_or(' ');
        f.render_widget(
            Paragraph::new(ch.to_string()).style(
                Style::default()
                    .fg(Color::Black)
                    .bg(C_OK)
                    .add_modifier(Modifier::BOLD),
            ),
            Rect {
                x: inner.x + cx as u16,
                y: inner.y + cy,
                width: 1,
                height: 1,
            },
        );
    }

    let hint = if term.connected {
        "Enter/i focus · arrows/keys remote · Ctrl+C to remote · Ctrl+Q detach · x disconnect"
    } else {
        "n/[ ] choose system · Enter/c connect (peer agent must run)"
    };
    f.render_widget(
        Paragraph::new(hint).style(Style::default().fg(C_MUTED)),
        chunks[2],
    );
}
