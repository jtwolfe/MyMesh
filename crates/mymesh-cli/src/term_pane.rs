//! TUI embedded shell: peer picker + vt100 screen with real cursor.
use anyhow::Result;
use crossterm::event::KeyCode;
use mymesh_core::{Capability, Config};
use mymesh_core::{DeviceStore, Paths, TrustState};
use mymesh_crypto::Identity;
use mymesh_protocol::{decode_msg, encode_msg, ChannelId, Frame, TerminalMessage};
use mymesh_session::Session;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
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
    // Signal worker first, then drop channels so the session task exits cleanly.
    if let Some(tx) = term._shutdown.take() {
        let _ = tx.try_send(());
    }
    term.tx_out = None;
    term.rx_in = None;
    term.active = false;
    term.connected = false;
    term.pick_peer = true;
    term.scroll = 0;
    // Keep scrollback content for a moment is nice, but reset avoids a "dead" focus trap.
    term.parser = vt100::Parser::new(term.rows, term.cols, 5000);
    term.status_msg = "disconnected".into();
}

/// Call each UI tick: drain PTY output and auto-detach if the remote session ended.
pub fn poll_session(term: &mut TermPane) {
    let mut ended = false;
    let mut chunks = Vec::new();
    if let Some(rx) = term.rx_in.as_mut() {
        loop {
            match rx.try_recv() {
                Ok(chunk) => {
                    if chunk.starts_with(b"__SESSION_END__") {
                        ended = true;
                        let msg = String::from_utf8_lossy(&chunk[16..]).trim().to_string();
                        if !msg.is_empty() {
                            term.status_msg = msg;
                        } else {
                            term.status_msg = "session ended".into();
                        }
                    } else {
                        chunks.push(chunk);
                    }
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                    ended = true;
                    if term.status_msg == "connected" || term.status_msg.is_empty() {
                        term.status_msg = "session ended".into();
                    }
                    break;
                }
            }
        }
    }
    for chunk in chunks {
        term.process_output(&chunk);
    }
    if ended && term.connected {
        // Soft end: leave last screen content visible by not wiping parser first
        if let Some(tx) = term._shutdown.take() {
            let _ = tx.try_send(());
        }
        term.tx_out = None;
        term.rx_in = None;
        term.active = false;
        term.connected = false;
        term.pick_peer = true;
        term.scroll = 0;
        if !term.status_msg.contains("exit") && !term.status_msg.contains("ended") {
            term.status_msg = "session ended — pick a system to reconnect".into();
        } else if !term.status_msg.contains("reconnect") {
            term.status_msg = format!("{} · pick a system to reconnect", term.status_msg);
        }
    }
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
        match session_task(
            paths,
            peer,
            cols,
            rows,
            tx_in,
            &mut rx_out,
            &mut shutdown_rx,
        )
        .await
        {
            Ok(()) => {}
            Err(e) => {
                let _ = err_tx.send(format!("\r\n[session error: {e}]\r\n").into_bytes());
                let _ = err_tx.send(format!("__SESSION_END__error: {e}").into_bytes());
            }
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
    let sock = std::path::PathBuf::from(&cfg.daemon.control_socket);
    let (conn, transport) = mymesh_net::connect_mesh(&identity, peer, &sock).await?;
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
    #[allow(unused_assignments)]
    let mut exit_note: Option<String> = None;
    loop {
        tokio::select! {
            _ = shutdown.recv() => {
                exit_note = Some("disconnected".into());
                break;
            }
            frame = conn.recv_frame() => {
                match frame {
                    Ok(frame) => {
                        if frame.channel.kind != mymesh_protocol::ChannelKind::Terminal {
                            continue;
                        }
                        let msg: TerminalMessage = match decode_msg(&frame.payload) {
                            Ok(m) => m,
                            Err(_) => continue,
                        };
                        match msg {
                            TerminalMessage::Output(data) => { let _ = tx_in.send(data); }
                            TerminalMessage::Exit { code } => {
                                let line = format!("\r\n[remote shell exit {code}]\r\n");
                                let _ = tx_in.send(line.into_bytes());
                                exit_note = Some(format!("exit {code}"));
                                break;
                            }
                            _ => {}
                        }
                    }
                    Err(e) => {
                        // Peer closed or transport drop after shell exit — normal, not a crash.
                        let n = format!("connection closed ({e})");
                        exit_note = Some(n.clone());
                        let _ = tx_in.send(format!("
[{n}]
").into_bytes());
                        break;
                    }
                }
            }
            inp = rx_out.recv() => {
                match inp {
                    Some(data) => {
                        if data.starts_with(b"__RESIZE__:") {
                            let s = String::from_utf8_lossy(&data[11..]);
                            if let Some((c, r)) = s.split_once('x') {
                                if let (Ok(c), Ok(r)) = (c.parse::<u16>(), r.parse::<u16>()) {
                                    let _ = conn.send_frame(Frame {
                                        channel: ChannelId::terminal(1),
                                        payload: encode_msg(&TerminalMessage::Resize { cols: c, rows: r })?,
                                    }).await;
                                }
                            }
                            continue;
                        }
                        if conn.send_frame(Frame {
                            channel: ChannelId::terminal(1),
                            payload: encode_msg(&TerminalMessage::Input(data))?,
                        }).await.is_err() {
                            exit_note = Some("send failed".into());
                            break;
                        }
                    }
                    None => {
                        exit_note = Some("local closed".into());
                        break;
                    }
                }
            }
        }
    }
    let note = exit_note.unwrap_or_else(|| "session ended".into());
    let _ = tx_in.send(format!("__SESSION_END__{note}").into_bytes());
    let _ = conn.close().await;
    if let Some(tr) = transport {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), tr.shutdown()).await;
    }
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
    term.parser.set_size(rows, cols);
    if term.connected {
        term.send_resize();
    }
}

pub fn drain_output(term: &mut TermPane) {
    poll_session(term);
}

pub fn key_to_bytes(code: KeyCode, app_cursor: bool) -> Option<Vec<u8>> {
    Some(match code {
        KeyCode::Enter => b"\r".to_vec(),
        KeyCode::Backspace => vec![0x7f],
        KeyCode::Delete => b"\x1b[3~".to_vec(),
        KeyCode::Tab => b"\t".to_vec(),
        KeyCode::Up => {
            if app_cursor {
                b"\x1bOA".to_vec()
            } else {
                b"\x1b[A".to_vec()
            }
        }
        KeyCode::Down => {
            if app_cursor {
                b"\x1bOB".to_vec()
            } else {
                b"\x1b[B".to_vec()
            }
        }
        KeyCode::Right => {
            if app_cursor {
                b"\x1bOC".to_vec()
            } else {
                b"\x1b[C".to_vec()
            }
        }
        KeyCode::Left => {
            if app_cursor {
                b"\x1bOD".to_vec()
            } else {
                b"\x1b[D".to_vec()
            }
        }
        KeyCode::Home => b"\x1b[H".to_vec(),
        KeyCode::End => b"\x1b[F".to_vec(),
        KeyCode::Char(c) => c.to_string().into_bytes(),
        _ => return None,
    })
}

pub fn draw(f: &mut TuiFrame, area: Rect, term: &mut TermPane) {
    f.render_widget(Clear, area);
    f.render_widget(
        Block::default().style(Style::default().bg(Color::Rgb(18, 18, 24))),
        area,
    );

    if area.height < 6 || area.width < 20 {
        f.render_widget(
            Paragraph::new("terminal too small").style(Style::default().fg(C_MUTED)),
            area,
        );
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(1),
        ])
        .split(area);

    term.peer_rect = chunks[0];
    term.screen_rect = chunks[1];

    // Sync VT size to the actual inner pane *before* painting cells.
    let inner_w = chunks[1].width.saturating_sub(2);
    let inner_h = chunks[1].height.saturating_sub(2);
    if inner_w >= 20 && inner_h >= 5 {
        let cols = inner_w;
        let rows = inner_h;
        if cols != term.cols || rows != term.rows {
            term.cols = cols;
            term.rows = rows;
            term.parser.set_size(rows, cols);
            if term.connected {
                term.send_resize();
            }
        }
    }

    let peer_hot = term.pick_peer || !term.connected;
    let title = term.peer_title();
    let peer_line = format!(
        " SYSTEM  [ {title} ]   n/[ ] cycle · click   {}",
        if term.connected { "connected" } else { "idle" }
    );
    f.render_widget(
        Paragraph::new(peer_line)
            .style(
                Style::default()
                    .fg(if peer_hot { Color::Black } else { C_TEXT })
                    .bg(if peer_hot { C_ACCENT } else { C_BTN }),
            )
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(if peer_hot { C_ACCENT } else { C_BORDER }))
                    .title(Span::styled(" shell target ", Style::default().fg(C_MUTED)))
                    .style(Style::default().bg(C_BTN)),
            ),
        chunks[0],
    );

    let focus = term.active && !term.pick_peer;
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if focus { C_OK } else { C_BORDER }))
        .title(Span::styled(
            format!(
                " PTY {}x{} · {} · {} ",
                term.cols,
                term.rows,
                if focus { "FOCUS" } else { "view" },
                term.status_msg
            ),
            Style::default().fg(C_ACCENT),
        ))
        .style(Style::default().bg(Color::Black).fg(C_TEXT));
    let inner = block.inner(chunks[1]);
    f.render_widget(block, chunks[1]);
    // Fill entire inner with black spaces so wide terminals never show ghosts.
    if inner.width > 0 && inner.height > 0 {
        let blank = " ".repeat(inner.width as usize);
        for row in 0..inner.height {
            f.render_widget(
                Paragraph::new(blank.as_str()).style(Style::default().bg(Color::Black).fg(C_TEXT)),
                Rect {
                    x: inner.x,
                    y: inner.y + row,
                    width: inner.width,
                    height: 1,
                },
            );
        }
    }

    let screen = term.parser.screen();
    let rows = inner.height.min(term.rows);
    let cols = inner.width.min(term.cols);
    let (cursor_row, cursor_col) = screen.cursor_position();

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
                        // Keep single-width; drop combining/wide leftovers
                        let ch = s.chars().next().unwrap_or(' ');
                        if ch.is_control() {
                            ' '
                        } else {
                            ch
                        }
                    }
                })
                .unwrap_or(' ');
            line.push(ch);
        }
        // Pad to full row width so partial cells don't leave debris
        while line.chars().count() < cols as usize {
            line.push(' ');
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

    let show_cursor = focus
        && term.scroll == 0
        && !screen.hide_cursor()
        && cursor_row < rows
        && cursor_col < cols;
    if show_cursor {
        let ch = screen
            .cell(cursor_row, cursor_col)
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
                x: inner.x + cursor_col,
                y: inner.y + cursor_row,
                width: 1,
                height: 1,
            },
        );
    }

    let hint = if term.connected {
        " Enter/i focus · keys remote · Ctrl+C remote · Ctrl+Q detach · x disconnect"
    } else {
        " n/[ ] choose system · Enter/c connect (peer agent must run)"
    };
    f.render_widget(
        Paragraph::new(hint).style(Style::default().fg(C_MUTED).bg(Color::Rgb(18, 18, 24))),
        chunks[2],
    );
}
