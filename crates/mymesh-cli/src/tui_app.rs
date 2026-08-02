//! Polished MyMesh TUI — button bar, mouse hit-testing, file browser, terminal, metrics.
use anyhow::Result;
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers,
    MouseButton, MouseEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use mymesh_core::{ArmState, Config, DeviceStore, JoinStore, MeshState, Paths, PeerMetrics, PendingKickStore};
use mymesh_crypto::{device_id_to_words, device_join_uri, Identity};
use mymesh_protocol::FileEntry;
use qrcode::QrCode;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap};
use ratatui::{Frame as TuiFrame, Terminal};
use std::io::{self, Stdout};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use crate::term_pane::{self, TermPane};
use tokio::sync::mpsc;

// ─── theme ───────────────────────────────────────────────────────────
const C_BG: Color = Color::Rgb(18, 18, 24);
const C_PANEL: Color = Color::Rgb(28, 28, 38);
const C_BORDER: Color = Color::Rgb(70, 70, 95);
const C_ACCENT: Color = Color::Rgb(120, 180, 255);
const C_ACCENT2: Color = Color::Rgb(160, 120, 255);
const C_OK: Color = Color::Rgb(100, 220, 150);
const C_WARN: Color = Color::Rgb(240, 190, 80);
#[allow(dead_code)]
const C_ERR: Color = Color::Rgb(240, 100, 110);
const C_MUTED: Color = Color::Rgb(130, 130, 150);
const C_TEXT: Color = Color::Rgb(230, 230, 240);
const C_BTN: Color = Color::Rgb(40, 44, 60);
const C_BTN_HOT: Color = Color::Rgb(70, 100, 180);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Home,
    Peers,
    Files,
    Term,
    Status,
}

impl Tab {
    const ALL: [Tab; 5] = [Tab::Home, Tab::Peers, Tab::Files, Tab::Term, Tab::Status];
    fn title(self) -> &'static str {
        match self {
            Tab::Home => " Home ",
            Tab::Peers => " Peers ",
            Tab::Files => " Files ",
            Tab::Term => " Term ",
            Tab::Status => " Status ",
        }
    }
    fn key(self) -> char {
        match self {
            Tab::Home => '1',
            Tab::Peers => '2',
            Tab::Files => '3',
            Tab::Term => '4',
            Tab::Status => '5',
        }
    }
    fn idx(self) -> usize {
        Self::ALL.iter().position(|t| *t == self).unwrap()
    }
}

#[derive(Clone)]
struct Btn {
    id: &'static str,
    rect: Rect,
}

#[derive(Clone)]
struct LocalEntry {
    name: String,
    path: PathBuf,
    is_dir: bool,
    size: u64,
}

/// A selectable endpoint in the dual file browser (local machine or mesh peer).
#[derive(Clone, Debug)]
enum BrowserNode {
    Local,
    Peer { id: String, label: String },
}

impl BrowserNode {
    fn title(&self) -> String {
        match self {
            BrowserNode::Local => "Local".into(),
            BrowserNode::Peer { label, id } => format!("{label} ({})", &id[..8.min(id.len())]),
        }
    }
    fn id_key(&self) -> String {
        match self {
            BrowserNode::Local => "local".into(),
            BrowserNode::Peer { id, .. } => id.clone(),
        }
    }
}

#[derive(Clone, Debug)]
struct BrowserEntry {
    name: String,
    /// Absolute/local path or remote relative path
    path: String,
    is_dir: bool,
    size: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FilesFocus {
    SrcNode,
    DstNode,
    SrcList,
    DstList,
}

/// Result of a background pane listing (never applied on the UI task's await).
enum PaneListResult {
    Src {
        gen: u64,
        entries: Result<Vec<BrowserEntry>, String>,
    },
    Dst {
        gen: u64,
        entries: Result<Vec<BrowserEntry>, String>,
    },
}

struct FileBrowser {
    nodes: Vec<BrowserNode>,
    src_node: usize,
    dst_node: usize,
    src_cwd: String,
    dst_cwd: String,
    src: Vec<BrowserEntry>,
    dst: Vec<BrowserEntry>,
    focus: FilesFocus,
    src_sel: usize,
    dst_sel: usize,
    src_scroll: usize,
    dst_scroll: usize,
    /// Selected paths per side: "src:path" / "dst:path"
    selected: std::collections::HashSet<String>,
    busy_src: String,
    busy_dst: String,
    /// Generation bumped on node/cwd change; stale bg results are dropped.
    refresh_gen: u64,
    last_remote_src: Instant,
    last_remote_dst: Instant,
    src_inflight: bool,
    dst_inflight: bool,
    list_tx: mpsc::UnboundedSender<PaneListResult>,
    list_rx: mpsc::UnboundedReceiver<PaneListResult>,
    /// Hit-test rects (updated each draw)
    src_list_rect: Rect,
    dst_list_rect: Rect,
    src_node_rect: Rect,
    dst_node_rect: Rect,
}

struct PeerPoll {
    enabled: bool,
    started: Instant,
    last: Instant,
    interval: Duration,
    max_duration: Duration,
}

#[derive(Clone, Default)]
struct KickWizard {
    active: bool,
    force: bool,
    step: u8, // 0 type KICK FROM MESH, 1 type I AM SURE
    buf: String,
    target: Option<String>,
    target_label: String,
}

struct App {
    paths: Paths,
    tab: Tab,
    peer_sel: usize,
    status: String,
    should_quit: bool,
    tab_rects: Vec<(Tab, Rect)>,
    buttons: Vec<Btn>,
    content: Rect,
    files: FileBrowser,
    term: TermPane,
    poll: PeerPoll,
    kick: KickWizard,
    /// Last *applied* terminal size (backend buffer).
    term_size: (u16, u16),
    /// Most recent size observed from the OS (may be mid-animation).
    pending_size: Option<(u16, u16)>,
    /// When pending_size last changed — used to debounce Hyprland fullscreen storms.
    pending_since: Option<Instant>,
}

pub async fn run_tui(paths: Paths) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let home = dirs_home();
    let mut app = App {
        paths: paths.clone(),
        tab: Tab::Home,
        peer_sel: 0,
        status: "mouse · buttons · keys in [brackets] · Ctrl+C / q quit".into(),
        should_quit: false,
        tab_rects: vec![],
        buttons: vec![],
        content: Rect::default(),
        files: {
            let (list_tx, list_rx) = mpsc::unbounded_channel();
            FileBrowser {
                nodes: load_nodes(&paths),
                src_node: 0,
                dst_node: 0,
                src_cwd: home.display().to_string(),
                dst_cwd: home.display().to_string(),
                src: local_to_browser(&list_local(&home)),
                dst: local_to_browser(&list_local(&home)),
                focus: FilesFocus::SrcList,
                src_sel: 0,
                dst_sel: 0,
                src_scroll: 0,
                dst_scroll: 0,
                selected: std::collections::HashSet::new(),
                busy_src: String::new(),
                busy_dst: String::new(),
                refresh_gen: 1,
                last_remote_src: Instant::now() - Duration::from_secs(100),
                last_remote_dst: Instant::now() - Duration::from_secs(100),
                src_inflight: false,
                dst_inflight: false,
                list_tx,
                list_rx,
                src_list_rect: Rect::default(),
                dst_list_rect: Rect::default(),
                src_node_rect: Rect::default(),
                dst_node_rect: Rect::default(),
            }
        },
        term: TermPane::new(),
        poll: PeerPoll {
            enabled: false,
            started: Instant::now(),
            last: Instant::now() - Duration::from_secs(100),
            interval: Duration::from_secs(10),
            max_duration: Duration::from_secs(300),
        },
        kick: KickWizard::default(),
        term_size: (0, 0),
        pending_size: None,
        pending_since: None,
    };

    let res = run_loop(&mut terminal, &mut app).await;

    app.term.active = false;
    app.term.connected = false;
    app.term.tx_out = None;
    app.term.rx_in = None;

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    res
}

fn dirs_home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

fn list_local(dir: &Path) -> Vec<LocalEntry> {
    let mut v = Vec::new();
    if let Some(parent) = dir.parent() {
        v.push(LocalEntry {
            name: "..".into(),
            path: parent.to_path_buf(),
            is_dir: true,
            size: 0,
        });
    }
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let md = e.metadata().ok()?;
            Some(LocalEntry {
                name: e.file_name().to_string_lossy().into(),
                path: e.path(),
                is_dir: md.is_dir(),
                size: md.len(),
            })
        })
        .collect();
    entries.sort_by(|a, b| match (a.is_dir, b.is_dir) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
    });
    v.extend(entries);
    v
}

fn local_to_browser(entries: &[LocalEntry]) -> Vec<BrowserEntry> {
    entries
        .iter()
        .map(|e| BrowserEntry {
            name: e.name.clone(),
            path: e.path.display().to_string(),
            is_dir: e.is_dir,
            size: e.size,
        })
        .collect()
}

fn remote_to_browser(entries: &[FileEntry]) -> Vec<BrowserEntry> {
    entries
        .iter()
        .map(|e| BrowserEntry {
            name: e.name.clone(),
            path: e.path.clone(),
            is_dir: e.is_dir,
            size: e.size,
        })
        .collect()
}

fn ensure_visible(sel: usize, scroll: &mut usize, view_h: usize) {
    if view_h == 0 {
        return;
    }
    if sel < *scroll {
        *scroll = sel;
    } else if sel >= *scroll + view_h {
        *scroll = sel + 1 - view_h;
    }
}

fn load_nodes(paths: &Paths) -> Vec<BrowserNode> {
    let mut nodes = vec![BrowserNode::Local];
    if let Ok(store) = DeviceStore::open(paths.devices_file()) {
        for d in store.list() {
            if matches!(d.trust, mymesh_core::TrustState::Trusted) {
                nodes.push(BrowserNode::Peer {
                    id: d.id.to_string(),
                    label: d.label.as_str().to_string(),
                });
            }
        }
    }
    nodes
}

fn node_cwd_default(node: &BrowserNode, home: &Path) -> String {
    match node {
        BrowserNode::Local => home.display().to_string(),
        BrowserNode::Peer { .. } => ".".into(),
    }
}

// ─── QR: half-block unicode (correct aspect for terminals) ───────────
fn qr_half_block_lines(data: &str) -> Vec<String> {
    let Ok(code) = QrCode::new(data.as_bytes()) else {
        return vec!["(qr encode failed)".into()];
    };
    let w = code.width();
    let quiet = 2usize;
    let dim = w + quiet * 2;
    let mut modules = vec![vec![false; dim]; dim];
    for y in 0..w {
        for x in 0..w {
            modules[y + quiet][x + quiet] = code[(x, y)] == qrcode::Color::Dark;
        }
    }
    // pad height to even
    if modules.len() % 2 == 1 {
        modules.push(vec![false; dim]);
    }
    let mut lines = Vec::new();
    let mut y = 0;
    while y < modules.len() {
        let mut row = String::new();
        for x in 0..dim {
            let top = modules[y][x];
            let bot = modules.get(y + 1).map(|r| r[x]).unwrap_or(false);
            let ch = match (top, bot) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            };
            row.push(ch);
        }
        lines.push(row);
        y += 2;
    }
    lines
}

fn human_bytes(n: u64) -> String {
    const U: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} {}", U[i])
    } else {
        format!("{v:.1} {}", U[i])
    }
}

fn bar_ratio(used: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        (used as f64 / total as f64).clamp(0.0, 1.0)
    }
}


/// Record a size observation. Resets the debounce clock when size changes.
fn note_pending_size(app: &mut App, w: u16, h: u16) {
    if w == 0 || h == 0 {
        return;
    }
    match app.pending_size {
        Some(prev) if prev == (w, h) => {}
        _ => {
            app.pending_size = Some((w, h));
            app.pending_since = Some(Instant::now());
        }
    }
}

/// After ~120ms of a stable size (and it differs from the applied buffer),
/// autoresize once and hard-clear. Avoids mid-animation corruption.
fn try_apply_settled_resize(
    terminal: &mut Terminal<ratatui::backend::CrosstermBackend<Stdout>>,
    app: &mut App,
) -> Result<()> {
    const SETTLE: Duration = Duration::from_millis(120);
    let Some(pending) = app.pending_size else {
        return Ok(());
    };
    let Some(since) = app.pending_since else {
        return Ok(());
    };
    if since.elapsed() < SETTLE {
        return Ok(());
    }
    // Re-check OS size — if still moving, keep waiting.
    if let Ok((w, h)) = crossterm::terminal::size() {
        if (w, h) != pending {
            note_pending_size(app, w, h);
            return Ok(());
        }
    }
    if app.term_size == pending {
        app.pending_size = None;
        app.pending_since = None;
        return Ok(());
    }
    app.term_size = pending;
    app.pending_size = None;
    app.pending_since = None;
    let _ = terminal.autoresize();
    // One clean slate after settle — not on every intermediate frame.
    let _ = terminal.clear();
    Ok(())
}

// ─── main loop ───────────────────────────────────────────────────────
async fn run_loop(
    terminal: &mut Terminal<ratatui::backend::CrosstermBackend<Stdout>>,
    app: &mut App,
) -> Result<()> {
    loop {
        // drain terminal VT output (non-blocking)
        term_pane::drain_output(&mut app.term);
        if app.tab == Tab::Term {
            term_pane::refresh_peers(&app.paths, &mut app.term);
            term_pane::maybe_resize(&mut app.term);
        }

        if app.poll.enabled && app.poll.started.elapsed() > app.poll.max_duration {
            app.poll.enabled = false;
            app.status = "metrics poll auto-stopped (5m remote window)".into();
        }

        // Files: non-blocking — apply bg results + schedule peer lists off the UI task
        if app.tab == Tab::Files {
            app.files.nodes = load_nodes(&app.paths);
            if app.files.src_node >= app.files.nodes.len() {
                app.files.src_node = 0;
            }
            if app.files.dst_node >= app.files.nodes.len() {
                app.files.dst_node = 0;
            }
            drain_file_list_results(app);
            // local panes: cheap sync refresh; peers: background every 5s
            schedule_file_refresh(app, false);
        }

        // Metrics poll also off UI thread
        if app.poll.enabled
            && app.poll.started.elapsed() <= app.poll.max_duration
            && app.poll.last.elapsed() >= app.poll.interval
        {
            if let Some(id) = selected_peer_id(app) {
                app.poll.last = Instant::now();
                let paths = app.paths.clone();
                let id = id.clone();
                tokio::spawn(async move {
                    let _ = crate::probe::probe_host_metrics(&paths, &id).await;
                });
            }
        }

        // Hyprland fullscreen (and similar WMs) emit a storm of intermediate
        // sizes. Applying clear/autoresize on every step desyncs the backend
        // buffer and produces jumbled chrome. Debounce until size settles.
        if let Ok((w, h)) = crossterm::terminal::size() {
            note_pending_size(app, w, h);
        }
        try_apply_settled_resize(terminal, app)?;

        terminal.draw(|f| ui(f, app))?;
        if app.should_quit {
            break;
        }

        if event::poll(Duration::from_millis(80))? {
            match event::read()? {
                Event::Key(k) if k.kind == KeyEventKind::Press => {
                    // Ctrl+C quits only when NOT focused in remote shell
                    let shell_focus = app.tab == Tab::Term && app.term.active && !app.term.pick_peer;
                    if k.modifiers.contains(KeyModifiers::CONTROL)
                        && matches!(k.code, KeyCode::Char('c') | KeyCode::Char('C'))
                        && !shell_focus
                    {
                        app.should_quit = true;
                        continue;
                    }
                    handle_key(app, k.code, k.modifiers).await;
                }
                Event::Mouse(m) => {
                    if matches!(m.kind, MouseEventKind::Down(MouseButton::Left)) {
                        handle_click(app, m.column, m.row).await;
                    }
                    if matches!(m.kind, MouseEventKind::ScrollDown | MouseEventKind::ScrollUp) {
                        let up = matches!(m.kind, MouseEventKind::ScrollUp);
                        if app.tab == Tab::Files {
                            handle_files_scroll(app, m.column, m.row, up);
                        } else if app.tab == Tab::Term {
                            if up {
                                app.term.scroll = app.term.scroll.saturating_add(3);
                            } else {
                                app.term.scroll = app.term.scroll.saturating_sub(3);
                            }
                        }
                    }
                }
                Event::Resize(w, h) => {
                    // Only record — apply after debounce settle.
                    note_pending_size(app, w, h);
                }
                _ => {}
            }
        }
    }
    Ok(())
}

async fn handle_key(app: &mut App, code: KeyCode, mods: KeyModifiers) {
    // global tab keys
    match code {
        KeyCode::Char('q') | KeyCode::Esc if app.tab != Tab::Term || !app.term.active => {
            if app.tab == Tab::Term && app.term.active && code == KeyCode::Esc {
                // detach term input mode
                app.term.active = false;
                app.status = "terminal detached (session may still run until reconnect)".into();
                return;
            }
            app.should_quit = true;
            return;
        }
        KeyCode::Char('1') if !mods.contains(KeyModifiers::CONTROL) && !(app.tab == Tab::Term && app.term.active) => {
            app.tab = Tab::Home;
            return;
        }
        KeyCode::Char('2') if !(app.tab == Tab::Term && app.term.active) => {
            app.tab = Tab::Peers;
            return;
        }
        KeyCode::Char('3') if !(app.tab == Tab::Term && app.term.active) => {
            app.tab = Tab::Files;
            return;
        }
        KeyCode::Char('4') if !(app.tab == Tab::Term && app.term.active) => {
            app.tab = Tab::Term;
            return;
        }
        KeyCode::Char('5') if !(app.tab == Tab::Term && app.term.active) => {
            app.tab = Tab::Status;
            return;
        }
        KeyCode::Tab if !(app.tab == Tab::Term && app.term.active) => {
            app.tab = Tab::ALL[(app.tab.idx() + 1) % Tab::ALL.len()];
            return;
        }
        KeyCode::BackTab => {
            app.tab = Tab::ALL[(app.tab.idx() + Tab::ALL.len() - 1) % Tab::ALL.len()];
            return;
        }
        _ => {}
    }

    // terminal input mode — ANSI to remote PTY
    if app.tab == Tab::Term && app.term.active && !app.term.pick_peer {
        use crossterm::event::KeyModifiers as KM;
        if mods.contains(KM::CONTROL) {
            match code {
                KeyCode::Char('q') | KeyCode::Char('Q') => {
                    app.term.active = false;
                    app.term.pick_peer = true;
                    app.status = "detached shell (Ctrl+Q)".into();
                    return;
                }
                KeyCode::Char('c') | KeyCode::Char('C') => {
                    app.term.send(&[0x03]);
                    return;
                }
                KeyCode::Char('d') | KeyCode::Char('D') => {
                    app.term.send(&[0x04]);
                    return;
                }
                KeyCode::Char('z') | KeyCode::Char('Z') => {
                    app.term.send(&[0x1a]);
                    return;
                }
                KeyCode::Char(c) => {
                    let b = (c.to_ascii_lowercase() as u8).wrapping_sub(b'a').wrapping_add(1);
                    if (1..=26).contains(&b) {
                        app.term.send(&[b]);
                    }
                    return;
                }
                _ => {}
            }
        }
        match code {
            KeyCode::Esc => {
                app.term.active = false;
                app.term.pick_peer = true;
                app.status = "left shell input".into();
            }
            KeyCode::PageUp => {
                app.term.scroll = app.term.scroll.saturating_add(app.term.rows / 2);
            }
            KeyCode::PageDown => {
                app.term.scroll = app.term.scroll.saturating_sub(app.term.rows / 2);
            }
            other => {
                if let Some(bytes) = term_pane::key_to_bytes(other, app.term.parser.screen().application_cursor()) {
                    app.term.send(&bytes);
                    app.term.scroll = 0;
                }
            }
        }
        return;
    }


    match app.tab {
        Tab::Home => match code {
            KeyCode::Char('a') => arm(app),
            KeyCode::Char('d') => disarm(app),
            KeyCode::Char('y') => accept_first(app),
            KeyCode::Char('c') => copy_id(app),
            _ => {}
        },
        Tab::Peers => {
          if app.kick.active {
            match code {
                KeyCode::Esc => {
                    app.kick = KickWizard::default();
                    app.status = "kick cancelled".into();
                }
                KeyCode::Char(c) => {
                    app.kick.buf.push(c);
                    app.status = format!("confirm: {}", app.kick.buf);
                }
                KeyCode::Backspace => { app.kick.buf.pop(); }
                KeyCode::Enter => {
                    let need = if app.kick.step == 0 { "KICK FROM MESH" } else { "I AM SURE" };
                    if app.kick.buf.trim() == need {
                        if app.kick.step == 0 {
                            app.kick.step = 1;
                            app.kick.buf.clear();
                            app.status = "type I AM SURE then Enter".into();
                        } else {
                            let force = app.kick.force;
                            let tgt = app.kick.target.clone();
                            app.kick = KickWizard::default();
                            if let Some(id) = tgt {
                                app.status = "kicking…".into();
                                match run_kick(&app.paths, &id, force).await {
                                    Ok(msg) => app.status = msg,
                                    Err(e) => app.status = format!("kick: {e}"),
                                }
                            }
                        }
                    } else {
                        app.status = format!("expected exactly `{need}`");
                        app.kick.buf.clear();
                    }
                }
                _ => {}
            }
            return;
          }
          match code {
            KeyCode::Down | KeyCode::Char('j') => {
                app.peer_sel = app.peer_sel.saturating_add(1);
            }
            KeyCode::Up | KeyCode::Char('k') => {
                app.peer_sel = app.peer_sel.saturating_sub(1);
            }
            KeyCode::Enter | KeyCode::Char('o') => {
                if let Some(id) = selected_peer_id(app) {
                    term_pane::refresh_peers(&app.paths, &mut app.term);
                    if let Some(i) = app.term.peers.iter().position(|p| p.id == id) {
                        app.term.peer_idx = i;
                    }
                    if let Some(idx) = app.files.nodes.iter().position(|n| match n {
                        BrowserNode::Peer { id: pid, .. } => pid == &id,
                        _ => false,
                    }) {
                        app.files.dst_node = idx;
                    }
                    app.status = format!("peer {id} · use Term tab for shell");
                }
            }
            KeyCode::Char('p') => ping_sel(app).await,
            KeyCode::Char('b') => bw_sel(app).await,
            KeyCode::Char('m') => metrics_sel(app).await,
            KeyCode::Char('t') => {
                app.poll.enabled = !app.poll.enabled;
                if app.poll.enabled {
                    app.poll.started = Instant::now();
                    app.poll.last = Instant::now() - app.poll.interval;
                    app.status =
                        "metrics poll ON · 10s interval · auto-off 5m (client; host answers each request)"
                            .into();
                } else {
                    app.status = "metrics poll OFF".into();
                }
            }
            KeyCode::Char('g') => {
                app.status = "mesh sync…".into();
                match mesh_sync_all(&app.paths).await {
                    Ok(n) => app.status = format!("mesh sync ok (+{n})"),
                    Err(e) => app.status = format!("sync: {e}"),
                }
            }
            KeyCode::Char('K') => start_kick_wizard(app, false),
            KeyCode::Char('F') => start_kick_wizard(app, true),
            _ => {}
          }
        }
        Tab::Files => match code {
            KeyCode::Down | KeyCode::Char('j') => files_move_sel(app, 1),
            KeyCode::Up | KeyCode::Char('k') => files_move_sel(app, -1),
            KeyCode::Left | KeyCode::Char('h') => {
                app.files.focus = FilesFocus::SrcList;
            }
            KeyCode::Right | KeyCode::Char('l') => {
                app.files.focus = FilesFocus::DstList;
            }
            KeyCode::Tab => {
                app.files.focus = match app.files.focus {
                    FilesFocus::SrcList => FilesFocus::DstList,
                    FilesFocus::DstList => FilesFocus::SrcNode,
                    FilesFocus::SrcNode => FilesFocus::DstNode,
                    FilesFocus::DstNode => FilesFocus::SrcList,
                };
            }
            KeyCode::Char('[') => {
                cycle_node(app, true, -1);
                kick_file_refresh(app, true);
            }
            KeyCode::Char(']') => {
                cycle_node(app, true, 1);
                kick_file_refresh(app, true);
            }
            KeyCode::Char('{') => {
                cycle_node(app, false, -1);
                kick_file_refresh(app, true);
            }
            KeyCode::Char('}') => {
                cycle_node(app, false, 1);
                kick_file_refresh(app, true);
            }
            KeyCode::Char('n') => {
                app.files.focus = FilesFocus::SrcNode;
                cycle_node(app, true, 1);
                kick_file_refresh(app, true);
            }
            KeyCode::Char('N') => {
                app.files.focus = FilesFocus::DstNode;
                cycle_node(app, false, 1);
                kick_file_refresh(app, true);
            }
            KeyCode::Char(' ') => toggle_select(app),
            KeyCode::Enter => enter_file(app).await,
            KeyCode::Char('c') | KeyCode::Char('C') => transfer_selected(app).await,
            KeyCode::Char('x') => {
                app.files.selected.clear();
                app.status = "selection cleared".into();
            }
            KeyCode::Char('r') => {
                kick_file_refresh(app, true);
            }
            KeyCode::Backspace | KeyCode::Char('u') => files_go_up(app).await,
            _ => {}
        },
        Tab::Term => match code {
            KeyCode::Char('n') | KeyCode::Char('[') => {
                term_pane::cycle_peer(&app.paths, &mut app.term, -1);
                app.status = app.term.status_msg.clone();
            }
            KeyCode::Char('N') | KeyCode::Char(']') => {
                term_pane::cycle_peer(&app.paths, &mut app.term, 1);
                app.status = app.term.status_msg.clone();
            }
            KeyCode::Left | KeyCode::Char('h') if app.term.pick_peer => {
                term_pane::cycle_peer(&app.paths, &mut app.term, -1);
                app.status = app.term.status_msg.clone();
            }
            KeyCode::Right | KeyCode::Char('l') if app.term.pick_peer => {
                term_pane::cycle_peer(&app.paths, &mut app.term, 1);
                app.status = app.term.status_msg.clone();
            }
            KeyCode::Enter => {
                if !app.term.connected {
                    let _ = term_pane::connect(&app.paths, &mut app.term).await;
                    app.status = app.term.status_msg.clone();
                } else {
                    app.term.pick_peer = false;
                    app.term.active = true;
                    app.term.scroll = 0;
                    app.status = "shell focus · Ctrl+Q detach".into();
                }
            }
            KeyCode::Char('i') | KeyCode::Char('c') => {
                if app.term.connected {
                    app.term.pick_peer = false;
                    app.term.active = true;
                    app.term.scroll = 0;
                    app.status = "shell focus".into();
                } else {
                    let _ = term_pane::connect(&app.paths, &mut app.term).await;
                    app.status = app.term.status_msg.clone();
                }
            }
            KeyCode::Char('x') => {
                term_pane::disconnect(&mut app.term);
                app.status = "shell disconnected".into();
            }
            _ => {}
        },
        Tab::Status => match code {
            KeyCode::Char('s') => {
                let _ = crate::install::cmd_service("start", false);
                app.status = "service start requested".into();
            }
            KeyCode::Char('x') => {
                let _ = crate::install::cmd_service("stop", false);
                app.status = "service stop requested".into();
            }
            KeyCode::Char('r') => {
                let _ = crate::install::cmd_service("restart", false);
                app.status = "service restart requested".into();
            }
            _ => {}
        },
    }
}

async fn handle_click(app: &mut App, col: u16, row: u16) {
    // tabs
    for (tab, r) in &app.tab_rects {
        if rect_contains(*r, col, row) {
            app.tab = *tab;
            app.status = format!("tab {}", tab.title().trim());
            return;
        }
    }
    // buttons
    let hit = app
        .buttons
        .iter()
        .find(|b| rect_contains(b.rect, col, row))
        .map(|b| b.id);
    if let Some(id) = hit {
        click_button(app, id).await;
        return;
    }
    if app.tab == Tab::Files {
        handle_files_click(app, col, row).await;
    }
    if app.tab == Tab::Term {
        if rect_contains(app.term.peer_rect, col, row) {
            term_pane::cycle_peer(&app.paths, &mut app.term, 1);
            app.status = app.term.status_msg.clone();
        } else if rect_contains(app.term.screen_rect, col, row) && app.term.connected {
            app.term.pick_peer = false;
            app.term.active = true;
            app.term.scroll = 0;
        }
    }
}

fn rect_contains(r: Rect, col: u16, row: u16) -> bool {
    col >= r.x && col < r.x.saturating_add(r.width) && row >= r.y && row < r.y.saturating_add(r.height)
}

async fn click_button(app: &mut App, id: &str) {
    match id {
        "arm" => arm(app),
        "disarm" => disarm(app),
        "accept" => accept_first(app),
        "copy_id" => copy_id(app),
        "ping" => ping_sel(app).await,
        "bw" => bw_sel(app).await,
        "metrics" => metrics_sel(app).await,
        "poll" => {
            app.poll.enabled = !app.poll.enabled;
            if app.poll.enabled {
                app.poll.started = Instant::now();
                app.poll.last = Instant::now() - app.poll.interval;
            }
            app.status = if app.poll.enabled {
                "metrics poll ON (10s / 5m)".into()
            } else {
                "metrics poll OFF".into()
            };
        }
        "mesh_sync" => {
            app.status = "mesh sync…".into();
            match mesh_sync_all(&app.paths).await {
                Ok(n) => app.status = format!("mesh sync ok (+{n} members)"),
                Err(e) => app.status = format!("mesh sync: {e}"),
            }
        }
        "kick" => start_kick_wizard(app, false),
        "force_kick" => start_kick_wizard(app, true),
        "copy_lr" => transfer_selected(app).await,
        "clear_sel" => {
            app.files.selected.clear();
            app.status = "selection cleared".into();
        }
        "src_node" => {
            app.files.focus = FilesFocus::SrcNode;
            cycle_node(app, true, 1);
            kick_file_refresh(app, true);
        }
        "dst_node" => {
            app.files.focus = FilesFocus::DstNode;
            cycle_node(app, false, 1);
            kick_file_refresh(app, true);
        }
        "term_peer" => {
            term_pane::cycle_peer(&app.paths, &mut app.term, 1);
            app.status = app.term.status_msg.clone();
        }
        "term_connect" => {
            let _ = term_pane::connect(&app.paths, &mut app.term).await;
            app.status = app.term.status_msg.clone();
        }
        "term_input" => {
            if app.term.connected {
                app.term.pick_peer = false;
                app.term.active = true;
                app.term.scroll = 0;
            } else {
                let _ = term_pane::connect(&app.paths, &mut app.term).await;
            }
            app.status = app.term.status_msg.clone();
        }
        "term_disc" => {
            term_pane::disconnect(&mut app.term);
            app.status = "shell disconnected".into();
        }
        "svc_start" => {
            let _ = crate::install::cmd_service("start", false);
        }
        "svc_stop" => {
            let _ = crate::install::cmd_service("stop", false);
        }
        "svc_restart" => {
            let _ = crate::install::cmd_service("restart", false);
        }
        "quit" => app.should_quit = true,
        _ => {}
    }
}

fn arm(app: &mut App) {
    let cfg = Config::load(app.paths.config_file()).unwrap_or_default();
    match ArmState::arm(app.paths.arm_file(), cfg.limits.arm_timeout_secs) {
        Ok(s) => app.status = format!("ARMED until {:?}", s.until),
        Err(e) => app.status = format!("arm failed: {e}"),
    }
}
fn disarm(app: &mut App) {
    let _ = ArmState::disarm(app.paths.arm_file());
    app.status = "disarmed".into();
}
fn accept_first(app: &mut App) {
    if let Ok(joins) = JoinStore::open(app.paths.join_dir()) {
        if let Ok(list) = joins.list_pending() {
            if let Some(p) = list.first() {
                let _ = joins.write_decision(&p.device_id, mymesh_core::JoinDecision::Accept);
                app.status = format!("accepted {}", p.device_id.short());
            } else {
                app.status = "no pending".into();
            }
        }
    }
}
fn copy_id(app: &mut App) {
    if let Ok(id) = Identity::load_or_create(app.paths.identity_file()) {
        app.status = format!("id {}", id.device_id());
    }
}

async fn ping_sel(app: &mut App) {
    if let Some(id) = selected_peer_id(app) {
        app.status = format!("ping {id}…");
        match crate::probe::probe_ping(&app.paths, &id).await {
            Ok(ms) => app.status = format!("pong {ms} ms"),
            Err(e) => app.status = format!("ping: {e}"),
        }
    }
}
async fn bw_sel(app: &mut App) {
    if let Some(id) = selected_peer_id(app) {
        app.status = format!("bw {id}…");
        match crate::probe::probe_bandwidth(&app.paths, &id, 1024 * 1024).await {
            Ok(r) => app.status = format!("bw {:.2} Mbps", r.mbps),
            Err(e) => app.status = format!("bw: {e}"),
        }
    }
}
async fn metrics_sel(app: &mut App) {
    if let Some(id) = selected_peer_id(app) {
        app.status = format!("metrics {id}…");
        match crate::probe::probe_host_metrics(&app.paths, &id).await {
            Ok(s) => {
                app.status = format!(
                    "{} CPU {:.0}% mem {} disk {}",
                    s.hostname,
                    s.cpu_pct,
                    human_bytes(s.mem_used_bytes),
                    human_bytes(s.disk_used_bytes)
                )
            }
            Err(e) => app.status = format!("metrics: {e}"),
        }
    }
}

fn selected_peer_id(app: &App) -> Option<String> {
    let store = DeviceStore::open(app.paths.devices_file()).ok()?;
    let list = store.list();
    if list.is_empty() {
        return None;
    }
    let i = app.peer_sel.min(list.len() - 1);
    Some(list[i].id.to_string())
}

fn files_view_h(app: &App) -> usize {
    // list area height approx: content minus node row (3) and borders
    app.files
        .src_list_rect
        .height
        .saturating_sub(2)
        .max(3) as usize
}

fn files_move_sel(app: &mut App, delta: i32) {
    let vh = files_view_h(app);
    match app.files.focus {
        FilesFocus::SrcList | FilesFocus::SrcNode => {
            if app.files.focus == FilesFocus::SrcNode {
                app.files.focus = FilesFocus::SrcList;
            }
            let len = app.files.src.len().max(1);
            let cur = app.files.src_sel.min(len - 1) as i32;
            let next = (cur + delta).clamp(0, (len - 1) as i32) as usize;
            app.files.src_sel = next;
            ensure_visible(next, &mut app.files.src_scroll, vh);
        }
        FilesFocus::DstList | FilesFocus::DstNode => {
            if app.files.focus == FilesFocus::DstNode {
                app.files.focus = FilesFocus::DstList;
            }
            let len = app.files.dst.len().max(1);
            let cur = app.files.dst_sel.min(len - 1) as i32;
            let next = (cur + delta).clamp(0, (len - 1) as i32) as usize;
            app.files.dst_sel = next;
            ensure_visible(next, &mut app.files.dst_scroll, vh);
        }
    }
}

fn cycle_node(app: &mut App, src: bool, delta: i32) {
    let n = app.files.nodes.len();
    if n == 0 {
        return;
    }
    if src {
        let cur = app.files.src_node as i32;
        app.files.src_node = ((cur + delta).rem_euclid(n as i32)) as usize;
        let home = dirs_home();
        app.files.src_cwd = node_cwd_default(&app.files.nodes[app.files.src_node], &home);
        app.files.src_sel = 0;
        app.files.src_scroll = 0;
        app.files.selected.retain(|k| !k.starts_with("src:"));
        app.status = format!("source → {}", app.files.nodes[app.files.src_node].title());
    } else {
        let cur = app.files.dst_node as i32;
        app.files.dst_node = ((cur + delta).rem_euclid(n as i32)) as usize;
        let home = dirs_home();
        app.files.dst_cwd = node_cwd_default(&app.files.nodes[app.files.dst_node], &home);
        app.files.dst_sel = 0;
        app.files.dst_scroll = 0;
        app.files.selected.retain(|k| !k.starts_with("dst:"));
        app.status = format!("dest → {}", app.files.nodes[app.files.dst_node].title());
    }
}

fn toggle_select(app: &mut App) {
    let (side, entries, sel) = match app.files.focus {
        FilesFocus::SrcList | FilesFocus::SrcNode => {
            app.files.focus = FilesFocus::SrcList;
            ("src", &app.files.src, app.files.src_sel)
        }
        FilesFocus::DstList | FilesFocus::DstNode => {
            app.files.focus = FilesFocus::DstList;
            ("dst", &app.files.dst, app.files.dst_sel)
        }
    };
    if entries.is_empty() {
        return;
    }
    let i = sel.min(entries.len() - 1);
    let e = &entries[i];
    if e.name == ".." {
        return;
    }
    let key = format!("{side}:{}", e.path);
    if app.files.selected.contains(&key) {
        app.files.selected.remove(&key);
        app.status = format!("deselected {}", e.name);
    } else {
        app.files.selected.insert(key);
        app.status = format!("selected {} ({} total)", e.name, app.files.selected.len());
    }
}

fn handle_files_scroll(app: &mut App, col: u16, row: u16, up: bool) {
    let delta = if up { -3 } else { 3 };
    if rect_contains(app.files.src_list_rect, col, row)
        || rect_contains(app.files.src_node_rect, col, row)
    {
        app.files.focus = FilesFocus::SrcList;
        let len = app.files.src.len().max(1);
        let vh = files_view_h(app);
        let next = (app.files.src_scroll as i32 + delta).clamp(0, (len.saturating_sub(1)) as i32) as usize;
        app.files.src_scroll = next;
        // keep selection in view naturally
        if app.files.src_sel < app.files.src_scroll {
            app.files.src_sel = app.files.src_scroll;
        }
        if app.files.src_sel >= app.files.src_scroll + vh {
            app.files.src_sel = app.files.src_scroll + vh.saturating_sub(1);
        }
    } else if rect_contains(app.files.dst_list_rect, col, row)
        || rect_contains(app.files.dst_node_rect, col, row)
    {
        app.files.focus = FilesFocus::DstList;
        let len = app.files.dst.len().max(1);
        let vh = files_view_h(app);
        let next = (app.files.dst_scroll as i32 + delta).clamp(0, (len.saturating_sub(1)) as i32) as usize;
        app.files.dst_scroll = next;
        if app.files.dst_sel < app.files.dst_scroll {
            app.files.dst_sel = app.files.dst_scroll;
        }
        if app.files.dst_sel >= app.files.dst_scroll + vh {
            app.files.dst_sel = app.files.dst_scroll + vh.saturating_sub(1);
        }
    }
}

async fn handle_files_click(app: &mut App, col: u16, row: u16) {
    if rect_contains(app.files.src_node_rect, col, row) {
        app.files.focus = FilesFocus::SrcNode;
        cycle_node(app, true, 1);
        kick_file_refresh(app, true);
        return;
    }
    if rect_contains(app.files.dst_node_rect, col, row) {
        app.files.focus = FilesFocus::DstNode;
        cycle_node(app, false, 1);
        kick_file_refresh(app, true);
        return;
    }
    if rect_contains(app.files.src_list_rect, col, row) {
        app.files.focus = FilesFocus::SrcList;
        let rel = row.saturating_sub(app.files.src_list_rect.y.saturating_add(1)) as usize;
        let idx = app.files.src_scroll + rel;
        if idx < app.files.src.len() {
            app.files.src_sel = idx;
            toggle_select(app);
        }
        return;
    }
    if rect_contains(app.files.dst_list_rect, col, row) {
        app.files.focus = FilesFocus::DstList;
        let rel = row.saturating_sub(app.files.dst_list_rect.y.saturating_add(1)) as usize;
        let idx = app.files.dst_scroll + rel;
        if idx < app.files.dst.len() {
            app.files.dst_sel = idx;
            toggle_select(app);
        }
    }
}

fn drain_file_list_results(app: &mut App) {
    while let Ok(msg) = app.files.list_rx.try_recv() {
        match msg {
            PaneListResult::Src { gen, entries } => {
                if gen != app.files.refresh_gen {
                    continue;
                }
                app.files.src_inflight = false;
                match entries {
                    Ok(list) => {
                        app.files.src = list;
                        app.files.busy_src.clear();
                        if app.files.src_sel >= app.files.src.len() && !app.files.src.is_empty() {
                            app.files.src_sel = app.files.src.len() - 1;
                        }
                    }
                    Err(e) => app.files.busy_src = e,
                }
            }
            PaneListResult::Dst { gen, entries } => {
                if gen != app.files.refresh_gen {
                    continue;
                }
                app.files.dst_inflight = false;
                match entries {
                    Ok(list) => {
                        app.files.dst = list;
                        app.files.busy_dst.clear();
                        if app.files.dst_sel >= app.files.dst.len() && !app.files.dst.is_empty() {
                            app.files.dst_sel = app.files.dst.len() - 1;
                        }
                    }
                    Err(e) => app.files.busy_dst = e,
                }
            }
        }
    }
}

/// Immediate local fill + optional peer background fetch.
fn kick_file_refresh(app: &mut App, force: bool) {
    app.files.refresh_gen = app.files.refresh_gen.saturating_add(1);
    // cancel conceptual inflight by gen bump
    app.files.src_inflight = false;
    app.files.dst_inflight = false;
    schedule_file_refresh(app, force);
}

fn schedule_file_refresh(app: &mut App, force: bool) {
    let gen = app.files.refresh_gen;
    // --- source ---
    let src_node = app
        .files
        .nodes
        .get(app.files.src_node)
        .cloned()
        .unwrap_or(BrowserNode::Local);
    match src_node {
        BrowserNode::Local => {
            let dir = PathBuf::from(if app.files.src_cwd.is_empty() {
                dirs_home().display().to_string()
            } else {
                app.files.src_cwd.clone()
            });
            app.files.src = local_to_browser(&list_local(&dir));
            app.files.busy_src.clear();
            app.files.src_inflight = false;
        }
        BrowserNode::Peer { id, .. } => {
            let due = force || app.files.last_remote_src.elapsed() >= Duration::from_secs(5);
            if due && !app.files.src_inflight {
                app.files.src_inflight = true;
                app.files.last_remote_src = Instant::now();
                app.files.busy_src = "loading…".into();
                let paths = app.paths.clone();
                let cwd = app.files.src_cwd.clone();
                let tx = app.files.list_tx.clone();
                tokio::spawn(async move {
                    let entries = load_peer_entries(&paths, &id, &cwd).await;
                    let _ = tx.send(PaneListResult::Src { gen, entries });
                });
            }
        }
    }
    // --- dest ---
    let dst_node = app
        .files
        .nodes
        .get(app.files.dst_node)
        .cloned()
        .unwrap_or(BrowserNode::Local);
    match dst_node {
        BrowserNode::Local => {
            let dir = PathBuf::from(if app.files.dst_cwd.is_empty() {
                dirs_home().display().to_string()
            } else {
                app.files.dst_cwd.clone()
            });
            app.files.dst = local_to_browser(&list_local(&dir));
            app.files.busy_dst.clear();
            app.files.dst_inflight = false;
        }
        BrowserNode::Peer { id, .. } => {
            let due = force || app.files.last_remote_dst.elapsed() >= Duration::from_secs(5);
            if due && !app.files.dst_inflight {
                app.files.dst_inflight = true;
                app.files.last_remote_dst = Instant::now();
                app.files.busy_dst = "loading…".into();
                let paths = app.paths.clone();
                let cwd = app.files.dst_cwd.clone();
                let tx = app.files.list_tx.clone();
                tokio::spawn(async move {
                    let entries = load_peer_entries(&paths, &id, &cwd).await;
                    let _ = tx.send(PaneListResult::Dst { gen, entries });
                });
            }
        }
    }
}

async fn load_peer_entries(
    paths: &Paths,
    id: &str,
    cwd: &str,
) -> Result<Vec<BrowserEntry>, String> {
    let path = if cwd == "~" || cwd.is_empty() {
        "."
    } else {
        cwd
    };
    match crate::probe::remote_list(paths, id, path).await {
        Ok(entries) => {
            let mut v = remote_to_browser(&entries);
            if path != "." && path != "/" {
                let parent = Path::new(path)
                    .parent()
                    .map(|p| p.to_string_lossy().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| ".".into());
                v.insert(
                    0,
                    BrowserEntry {
                        name: "..".into(),
                        path: parent,
                        is_dir: true,
                        size: 0,
                    },
                );
            }
            Ok(v)
        }
        Err(e) => Err(e.to_string()),
    }
}

async fn files_go_up(app: &mut App) {
    let (node_i, cwd) = match app.files.focus {
        FilesFocus::SrcList | FilesFocus::SrcNode => (app.files.src_node, app.files.src_cwd.clone()),
        FilesFocus::DstList | FilesFocus::DstNode => (app.files.dst_node, app.files.dst_cwd.clone()),
    };
    let node = app.files.nodes.get(node_i).cloned().unwrap_or(BrowserNode::Local);
    let new_cwd = match node {
        BrowserNode::Local => PathBuf::from(&cwd)
            .parent()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| cwd.clone()),
        BrowserNode::Peer { .. } => {
            if cwd == "." || cwd == "/" || cwd == "~" {
                cwd
            } else {
                Path::new(&cwd)
                    .parent()
                    .map(|p| p.to_string_lossy().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| ".".into())
            }
        }
    };
    match app.files.focus {
        FilesFocus::SrcList | FilesFocus::SrcNode => {
            app.files.src_cwd = new_cwd;
            app.files.src_sel = 0;
            app.files.src_scroll = 0;
        }
        FilesFocus::DstList | FilesFocus::DstNode => {
            app.files.dst_cwd = new_cwd;
            app.files.dst_sel = 0;
            app.files.dst_scroll = 0;
        }
    }
    kick_file_refresh(app, true);
}

async fn enter_file(app: &mut App) {
    let (focus_src, entries, sel) = match app.files.focus {
        FilesFocus::SrcList | FilesFocus::SrcNode => {
            app.files.focus = FilesFocus::SrcList;
            (true, app.files.src.clone(), app.files.src_sel)
        }
        FilesFocus::DstList | FilesFocus::DstNode => {
            app.files.focus = FilesFocus::DstList;
            (false, app.files.dst.clone(), app.files.dst_sel)
        }
    };
    if entries.is_empty() {
        return;
    }
    let i = sel.min(entries.len() - 1);
    let e = &entries[i];
    if !e.is_dir {
        // select file
        toggle_select(app);
        return;
    }
    if focus_src {
        app.files.src_cwd = e.path.clone();
        app.files.src_sel = 0;
        app.files.src_scroll = 0;
    } else {
        app.files.dst_cwd = e.path.clone();
        app.files.dst_sel = 0;
        app.files.dst_scroll = 0;
    }
    kick_file_refresh(app, true);
}

async fn transfer_selected(app: &mut App) {
    // Collect selected on source side; if none, use current source cursor file
    let mut paths: Vec<BrowserEntry> = app
        .files
        .selected
        .iter()
        .filter(|k| k.starts_with("src:"))
        .filter_map(|k| {
            let path = k.trim_start_matches("src:");
            app.files.src.iter().find(|e| e.path == path).cloned()
        })
        .collect();
    if paths.is_empty() {
        if !app.files.src.is_empty() {
            let i = app.files.src_sel.min(app.files.src.len() - 1);
            let e = app.files.src[i].clone();
            if !e.is_dir && e.name != ".." {
                paths.push(e);
            }
        }
    }
    paths.retain(|e| !e.is_dir && e.name != "..");
    if paths.is_empty() {
        app.status = "select files on source (Space) then [c] transfer".into();
        return;
    }

    let src = app.files.nodes.get(app.files.src_node).cloned().unwrap_or(BrowserNode::Local);
    let dst = app.files.nodes.get(app.files.dst_node).cloned().unwrap_or(BrowserNode::Local);
    if src.id_key() == dst.id_key() && matches!(src, BrowserNode::Local) {
        // local to local
        for e in &paths {
            let dest = PathBuf::from(&app.files.dst_cwd).join(&e.name);
            match std::fs::copy(&e.path, &dest) {
                Ok(_) => app.status = format!("copied {}", e.name),
                Err(err) => app.status = format!("copy {}: {err}", e.name),
            }
        }
        kick_file_refresh(app, true);
        return;
    }

    let mut ok = 0usize;
    let mut err = 0usize;
    for e in &paths {
        app.status = format!("transfer {}…", e.name);
        let res = match (&src, &dst) {
            (BrowserNode::Local, BrowserNode::Peer { id, .. }) => {
                let remote = if app.files.dst_cwd == "." || app.files.dst_cwd == "~" {
                    e.name.clone()
                } else {
                    format!(
                        "{}/{}",
                        app.files.dst_cwd.trim_end_matches('/'),
                        e.name
                    )
                };
                push_file_helper(&app.paths, Path::new(&e.path), id, &remote).await
            }
            (BrowserNode::Peer { id, .. }, BrowserNode::Local) => {
                let dest = PathBuf::from(&app.files.dst_cwd).join(&e.name);
                pull_file_helper(&app.paths, id, &e.path, &dest).await
            }
            (BrowserNode::Peer { id: sid, .. }, BrowserNode::Peer { id: did, .. }) => {
                let tmp = std::env::temp_dir().join(format!("mymesh-xfer-{}", e.name));
                match pull_file_helper(&app.paths, sid, &e.path, &tmp).await {
                    Ok(()) => {
                        let remote = if app.files.dst_cwd == "." || app.files.dst_cwd == "~" {
                            e.name.clone()
                        } else {
                            format!(
                                "{}/{}",
                                app.files.dst_cwd.trim_end_matches('/'),
                                e.name
                            )
                        };
                        let r = push_file_helper(&app.paths, &tmp, did, &remote).await;
                        let _ = std::fs::remove_file(&tmp);
                        r
                    }
                    Err(err) => Err(err),
                }
            }
            (BrowserNode::Local, BrowserNode::Local) => Ok(()),
        };
        match res {
            Ok(()) => ok += 1,
            Err(e) => {
                err += 1;
                app.status = format!("err: {e}");
            }
        }
    }
    app.files.selected.clear();
    app.status = format!("transfer done · ok={ok} err={err}");
    kick_file_refresh(app, true);
}

async fn push_file_helper(
    paths: &Paths,
    local: &Path,
    device: &str,
    remote: &str,
) -> anyhow::Result<()> {
    // reuse main's approach via shelling to same binary functions - call probe bandwidth path style
    use mymesh_core::{Capability, Config, DeviceStore};
    use mymesh_crypto::Identity;
    use mymesh_net::{IrohTransport, Transport};
    use mymesh_protocol::{decode_msg, encode_msg, ChannelId, FileMessage, Frame};
    use mymesh_session::Session;
    let data = std::fs::read(local)?;
    let identity = Identity::load_or_create(paths.identity_file())?;
    let cfg = Config::load(paths.config_file())?;
    let store = DeviceStore::open(paths.devices_file())?;
    let peer = crate::resolve_device(&store, device)?;
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
    let conn = session.into_conn();
    let size = data.len() as u64;
    conn.send_frame(Frame {
        channel: ChannelId::files(1),
        payload: encode_msg(&FileMessage::Put {
            path: remote.to_string(),
            size,
            mode: 0o644,
            resume_from: 0,
        })?,
    })
    .await?;
    let mut offset = 0u64;
    for chunk in data.chunks(64 * 1024) {
        conn.send_frame(Frame {
            channel: ChannelId::files(1),
            payload: encode_msg(&FileMessage::Chunk {
                offset,
                data: chunk.to_vec(),
            })?,
        })
        .await?;
        offset += chunk.len() as u64;
    }
    conn.send_frame(Frame {
        channel: ChannelId::files(1),
        payload: encode_msg(&FileMessage::Done {
            path: remote.to_string(),
            bytes: size,
        })?,
    })
    .await?;
    let frame = conn.recv_frame().await?;
    let msg: FileMessage = decode_msg(&frame.payload)?;
    if let FileMessage::Error { message } = msg {
        anyhow::bail!(message);
    }
    let _ = conn.close().await;
    transport.shutdown().await;
    Ok(())
}

async fn pull_file_helper(
    paths: &Paths,
    device: &str,
    remote: &str,
    local: &Path,
) -> anyhow::Result<()> {
    use mymesh_core::{Capability, Config, DeviceStore};
    use mymesh_crypto::Identity;
    use mymesh_net::{IrohTransport, Transport};
    use mymesh_protocol::{decode_msg, encode_msg, ChannelId, FileMessage, Frame};
    use mymesh_session::Session;
    use std::io::Write;
    let identity = Identity::load_or_create(paths.identity_file())?;
    let cfg = Config::load(paths.config_file())?;
    let store = DeviceStore::open(paths.devices_file())?;
    let peer = crate::resolve_device(&store, device)?;
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
    let conn = session.into_conn();
    conn.send_frame(Frame {
        channel: ChannelId::files(1),
        payload: encode_msg(&FileMessage::Get {
            path: remote.to_string(),
            offset: 0,
            length: None,
        })?,
    })
    .await?;
    if let Some(p) = local.parent() {
        std::fs::create_dir_all(p)?;
    }
    let mut file = std::fs::File::create(local)?;
    loop {
        let frame = conn.recv_frame().await?;
        let msg: FileMessage = decode_msg(&frame.payload)?;
        match msg {
            FileMessage::Chunk { data, .. } => file.write_all(&data)?,
            FileMessage::Done { .. } => break,
            FileMessage::Error { message } => anyhow::bail!(message),
            _ => {}
        }
    }
    let _ = conn.close().await;
    transport.shutdown().await;
    Ok(())
}

// ─── UI ──────────────────────────────────────────────────────────────
fn ui(f: &mut TuiFrame, app: &mut App) {
    app.buttons.clear();
    app.tab_rects.clear();

    let root = f.area();
    // Full clear every frame — prevents ghost cells after resize / wide terminals.
    f.render_widget(Clear, root);
    f.render_widget(
        Block::default().style(Style::default().bg(C_BG).fg(C_TEXT)),
        root,
    );

    // Adaptive chrome: collapse action bar on short terminals.
    let (header_h, action_h, status_h) = if root.height < 12 {
        (3u16, 0u16, 1u16)
    } else if root.height < 18 {
        (3, 3, 1)
    } else {
        (3, 3, 2)
    };

    let mut constraints = vec![Constraint::Length(header_h)];
    if action_h > 0 {
        constraints.push(Constraint::Length(action_h));
    }
    constraints.push(Constraint::Min(3));
    constraints.push(Constraint::Length(status_h));

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(root);

    let mut i = 0usize;
    draw_header(f, chunks[i], app);
    i += 1;
    if action_h > 0 {
        draw_action_bar(f, chunks[i], app);
        i += 1;
    }
    let content = chunks[i];
    i += 1;
    let status = chunks[i];

    app.content = content;
    // Clear content region so panels never leave trails from previous tab/size.
    f.render_widget(Clear, content);
    f.render_widget(
        Block::default().style(Style::default().bg(C_BG)),
        content,
    );

    match app.tab {
        Tab::Home => draw_home(f, content, app),
        Tab::Peers => draw_peers(f, content, app),
        Tab::Files => draw_files(f, content, app),
        Tab::Term => term_pane::draw(f, content, &mut app.term),
        Tab::Status => draw_status(f, content, app),
    }
    draw_status_line(f, status, app);
}

fn panel(title: &str) -> Block<'_> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_BORDER))
        .title(Span::styled(
            format!(" {title} "),
            Style::default().fg(C_ACCENT).add_modifier(Modifier::BOLD),
        ))
        .style(Style::default().bg(C_PANEL).fg(C_TEXT))
}

fn draw_header(f: &mut TuiFrame, area: Rect, app: &mut App) {
    if area.width < 10 || area.height == 0 {
        return;
    }
    f.render_widget(Clear, area);

    let brand_w = 12u16.min(area.width / 4);
    let ver_w = 14u16.min(area.width / 5);
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(brand_w),
            Constraint::Min(8),
            Constraint::Length(ver_w),
        ])
        .split(area);

    let brand = Paragraph::new(Line::from(vec![
        Span::styled(" * ", Style::default().fg(C_ACCENT2)),
        Span::styled(
            "MyMesh",
            Style::default()
                .fg(C_ACCENT)
                .add_modifier(Modifier::BOLD),
        ),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(C_BORDER))
            .style(Style::default().bg(C_PANEL)),
    );
    f.render_widget(brand, cols[0]);

    let tab_area = cols[1];
    f.render_widget(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(C_BORDER))
            .style(Style::default().bg(C_PANEL)),
        tab_area,
    );
    let n = Tab::ALL.len() as u16;
    let inner_w = tab_area.width.saturating_sub(2);
    let inner_h = tab_area.height.saturating_sub(2).max(1);
    if n > 0 && inner_w > 0 {
        let base = inner_w / n;
        let rem = inner_w % n;
        let mut x = tab_area.x.saturating_add(1);
        let y = tab_area.y.saturating_add(1);
        for (i, tab) in Tab::ALL.iter().enumerate() {
            let w = base + if (i as u16) < rem { 1 } else { 0 };
            if w == 0 {
                break;
            }
            let r = Rect {
                x,
                y,
                width: w,
                height: inner_h.min(1),
            };
            app.tab_rects.push((*tab, r));
            let selected = app.tab == *tab;
            let label = format!("[{}]{}", tab.key(), tab.title().trim());
            let style = if selected {
                Style::default()
                    .fg(Color::Black)
                    .bg(C_ACCENT)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(C_MUTED).bg(C_PANEL)
            };
            // Pad label visually by filling whole slot
            f.render_widget(
                Paragraph::new(label)
                    .style(style)
                    .alignment(Alignment::Center),
                r,
            );
            x = x.saturating_add(w);
        }
    }

    let ver = Paragraph::new(Line::from(Span::styled(
        format!("v{}", env!("CARGO_PKG_VERSION")),
        Style::default().fg(C_MUTED),
    )))
    .alignment(Alignment::Center)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(C_BORDER))
            .style(Style::default().bg(C_PANEL)),
    );
    f.render_widget(ver, cols[2]);
}

fn push_btn(app: &mut App, f: &mut TuiFrame, id: &'static str, label: &str, rect: Rect, hot: bool) {
    if rect.width == 0 || rect.height == 0 {
        return;
    }
    app.buttons.push(Btn {
        id,
        rect,
    });
    let style = if hot {
        Style::default()
            .fg(Color::White)
            .bg(C_BTN_HOT)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(C_TEXT).bg(C_BTN)
    };
    // Compact single-row buttons: solid fill, no nested borders (avoids edge artifacts).
    f.render_widget(
        Paragraph::new(label)
            .style(style)
            .alignment(Alignment::Center),
        rect,
    );
}

fn draw_action_bar(f: &mut TuiFrame, area: Rect, app: &mut App) {
    if area.height < 3 || area.width < 8 {
        return;
    }
    f.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_BORDER))
        .title(Span::styled(" actions ", Style::default().fg(C_MUTED)))
        .style(Style::default().bg(C_PANEL));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let specs: Vec<(&str, &str)> = match app.tab {
        Tab::Home => vec![
            ("arm", "[a] Arm"),
            ("disarm", "[d] Disarm"),
            ("accept", "[y] Accept"),
            ("copy_id", "[c] Show ID"),
            ("quit", "[q] Quit"),
        ],
        Tab::Peers => vec![
            ("ping", "[p] Ping"),
            ("bw", "[b] BW"),
            ("metrics", "[m] Metrics"),
            ("poll", "[t] Poll"),
            ("mesh_sync", "[g] Sync"),
            ("kick", "[K] Kick"),
            ("force_kick", "[F] Force"),
            ("quit", "[q] Quit"),
        ],
        Tab::Files => vec![
            ("copy_lr", "[c] Transfer"),
            ("clear_sel", "[x] Clear"),
            ("src_node", "[n] Src"),
            ("dst_node", "[N] Dst"),
            ("quit", "[q] Quit"),
        ],
        Tab::Term => vec![
            ("term_peer", "[n] Peer"),
            ("term_connect", "[c] Connect"),
            ("term_input", "[i] Focus"),
            ("term_disc", "[x] Disc"),
            ("quit", "[q] Quit"),
        ],
        Tab::Status => vec![
            ("svc_start", "[s] Start"),
            ("svc_stop", "[x] Stop"),
            ("svc_restart", "[r] Restart"),
            ("quit", "[q] Quit"),
        ],
    };
    let n = specs.len() as u16;
    if n == 0 || inner.width < 4 || inner.height == 0 {
        return;
    }
    // Equal columns across full width (no leftover gap on ultrawide).
    let base = inner.width / n;
    let rem = inner.width % n;
    let mut x = inner.x;
    for (i, (id, label)) in specs.into_iter().enumerate() {
        let w = base + if (i as u16) < rem { 1 } else { 0 };
        if w < 4 {
            break;
        }
        // 1px gap between buttons except last
        let gap = if i + 1 < n as usize { 1u16 } else { 0 };
        let bw = w.saturating_sub(gap).max(3);
        let r = Rect {
            x,
            y: inner.y,
            width: bw,
            height: inner.height.min(1).max(1),
        };
        let hot = match id {
            "arm" => ArmState::load(app.paths.arm_file())
                .map(|a| a.is_effectively_armed())
                .unwrap_or(false),
            "poll" => app.poll.enabled,
            _ => false,
        };
        push_btn(app, f, id, label, r, hot);
        x = x.saturating_add(w);
    }
}

fn draw_home(f: &mut TuiFrame, area: Rect, app: &App) {
    f.render_widget(Clear, area);
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(52), Constraint::Percentage(48)])
        .split(area);

    let id = Identity::load_or_create(app.paths.identity_file()).ok();
    let cfg = Config::load(app.paths.config_file()).unwrap_or_default();
    let arm = ArmState::load(app.paths.arm_file()).unwrap_or_default();
    let store = DeviceStore::open(app.paths.devices_file()).ok();
    let pending = JoinStore::open(app.paths.join_dir())
        .ok()
        .and_then(|j| j.list_pending().ok())
        .unwrap_or_default();
    let active = crate::install::service_is_active(false);

    let mut left_lines = vec![
        Line::from(vec![
            Span::styled("Device  ", Style::default().fg(C_MUTED)),
            Span::styled(
                cfg.device_label.clone(),
                Style::default()
                    .fg(C_TEXT)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("Agent   ", Style::default().fg(C_MUTED)),
            if active {
                Span::styled("● running (user unit)", Style::default().fg(C_OK))
            } else {
                Span::styled("○ not active", Style::default().fg(C_WARN))
            },
        ]),
        Line::from(vec![
            Span::styled("Join    ", Style::default().fg(C_MUTED)),
            if arm.is_effectively_armed() {
                Span::styled(
                    format!("● ARMED until {:?}", arm.until),
                    Style::default().fg(C_OK),
                )
            } else {
                Span::styled("○ disarmed — joins rejected", Style::default().fg(C_MUTED))
            },
        ]),
        Line::from(vec![
            Span::styled("Peers   ", Style::default().fg(C_MUTED)),
            Span::raw(format!(
                "{}",
                store.as_ref().map(|s| s.list().len()).unwrap_or(0)
            )),
        ]),
        Line::from(""),
    ];
    if let Some(id) = &id {
        let did = id.device_id();
        left_lines.push(Line::from(Span::styled(
            "Identity",
            Style::default().fg(C_ACCENT2).add_modifier(Modifier::BOLD),
        )));
        left_lines.push(Line::from(vec![
            Span::styled("hex   ", Style::default().fg(C_MUTED)),
            Span::raw(did.to_string()),
        ]));
        left_lines.push(Line::from(vec![
            Span::styled("short ", Style::default().fg(C_MUTED)),
            Span::raw(did.short()),
        ]));
        if let Ok(w) = device_id_to_words(&did) {
            left_lines.push(Line::from(Span::styled(
                "words",
                Style::default().fg(C_MUTED),
            )));
            // wrap words 4 per line
            let ws: Vec<_> = w.split_whitespace().collect();
            for chunk in ws.chunks(4) {
                left_lines.push(Line::from(Span::raw(format!("  {}", chunk.join(" ")))));
            }
        }
    }
    left_lines.push(Line::from(""));
    left_lines.push(Line::from(Span::styled(
        format!("Pending joins ({})", pending.len()),
        Style::default().fg(C_ACCENT2).add_modifier(Modifier::BOLD),
    )));
    if pending.is_empty() {
        left_lines.push(Line::from(Span::styled(
            "  none — arm to accept new devices",
            Style::default().fg(C_MUTED),
        )));
    } else {
        for p in pending.iter().take(6) {
            left_lines.push(Line::from(format!(
                "  • {}  {}  {}",
                p.device_id.short(),
                p.label,
                p.fingerprint
            )));
        }
    }

    f.render_widget(
        Paragraph::new(left_lines)
            .block(panel("This device · linking"))
            .wrap(Wrap { trim: false }),
        cols[0],
    );

    // QR panel
    let mut qr_lines = vec![Line::from(Span::styled(
        "Scan / share join URI",
        Style::default().fg(C_MUTED),
    ))];
    if let Some(id) = id {
        if let Ok(uri) = device_join_uri(&id.device_id()) {
            qr_lines.push(Line::from(Span::styled(
                uri.clone(),
                Style::default().fg(C_ACCENT),
            )));
            qr_lines.push(Line::from(""));
            for row in qr_half_block_lines(&uri) {
                qr_lines.push(Line::from(Span::styled(
                    row,
                    Style::default().fg(C_TEXT).bg(C_PANEL),
                )));
            }
        }
    }
    f.render_widget(
        Paragraph::new(qr_lines)
            .block(panel("QR · half-block"))
            .wrap(Wrap { trim: false }),
        cols[1],
    );
}

fn draw_peers(f: &mut TuiFrame, area: Rect, app: &App) {
    f.render_widget(Clear, area);
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(38), Constraint::Percentage(62)])
        .split(area);

    let store = DeviceStore::open(app.paths.devices_file()).ok();
    let list = store.as_ref().map(|s| s.list()).unwrap_or_default();
    let items: Vec<ListItem> = if list.is_empty() {
        vec![ListItem::new(Span::styled(
            "No peers — use Home to arm & link",
            Style::default().fg(C_MUTED),
        ))]
    } else {
        list.iter()
            .enumerate()
            .map(|(i, d)| {
                let sel = i == app.peer_sel.min(list.len() - 1);
                let m = PeerMetrics::load(app.paths.metrics_dir(), &d.id).ok();
                let rtt = m
                    .as_ref()
                    .and_then(|x| x.latest_rtt())
                    .map(|ms| format!("{ms}ms"))
                    .unwrap_or_else(|| "—".into());
                let mark = if sel { "▸ " } else { "  " };
                let line = format!(
                    "{mark}{}  {}  rtt {rtt}",
                    d.label,
                    d.id.short()
                );
                ListItem::new(Line::from(Span::styled(
                    line,
                    if sel {
                        Style::default()
                            .fg(Color::Black)
                            .bg(C_ACCENT)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(C_TEXT)
                    },
                )))
            })
            .collect()
    };
    f.render_widget(
        List::new(items).block(panel("Peers  ↑↓ navigate  Enter open")),
        cols[0],
    );

    // detail
    let mut lines = vec![Line::from(Span::styled(
        "Peer detail · tools · host metrics",
        Style::default().fg(C_MUTED),
    ))];
    if list.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from("Link a device from Home, then select it here."));
    } else {
        let i = app.peer_sel.min(list.len() - 1);
        let d = list[i];
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("Label  ", Style::default().fg(C_MUTED)),
            Span::styled(
                d.label.as_str().to_string(),
                Style::default().add_modifier(Modifier::BOLD),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::styled("Id     ", Style::default().fg(C_MUTED)),
            Span::raw(d.id.to_string()),
        ]));
        lines.push(Line::from(vec![
            Span::styled("Trust  ", Style::default().fg(C_MUTED)),
            Span::raw(format!("{:?}", d.trust)),
        ]));
        let m = PeerMetrics::load(app.paths.metrics_dir(), &d.id).ok();
        if let Some(m) = &m {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Latency (recent)",
                Style::default().fg(C_ACCENT2),
            )));
            for s in m.samples.iter().rev().take(8) {
                lines.push(Line::from(format!(
                    "  {}  {}",
                    s.at.format("%H:%M:%S"),
                    s.rtt_ms
                        .map(|ms| format!("{ms} ms"))
                        .unwrap_or_else(|| "fail".into())
                )));
            }
            if let Some(bw) = &m.last_bandwidth {
                lines.push(Line::from(format!(
                    "Bandwidth  {:.2} Mbps ({} in {}ms)",
                    bw.mbps, human_bytes(bw.bytes), bw.elapsed_ms
                )));
            }
            if let Some(h) = &m.last_host {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    format!("Host {}", h.hostname),
                    Style::default().fg(C_ACCENT2).add_modifier(Modifier::BOLD),
                )));
                lines.push(Line::from(format!(
                    "CPU {:.0}%   load {:.2}   up {}s",
                    h.cpu_pct, h.load_1, h.uptime_secs
                )));
                // gauges area via text bars
                let mem_r = bar_ratio(h.mem_used_bytes, h.mem_total_bytes);
                let disk_r = bar_ratio(h.disk_used_bytes, h.disk_total_bytes);
                lines.push(Line::from(format!(
                    "MEM  {} / {}  ({:.0}%)",
                    human_bytes(h.mem_used_bytes),
                    human_bytes(h.mem_total_bytes),
                    mem_r * 100.0
                )));
                lines.push(Line::from(spark_bar(mem_r, 24)));
                lines.push(Line::from(format!(
                    "DISK {} / {}  ({:.0}%)",
                    human_bytes(h.disk_used_bytes),
                    human_bytes(h.disk_total_bytes),
                    disk_r * 100.0
                )));
                lines.push(Line::from(spark_bar(disk_r, 24)));
                lines.push(Line::from(format!(
                    "NET  rx {}  tx {}",
                    human_bytes(h.net_rx_bytes),
                    human_bytes(h.net_tx_bytes)
                )));
                lines.push(Line::from(Span::styled(
                    format!("sampled {}", h.at.format("%H:%M:%S")),
                    Style::default().fg(C_MUTED),
                )));
            } else {
                lines.push(Line::from(Span::styled(
                    "No host metrics yet — [m] sample or [t] poll",
                    Style::default().fg(C_MUTED),
                )));
            }
        }
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            if app.poll.enabled {
                "● Poll ON · 10s · stops after 5m"
            } else {
                "○ Poll OFF · press [t] or Poll button"
            },
            Style::default().fg(if app.poll.enabled { C_OK } else { C_MUTED }),
        )));
    }

    // mesh + pending kicks
    lines.push(Line::from(""));
    if let Ok(mesh) = MeshState::load(app.paths.mesh_file()) {
        lines.push(Line::from(Span::styled(
            format!("Mesh {}", mesh.mesh_id),
            Style::default().fg(C_ACCENT2),
        )));
        lines.push(Line::from(Span::styled(
            format!("gen {}  last_sync {:?}", mesh.roster_generation, mesh.last_sync),
            Style::default().fg(C_MUTED),
        )));
    }
    if let Ok(pk) = PendingKickStore::open(app.paths.pending_kicks_file()) {
        let kicks = pk.list();
        if !kicks.is_empty() {
            lines.push(Line::from(Span::styled(
                "Pending kicks",
                Style::default().fg(C_WARN).add_modifier(Modifier::BOLD),
            )));
            for k in kicks.iter().take(6) {
                lines.push(Line::from(format!(
                    "  {} {} force={} deliv={} acks={}/{}",
                    k.target_id.short(),
                    k.target_label,
                    k.force,
                    k.delivered_to_target,
                    k.acks.len(),
                    k.expected.len()
                )));
            }
        }
    }
    if app.kick.active {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            if app.kick.force { "FORCE KICK CONFIRM" } else { "KICK CONFIRM" },
            Style::default().fg(C_ERR).add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(format!(
            "target: {} ({})",
            app.kick.target_label,
            app.kick.target.as_deref().unwrap_or("?")
        )));
        let need = if app.kick.step == 0 {
            "KICK FROM MESH"
        } else {
            "I AM SURE"
        };
        lines.push(Line::from(format!("type exactly: {need}")));
        lines.push(Line::from(format!("> {}", app.kick.buf)));
        lines.push(Line::from(Span::styled(
            "Enter confirm · Esc cancel",
            Style::default().fg(C_MUTED),
        )));
    } else {
        lines.push(Line::from(Span::styled(
            "[K] kick  [F] force kick  [g] mesh sync",
            Style::default().fg(C_MUTED),
        )));
    }

    f.render_widget(
        Paragraph::new(lines)
            .block(panel("Detail · mesh · kicks"))
            .wrap(Wrap { trim: false }),
        cols[1],
    );
}

fn spark_bar(ratio: f64, width: usize) -> String {
    let filled = ((ratio * width as f64).round() as usize).min(width);
    let mut s = String::from("  [");
    for i in 0..width {
        s.push(if i < filled { '█' } else { '░' });
    }
    s.push(']');
    s
}

fn draw_files(f: &mut TuiFrame, area: Rect, app: &mut App) {
    f.render_widget(Clear, area);
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // each col: node bar + list
    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(3)])
        .split(cols[0]);
    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(3)])
        .split(cols[1]);

    app.files.src_node_rect = left[0];
    app.files.dst_node_rect = right[0];
    app.files.src_list_rect = left[1];
    app.files.dst_list_rect = right[1];

    let src_node = app
        .files
        .nodes
        .get(app.files.src_node)
        .map(|n| n.title())
        .unwrap_or_else(|| "?".into());
    let dst_node = app
        .files
        .nodes
        .get(app.files.dst_node)
        .map(|n| n.title())
        .unwrap_or_else(|| "?".into());

    let src_node_hot = matches!(app.files.focus, FilesFocus::SrcNode);
    let dst_node_hot = matches!(app.files.focus, FilesFocus::DstNode);
    f.render_widget(
        Paragraph::new(format!("SEND FROM  [ {src_node} ]  · n/[ ] cycle · click"))
            .style(Style::default().fg(if src_node_hot { Color::Black } else { C_TEXT }).bg(if src_node_hot { C_ACCENT } else { C_BTN }))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(if src_node_hot { C_ACCENT } else { C_BORDER }))
                    .title(Span::styled(" source node ", Style::default().fg(C_MUTED))),
            ),
        left[0],
    );
    f.render_widget(
        Paragraph::new(format!("RECEIVE TO  [ {dst_node} ]  · N/{{ }} cycle · click"))
            .style(Style::default().fg(if dst_node_hot { Color::Black } else { C_TEXT }).bg(if dst_node_hot { C_ACCENT2 } else { C_BTN }))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(if dst_node_hot { C_ACCENT2 } else { C_BORDER }))
                    .title(Span::styled(" dest node ", Style::default().fg(C_MUTED))),
            ),
        right[0],
    );

    let vh = left[1].height.saturating_sub(2) as usize;
    let src_items = file_list_items(
        &app.files.src,
        app.files.src_sel,
        app.files.src_scroll,
        vh,
        matches!(app.files.focus, FilesFocus::SrcList),
        "src",
        &app.files.selected,
    );
    let dst_items = file_list_items(
        &app.files.dst,
        app.files.dst_sel,
        app.files.dst_scroll,
        vh,
        matches!(app.files.focus, FilesFocus::DstList),
        "dst",
        &app.files.selected,
    );

    let src_busy = if app.files.busy_src.is_empty() {
        ""
    } else {
        app.files.busy_src.as_str()
    };
    let dst_busy = if app.files.busy_dst.is_empty() {
        ""
    } else {
        app.files.busy_dst.as_str()
    };
    let src_title = format!(
        " {}  sel:{}  {} {}",
        app.files.src_cwd,
        app.files.selected.iter().filter(|k| k.starts_with("src:")).count(),
        if matches!(app.files.focus, FilesFocus::SrcList) { "◀" } else { "" },
        src_busy
    );
    let dst_title = format!(
        " {}  sel:{}  {} {}",
        app.files.dst_cwd,
        app.files.selected.iter().filter(|k| k.starts_with("dst:")).count(),
        if matches!(app.files.focus, FilesFocus::DstList) { "◀" } else { "" },
        dst_busy
    );

    f.render_widget(
        List::new(src_items).block(panel(&format!("Source ·{src_title}"))),
        left[1],
    );
    f.render_widget(
        List::new(dst_items).block(panel(&format!("Dest ·{dst_title}"))),
        right[1],
    );
}

fn file_list_items(
    entries: &[BrowserEntry],
    sel: usize,
    scroll: usize,
    view_h: usize,
    focused: bool,
    side: &str,
    selected: &std::collections::HashSet<String>,
) -> Vec<ListItem<'static>> {
    if entries.is_empty() {
        return vec![ListItem::new(Span::styled(
            "(empty — auto-refresh · agent must run for peers)",
            Style::default().fg(C_MUTED),
        ))];
    }
    let end = (scroll + view_h.max(1)).min(entries.len());
    let start = scroll.min(end);
    entries[start..end]
        .iter()
        .enumerate()
        .map(|(off, e)| {
            let i = start + off;
            let is_cursor = focused && i == sel.min(entries.len() - 1);
            let key = format!("{side}:{}", e.path);
            let marked = selected.contains(&key);
            let mark = if marked { "● " } else { "  " };
            let icon = if e.is_dir { "[D]" } else { " · " };
            let size = if e.is_dir {
                String::new()
            } else {
                format!("  {}", human_bytes(e.size))
            };
            let text = format!("{mark}{icon} {}{size}", e.name);
            ListItem::new(Line::from(Span::styled(
                text,
                if is_cursor {
                    Style::default().fg(Color::Black).bg(C_ACCENT)
                } else if marked {
                    Style::default().fg(C_OK)
                } else if e.is_dir {
                    Style::default().fg(C_ACCENT2)
                } else {
                    Style::default().fg(C_TEXT)
                },
            )))
        })
        .collect()
}

fn draw_status(f: &mut TuiFrame, area: Rect, app: &App) {
    f.render_widget(Clear, area);
    let active = crate::install::service_is_active(false);
    let marker = std::fs::read_to_string(app.paths.install_marker()).unwrap_or_default();
    // try systemctl show
    let sys = std::process::Command::new("systemctl")
        .args([
            "--user",
            "show",
            "mymesh.service",
            "--no-page",
            "--property=ActiveState,SubState,MainPID,FragmentPath,Description",
        ])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_else(|| "(systemctl unavailable)".into());

    let text = format!(
        "Service status (user unit)\n\n\
Active (is-active): {}\n\n\
systemctl --user show mymesh.service:\n{}\n\n\
Install marker:\n{}\n\n\
Keys: [s] start  [x] stop  [r] restart\n\
Install: mymesh install   ·  Uninstall: mymesh uninstall\n",
        if active { "active" } else { "inactive" },
        sys.trim(),
        if marker.is_empty() {
            "(none — run mymesh install)"
        } else {
            marker.as_str()
        }
    );
    f.render_widget(
        Paragraph::new(text)
            .block(panel("Status · systemd"))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_status_line(f: &mut TuiFrame, area: Rect, app: &App) {
    if area.height == 0 || area.width == 0 {
        return;
    }
    f.render_widget(Clear, area);
    let p = Paragraph::new(Line::from(vec![
        Span::styled(" ", Style::default().fg(C_BORDER)),
        Span::styled(&app.status, Style::default().fg(C_TEXT)),
    ]))
    .style(Style::default().bg(C_PANEL).fg(C_TEXT))
    .block(
        Block::default()
            .borders(if area.height > 1 { Borders::TOP } else { Borders::NONE })
            .border_style(Style::default().fg(C_BORDER))
            .style(Style::default().bg(C_PANEL)),
    );
    f.render_widget(p, area);
}


fn start_kick_wizard(app: &mut App, force: bool) {
    let Some(id) = selected_peer_id(app) else {
        app.status = "select a peer to kick".into();
        return;
    };
    let label = DeviceStore::open(app.paths.devices_file())
        .ok()
        .and_then(|s| {
            s.list()
                .into_iter()
                .find(|d| d.id.to_string() == id)
                .map(|d| d.label.as_str().to_string())
        })
        .unwrap_or_else(|| id.clone());
    app.kick = KickWizard {
        active: true,
        force,
        step: 0,
        buf: String::new(),
        target: Some(id),
        target_label: label,
    };
    app.status = if force {
        "FORCE KICK — type KICK FROM MESH".into()
    } else {
        "KICK — type KICK FROM MESH".into()
    };
}

async fn run_kick(_paths: &Paths, device: &str, force: bool) -> anyhow::Result<String> {
    // Non-interactive path using CLI flags
    use std::process::Command;
    let bin = std::env::current_exe()?;
    let mut cmd = Command::new(bin);
    cmd.arg("kick").arg(device);
    if force {
        cmd.arg("--force");
    }
    cmd.arg("--yes-kick-from-mesh").arg("--yes-i-am-sure");
    if let Ok(home) = std::env::var("MYMESH_HOME") {
        cmd.arg("--home").arg(home);
    }
    let out = cmd.output()?;
    if !out.status.success() {
        anyhow::bail!(String::from_utf8_lossy(&out.stderr).to_string() + &String::from_utf8_lossy(&out.stdout));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

async fn mesh_sync_all(paths: &Paths) -> anyhow::Result<usize> {
    use mymesh_core::{Capability, Config, DeviceStore, MeshState};
    use mymesh_crypto::Identity;
    use mymesh_net::{IrohTransport, Transport};
    use mymesh_protocol::{decode_msg, encode_msg, ChannelId, ControlMessage, Frame};
    use mymesh_session::{apply_membership, build_announce, Session};
    let identity = Identity::load_or_create(paths.identity_file())?;
    let cfg = Config::load(paths.config_file())?;
    let store = DeviceStore::open(paths.devices_file())?;
    let mesh = MeshState::load(paths.mesh_file())?;
    let peers: Vec<_> = store
        .list()
        .into_iter()
        .filter(|d| matches!(d.trust, mymesh_core::TrustState::Trusted))
        .map(|d| d.id)
        .collect();
    let transport = IrohTransport::bind(&identity).await?;
    let mut added = 0usize;
    for peer in peers {
        let store = DeviceStore::open(paths.devices_file())?;
        let conn = match transport.connect(peer).await {
            Ok(c) => c,
            Err(_) => continue,
        };
        let session = match Session::handshake_dialer(
            conn,
            &identity,
            &cfg.device_label,
            &store,
            Capability::all(),
        )
        .await
        {
            Ok(s) => s,
            Err(_) => continue,
        };
        let conn = session.into_conn();
        let ann = build_announce(&identity, &cfg.device_label, &store, &mesh);
        let _ = conn
            .send_frame(Frame {
                channel: ChannelId::control(),
                payload: encode_msg(&ann)?,
            })
            .await;
        let _ = conn
            .send_frame(Frame {
                channel: ChannelId::control(),
                payload: encode_msg(&ControlMessage::MembershipRequest { nonce: 1 })?,
            })
            .await;
        if let Ok(Ok(frame)) =
            tokio::time::timeout(std::time::Duration::from_secs(5), conn.recv_frame()).await
        {
            if let Ok(ControlMessage::MembershipSnapshot {
                mesh_id,
                from_id,
                members,
                ts,
                signature,
                ..
            }) = decode_msg(&frame.payload)
            {
                if mymesh_session::verify_membership(&from_id, &mesh_id, ts, &members, &signature)
                    .is_ok()
                {
                    let mut store = DeviceStore::open(paths.devices_file())?;
                    added += apply_membership(
                        &mut store,
                        &paths.mesh_file(),
                        &from_id,
                        &mesh_id,
                        &members,
                        identity.device_id(),
                    )?;
                }
            }
        }
        let _ = conn.close().await;
    }
    transport.shutdown().await;
    Ok(added)
}
