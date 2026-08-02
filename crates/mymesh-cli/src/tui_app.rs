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
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use ratatui::{Frame as TuiFrame, Terminal};
use std::io::{self, Stdout};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
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
    label: String,
    rect: Rect,
}

#[derive(Clone)]
struct LocalEntry {
    name: String,
    path: PathBuf,
    is_dir: bool,
    size: u64,
}

struct FileBrowser {
    local_cwd: PathBuf,
    remote_cwd: String,
    local: Vec<LocalEntry>,
    remote: Vec<FileEntry>,
    focus_remote: bool,
    local_sel: usize,
    remote_sel: usize,
    peer: Option<String>,
    busy: String,
}

struct TermPane {
    peer: Option<String>,
    lines: Vec<String>,
    input: String,
    scroll: usize,
    /// When active, stdin bytes go to remote
    active: bool,
    tx_out: Option<mpsc::UnboundedSender<Vec<u8>>>,
    rx_in: Option<mpsc::UnboundedReceiver<Vec<u8>>>,
    // keep session alive via task
    _shutdown: Option<mpsc::Sender<()>>,
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
    last_draw_size: (u16, u16),
    kick: KickWizard,
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
        paths,
        tab: Tab::Home,
        peer_sel: 0,
        status: "mouse · buttons · keys in [brackets] · Ctrl+C / q quit".into(),
        should_quit: false,
        tab_rects: vec![],
        buttons: vec![],
        content: Rect::default(),
        files: FileBrowser {
            local_cwd: home.clone(),
            remote_cwd: "~".into(),
            local: list_local(&home),
            remote: vec![],
            focus_remote: false,
            local_sel: 0,
            remote_sel: 0,
            peer: None,
            busy: String::new(),
        },
        term: TermPane {
            peer: None,
            lines: vec!["Select a peer on Peers, then open Term · Enter connects.".into()],
            input: String::new(),
            scroll: 0,
            active: false,
            tx_out: None,
            rx_in: None,
            _shutdown: None,
        },
        poll: PeerPoll {
            enabled: false,
            started: Instant::now(),
            last: Instant::now() - Duration::from_secs(100),
            interval: Duration::from_secs(10),
            max_duration: Duration::from_secs(300),
        },
        last_draw_size: (0, 0),
        kick: KickWizard::default(),
    };

    let res = run_loop(&mut terminal, &mut app).await;

    // teardown terminal session
    app.term.active = false;
    app.term.tx_out = None;

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

// ─── main loop ───────────────────────────────────────────────────────
async fn run_loop(
    terminal: &mut Terminal<ratatui::backend::CrosstermBackend<Stdout>>,
    app: &mut App,
) -> Result<()> {
    loop {
        // drain terminal output
        if let Some(rx) = app.term.rx_in.as_mut() {
            while let Ok(chunk) = rx.try_recv() {
                let s = String::from_utf8_lossy(&chunk);
                for part in s.split_inclusive('\n') {
                    if let Some(last) = app.term.lines.last_mut() {
                        if !last.ends_with('\n') && !part.contains('\n') {
                            last.push_str(part);
                            continue;
                        }
                    }
                    for line in part.lines() {
                        app.term.lines.push(line.to_string());
                    }
                    if part.ends_with('\n') {
                        app.term.lines.push(String::new());
                    }
                }
                if app.term.lines.len() > 2000 {
                    let n = app.term.lines.len() - 1500;
                    app.term.lines.drain(0..n);
                }
            }
        }

        // metrics poll
        if app.poll.enabled {
            if app.poll.started.elapsed() > app.poll.max_duration {
                app.poll.enabled = false;
                app.status = "metrics poll auto-stopped (5m remote window)".into();
            } else if app.poll.last.elapsed() >= app.poll.interval {
                if let Some(id) = selected_peer_id(app) {
                    app.poll.last = Instant::now();
                    match crate::probe::probe_host_metrics(&app.paths, &id).await {
                        Ok(s) => {
                            app.status = format!(
                                "metrics {} · CPU {:.0}% · mem {}/{}",
                                s.hostname,
                                s.cpu_pct,
                                human_bytes(s.mem_used_bytes),
                                human_bytes(s.mem_total_bytes)
                            );
                        }
                        Err(e) => app.status = format!("metrics err: {e}"),
                    }
                }
            }
        }

        terminal.draw(|f| ui(f, app))?;
        if app.should_quit {
            break;
        }

        if event::poll(Duration::from_millis(80))? {
            match event::read()? {
                Event::Key(k) if k.kind == KeyEventKind::Press => {
                    // Ctrl+C always quits
                    if k.modifiers.contains(KeyModifiers::CONTROL)
                        && (k.code == KeyCode::Char('c') || k.code == KeyCode::Char('C'))
                    {
                        app.should_quit = true;
                        continue;
                    }
                    handle_key(app, k.code, k.modifiers).await;
                }
                Event::Mouse(m) => {
                    if matches!(
                        m.kind,
                        MouseEventKind::Down(MouseButton::Left) | MouseEventKind::Up(MouseButton::Left)
                    ) {
                        // only handle Down
                        if matches!(m.kind, MouseEventKind::Down(MouseButton::Left)) {
                            handle_click(app, m.column, m.row).await;
                        }
                    }
                    if matches!(m.kind, MouseEventKind::ScrollDown) {
                        app.term.scroll = app.term.scroll.saturating_add(3);
                    }
                    if matches!(m.kind, MouseEventKind::ScrollUp) {
                        app.term.scroll = app.term.scroll.saturating_sub(3);
                    }
                }
                Event::Resize(_, _) => {}
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

    // terminal input mode
    if app.tab == Tab::Term && app.term.active {
        match code {
            KeyCode::Char(c) => {
                app.term.input.push(c);
                if let Some(tx) = &app.term.tx_out {
                    let _ = tx.send(c.to_string().into_bytes());
                }
            }
            KeyCode::Enter => {
                if let Some(tx) = &app.term.tx_out {
                    let _ = tx.send(b"\r".to_vec());
                }
                app.term.input.clear();
            }
            KeyCode::Backspace => {
                app.term.input.pop();
                if let Some(tx) = &app.term.tx_out {
                    let _ = tx.send(vec![0x7f]);
                }
            }
            KeyCode::Esc => {
                app.term.active = false;
                app.status = "left terminal input mode (Esc)".into();
            }
            _ => {}
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
                    app.files.peer = Some(id.clone());
                    app.term.peer = Some(id.clone());
                    app.status = format!("opened peer {id} · Files / Term ready");
                    app.tab = Tab::Peers;
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
            KeyCode::Char('s') => {
                if let Some(id) = selected_peer_id(app) {
                    app.term.peer = Some(id);
                    app.tab = Tab::Term;
                    app.status = "Term — press Enter to connect".into();
                }
            }
            KeyCode::Char('f') => {
                if let Some(id) = selected_peer_id(app) {
                    app.files.peer = Some(id);
                    app.tab = Tab::Files;
                    refresh_remote(app).await;
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
            KeyCode::Down | KeyCode::Char('j') => {
                if app.files.focus_remote {
                    app.files.remote_sel = app.files.remote_sel.saturating_add(1);
                } else {
                    app.files.local_sel = app.files.local_sel.saturating_add(1);
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if app.files.focus_remote {
                    app.files.remote_sel = app.files.remote_sel.saturating_sub(1);
                } else {
                    app.files.local_sel = app.files.local_sel.saturating_sub(1);
                }
            }
            KeyCode::Left | KeyCode::Char('h') => app.files.focus_remote = false,
            KeyCode::Right | KeyCode::Char('l') => app.files.focus_remote = true,
            KeyCode::Tab => app.files.focus_remote = !app.files.focus_remote,
            KeyCode::Enter => enter_file(app).await,
            KeyCode::Char('c') => copy_selected(app).await,
            KeyCode::Char('r') => refresh_remote(app).await,
            KeyCode::Char('u') => {
                if !app.files.focus_remote {
                    if let Some(p) = app.files.local_cwd.parent() {
                        app.files.local_cwd = p.to_path_buf();
                        app.files.local = list_local(&app.files.local_cwd);
                        app.files.local_sel = 0;
                    }
                }
            }
            _ => {}
        },
        Tab::Term => match code {
            KeyCode::Enter => connect_term(app).await,
            KeyCode::Char('i') => {
                if app.term.tx_out.is_some() {
                    app.term.active = true;
                    app.status = "terminal input mode · Esc to leave · Ctrl+C quit app".into();
                } else {
                    app.status = "connect first (Enter)".into();
                }
            }
            KeyCode::Char('x') => {
                app.term.active = false;
                app.term.tx_out = None;
                app.term.rx_in = None;
                app.term.lines.push("--- disconnected ---".into());
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
    // file panes / peer list rough: content area
    if rect_contains(app.content, col, row) && app.tab == Tab::Files {
        let mid = app.content.x + app.content.width / 2;
        app.files.focus_remote = col >= mid;
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
        "open_files" => {
            if let Some(id) = selected_peer_id(app) {
                app.files.peer = Some(id);
                app.tab = Tab::Files;
                refresh_remote(app).await;
            }
        }
        "open_term" => {
            if let Some(id) = selected_peer_id(app) {
                app.term.peer = Some(id);
                app.tab = Tab::Term;
            }
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
        "copy_lr" => copy_selected(app).await,
        "refresh_remote" => refresh_remote(app).await,
        "term_connect" => connect_term(app).await,
        "term_input" => {
            app.term.active = true;
            app.status = "terminal input mode".into();
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

async fn refresh_remote(app: &mut App) {
    let Some(peer) = app.files.peer.clone().or_else(|| selected_peer_id(app)) else {
        app.status = "select a peer first".into();
        return;
    };
    app.files.peer = Some(peer.clone());
    app.files.busy = "listing…".into();
    let path = if app.files.remote_cwd == "~" {
        // agent sandbox is home; list "."
        ".".into()
    } else {
        app.files.remote_cwd.clone()
    };
    match crate::probe::remote_list(&app.paths, &peer, &path).await {
        Ok(entries) => {
            app.files.remote = entries;
            app.files.remote_sel = 0;
            app.files.busy.clear();
            app.status = format!("remote {} entries", app.files.remote.len());
        }
        Err(e) => {
            app.files.busy = e.to_string();
            app.status = format!("list: {e}");
        }
    }
}

async fn enter_file(app: &mut App) {
    if app.files.focus_remote {
        if app.files.remote.is_empty() {
            return;
        }
        let i = app.files.remote_sel.min(app.files.remote.len() - 1);
        let e = app.files.remote[i].clone();
        if e.is_dir {
            app.files.remote_cwd = e.path.clone();
            refresh_remote(app).await;
        }
    } else {
        if app.files.local.is_empty() {
            return;
        }
        let i = app.files.local_sel.min(app.files.local.len() - 1);
        let e = app.files.local[i].clone();
        if e.is_dir {
            app.files.local_cwd = e.path.clone();
            app.files.local = list_local(&app.files.local_cwd);
            app.files.local_sel = 0;
        }
    }
}

async fn copy_selected(app: &mut App) {
    let Some(peer) = app.files.peer.clone().or_else(|| selected_peer_id(app)) else {
        app.status = "no peer".into();
        return;
    };
    if app.files.focus_remote {
        // remote → local
        if app.files.remote.is_empty() {
            return;
        }
        let i = app.files.remote_sel.min(app.files.remote.len() - 1);
        let e = &app.files.remote[i];
        if e.is_dir {
            app.status = "pick a file (not dir)".into();
            return;
        }
        let dest = app.files.local_cwd.join(&e.name);
        app.status = format!("pull {}…", e.path);
        // use CLI cp logic via probe-style
        match pull_file_helper(&app.paths, &peer, &e.path, &dest).await {
            Ok(()) => app.status = format!("pulled → {}", dest.display()),
            Err(e) => app.status = format!("pull: {e}"),
        }
    } else {
        if app.files.local.is_empty() {
            return;
        }
        let i = app.files.local_sel.min(app.files.local.len() - 1);
        let e = &app.files.local[i];
        if e.is_dir {
            app.status = "pick a file (not dir)".into();
            return;
        }
        let remote = if app.files.remote_cwd == "~" || app.files.remote_cwd == "." {
            e.name.clone()
        } else {
            format!("{}/{}", app.files.remote_cwd.trim_end_matches('/'), e.name)
        };
        app.status = format!("push {}…", e.name);
        match push_file_helper(&app.paths, &e.path, &peer, &remote).await {
            Ok(()) => app.status = format!("pushed → {peer}:{remote}"),
            Err(e) => app.status = format!("push: {e}"),
        }
    }
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

async fn connect_term(app: &mut App) {
    let Some(peer) = app.term.peer.clone().or_else(|| selected_peer_id(app)) else {
        app.status = "no peer — open from Peers".into();
        return;
    };
    app.term.peer = Some(peer.clone());
    app.term.lines.push(format!("connecting to {peer}…"));
    // Spawn session task
    let paths = app.paths.clone();
    let (tx_out, mut rx_out) = mpsc::unbounded_channel::<Vec<u8>>();
    let (tx_in, rx_in) = mpsc::unbounded_channel::<Vec<u8>>();
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

    tokio::spawn(async move {
        let err_tx = tx_in.clone();
        if let Err(e) = term_session_task(paths, peer, tx_in, &mut rx_out, &mut shutdown_rx).await {
            let _ = err_tx.send(format!("\r\n[session error: {e}]\r\n").into_bytes());
        }
    });

    app.term.tx_out = Some(tx_out);
    app.term.rx_in = Some(rx_in);
    app.term._shutdown = Some(shutdown_tx);
    app.term.active = true;
    app.status = "terminal connected · typing goes remote · Esc detach · Ctrl+C quit".into();
}

async fn term_session_task(
    paths: Paths,
    device: String,
    tx_in: mpsc::UnboundedSender<Vec<u8>>,
    rx_out: &mut mpsc::UnboundedReceiver<Vec<u8>>,
    shutdown: &mut mpsc::Receiver<()>,
) -> anyhow::Result<()> {
    use mymesh_core::{Capability, Config, DeviceStore};
    use mymesh_crypto::Identity;
    use mymesh_net::{IrohTransport, Transport};
    use mymesh_protocol::{decode_msg, encode_msg, ChannelId, Frame, TerminalMessage};
    use mymesh_session::Session;

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
    let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
    session
        .send_raw(
            ChannelId::terminal(1),
            encode_msg(&TerminalMessage::Open {
                cols,
                rows: rows.saturating_sub(8),
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
                    TerminalMessage::Output(data) => {
                        let _ = tx_in.send(data);
                    }
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

// ─── UI ──────────────────────────────────────────────────────────────
fn ui(f: &mut TuiFrame, app: &mut App) {
    app.buttons.clear();
    app.tab_rects.clear();

    let root = f.area();
    // dark background
    f.render_widget(
        Block::default().style(Style::default().bg(C_BG).fg(C_TEXT)),
        root,
    );

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // title + tabs
            Constraint::Length(3), // action buttons
            Constraint::Min(8),    // content
            Constraint::Length(2), // status
        ])
        .split(root);

    draw_header(f, chunks[0], app);
    draw_action_bar(f, chunks[1], app);
    app.content = chunks[2];
    match app.tab {
        Tab::Home => draw_home(f, chunks[2], app),
        Tab::Peers => draw_peers(f, chunks[2], app),
        Tab::Files => draw_files(f, chunks[2], app),
        Tab::Term => draw_term(f, chunks[2], app),
        Tab::Status => draw_status(f, chunks[2], app),
    }
    draw_status_line(f, chunks[3], app);
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
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(14), Constraint::Min(10), Constraint::Length(18)])
        .split(area);

    let brand = Paragraph::new(Line::from(vec![
        Span::styled(" ◆ ", Style::default().fg(C_ACCENT2)),
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

    // tab buttons with exact rects (account for borders: x+1)
    let n = Tab::ALL.len() as u16;
    let tab_area = cols[1];
    let inner_w = tab_area.width.saturating_sub(2);
    let slot = if n == 0 { 1 } else { inner_w / n };
    let mut x = tab_area.x.saturating_add(1);
    let y = tab_area.y.saturating_add(1);
    // background
    f.render_widget(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(C_BORDER))
            .style(Style::default().bg(C_PANEL)),
        tab_area,
    );
    for tab in Tab::ALL {
        let w = slot.max(8).min(16);
        let r = Rect {
            x,
            y,
            width: w.saturating_sub(1).max(1),
            height: 1,
        };
        app.tab_rects.push((tab, r));
        let selected = app.tab == tab;
        let label = format!("[{}]{}", tab.key(), tab.title());
        let style = if selected {
            Style::default()
                .fg(Color::Black)
                .bg(C_ACCENT)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(C_MUTED).bg(C_BTN)
        };
        f.render_widget(Paragraph::new(label).style(style).alignment(Alignment::Center), r);
        x = x.saturating_add(w);
    }

    let ver = Paragraph::new(Line::from(Span::styled(
        format!(" v{} ", env!("CARGO_PKG_VERSION")),
        Style::default().fg(C_MUTED),
    )))
    .alignment(Alignment::Right)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(C_BORDER))
            .style(Style::default().bg(C_PANEL)),
    );
    f.render_widget(ver, cols[2]);
}

fn push_btn(app: &mut App, f: &mut TuiFrame, id: &'static str, label: &str, rect: Rect, hot: bool) {
    app.buttons.push(Btn {
        id,
        label: label.into(),
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
    f.render_widget(
        Paragraph::new(label)
            .style(style)
            .alignment(Alignment::Center)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(if hot { C_ACCENT } else { C_BORDER })),
            ),
        rect,
    );
}

fn draw_action_bar(f: &mut TuiFrame, area: Rect, app: &mut App) {
    f.render_widget(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(C_BORDER))
            .title(Span::styled(" actions ", Style::default().fg(C_MUTED)))
            .style(Style::default().bg(C_PANEL)),
        area,
    );
    let inner = Rect {
        x: area.x + 1,
        y: area.y,
        width: area.width.saturating_sub(2),
        height: area.height,
    };
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
            ("open_files", "[f] Files"),
            ("open_term", "[s] Shell"),
            ("quit", "[q] Quit"),
        ],
        Tab::Files => vec![
            ("copy_lr", "[c] Copy"),
            ("refresh_remote", "[r] Refresh"),
            ("quit", "[q] Quit"),
        ],
        Tab::Term => vec![
            ("term_connect", "[Enter] Connect"),
            ("term_input", "[i] Type"),
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
    if n == 0 || inner.width < 4 {
        return;
    }
    let slot = (inner.width / n).max(8);
    let mut x = inner.x;
    for (id, label) in specs {
        let w = slot.min(18).min(inner.x + inner.width - x);
        if w < 6 {
            break;
        }
        let r = Rect {
            x,
            y: inner.y,
            width: w.saturating_sub(1).max(5),
            height: 3,
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

fn draw_files(f: &mut TuiFrame, area: Rect, app: &App) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // local
    let local_items: Vec<ListItem> = app
        .files
        .local
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let sel = !app.files.focus_remote && i == app.files.local_sel.min(app.files.local.len().saturating_sub(1));
            let icon = if e.is_dir { "📁" } else { "📄" };
            let size = if e.is_dir {
                String::new()
            } else {
                format!("  {}", human_bytes(e.size))
            };
            let text = format!("{icon} {}{size}", e.name);
            ListItem::new(Line::from(Span::styled(
                text,
                if sel {
                    Style::default().fg(Color::Black).bg(C_ACCENT)
                } else if e.is_dir {
                    Style::default().fg(C_ACCENT2)
                } else {
                    Style::default().fg(C_TEXT)
                },
            )))
        })
        .collect();
    let local_title = format!(
        "Local {} {}",
        app.files.local_cwd.display(),
        if !app.files.focus_remote { "◀" } else { "" }
    );
    f.render_widget(
        List::new(local_items).block(panel(&local_title)),
        cols[0],
    );

    // remote
    let remote_items: Vec<ListItem> = if app.files.remote.is_empty() {
        vec![ListItem::new(Span::styled(
            if app.files.busy.is_empty() {
                "Empty or not loaded — [r] refresh (peer agent must run)"
            } else {
                app.files.busy.as_str()
            },
            Style::default().fg(C_MUTED),
        ))]
    } else {
        app.files
            .remote
            .iter()
            .enumerate()
            .map(|(i, e)| {
                let sel = app.files.focus_remote
                    && i == app.files.remote_sel.min(app.files.remote.len().saturating_sub(1));
                let icon = if e.is_dir { "📁" } else { "📄" };
                let size = if e.is_dir {
                    String::new()
                } else {
                    format!("  {}", human_bytes(e.size))
                };
                let text = format!("{icon} {}{size}", e.name);
                ListItem::new(Line::from(Span::styled(
                    text,
                    if sel {
                        Style::default().fg(Color::Black).bg(C_ACCENT)
                    } else if e.is_dir {
                        Style::default().fg(C_ACCENT2)
                    } else {
                        Style::default().fg(C_TEXT)
                    },
                )))
            })
            .collect()
    };
    let peer = app
        .files
        .peer
        .as_deref()
        .unwrap_or("(no peer)");
    let remote_title = format!(
        "Remote {peer}:{} {} {}",
        app.files.remote_cwd,
        if app.files.focus_remote { "◀" } else { "" },
        if app.files.busy.is_empty() {
            ""
        } else {
            "…"
        }
    );
    f.render_widget(
        List::new(remote_items).block(panel(&remote_title)),
        cols[1],
    );
}

fn draw_term(f: &mut TuiFrame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(5), Constraint::Length(3)])
        .split(area);

    let peer = app.term.peer.as_deref().unwrap_or("(no peer)");
    let h = chunks[0].height.saturating_sub(2) as usize;
    let total = app.term.lines.len();
    let start = total.saturating_sub(h + app.term.scroll);
    let end = (start + h).min(total);
    let body: Vec<Line> = app.term.lines[start..end]
        .iter()
        .map(|l| Line::from(l.clone()))
        .collect();
    f.render_widget(
        Paragraph::new(body)
            .block(panel(&format!(
                "Terminal · {peer} · {}",
                if app.term.active {
                    "INPUT"
                } else {
                    "view"
                }
            )))
            .wrap(Wrap { trim: false }),
        chunks[0],
    );

    let input = Paragraph::new(format!("❯ {}", app.term.input))
        .block(panel("Input (i = type, Esc = leave input)"));
    f.render_widget(input, chunks[1]);
}

fn draw_status(f: &mut TuiFrame, area: Rect, app: &App) {
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
    let p = Paragraph::new(Line::from(vec![
        Span::styled(" │ ", Style::default().fg(C_BORDER)),
        Span::styled(&app.status, Style::default().fg(C_TEXT)),
    ]))
    .block(
        Block::default()
            .borders(Borders::TOP)
            .border_style(Style::default().fg(C_BORDER))
            .style(Style::default().bg(C_BG)),
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

async fn run_kick(paths: &Paths, device: &str, force: bool) -> anyhow::Result<String> {
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
