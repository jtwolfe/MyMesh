//! MyMesh TUI — dashboard-style browser (keyboard + mouse).
use anyhow::Result;
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, MouseEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use mymesh_core::{ArmState, Config, DeviceStore, JoinStore, Paths, PeerMetrics};
use mymesh_crypto::{device_id_to_words, device_join_uri, Identity};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Tabs, Wrap};
use ratatui::{Frame, Terminal};
use std::io::{self, Stdout};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Dashboard,
    Peers,
    Link,
    Tools,
    Service,
}

impl Tab {
    const ALL: [Tab; 5] = [
        Tab::Dashboard,
        Tab::Peers,
        Tab::Link,
        Tab::Tools,
        Tab::Service,
    ];
    fn title(self) -> &'static str {
        match self {
            Tab::Dashboard => "Dashboard",
            Tab::Peers => "Peers",
            Tab::Link => "Link",
            Tab::Tools => "Tools",
            Tab::Service => "Service",
        }
    }
    fn idx(self) -> usize {
        Self::ALL.iter().position(|t| *t == self).unwrap_or(0)
    }
    fn from_idx(i: usize) -> Self {
        Self::ALL[i % Self::ALL.len()]
    }
}

struct App {
    paths: Paths,
    tab: Tab,
    peer_sel: usize,
    status: String,
    last_tick: Instant,
    should_quit: bool,
}

pub async fn run_tui(paths: Paths) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App {
        paths,
        tab: Tab::Dashboard,
        peer_sel: 0,
        status: "↑↓/Tab navigate · Enter action · q quit · mouse supported".into(),
        last_tick: Instant::now(),
        should_quit: false,
    };

    let res = run_loop(&mut terminal, &mut app).await;

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    res
}

async fn run_loop(
    terminal: &mut Terminal<ratatui::backend::CrosstermBackend<Stdout>>,
    app: &mut App,
) -> Result<()> {
    loop {
        terminal.draw(|f| ui(f, app))?;
        if app.should_quit {
            break;
        }
        if event::poll(Duration::from_millis(200))? {
            match event::read()? {
                Event::Key(k) if k.kind == KeyEventKind::Press => match k.code {
                    KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
                    KeyCode::Tab | KeyCode::Right | KeyCode::Char('l') => {
                        app.tab = Tab::from_idx(app.tab.idx() + 1);
                    }
                    KeyCode::BackTab | KeyCode::Left | KeyCode::Char('h') => {
                        app.tab = Tab::from_idx(app.tab.idx() + Tab::ALL.len() - 1);
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        app.peer_sel = app.peer_sel.saturating_add(1);
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        app.peer_sel = app.peer_sel.saturating_sub(1);
                    }
                    KeyCode::Char('1') => app.tab = Tab::Dashboard,
                    KeyCode::Char('2') => app.tab = Tab::Peers,
                    KeyCode::Char('3') => app.tab = Tab::Link,
                    KeyCode::Char('4') => app.tab = Tab::Tools,
                    KeyCode::Char('5') => app.tab = Tab::Service,
                    KeyCode::Enter | KeyCode::Char(' ') => {
                        handle_action(app).await;
                    }
                    KeyCode::Char('r') => {
                        app.status = "refreshed".into();
                    }
                    KeyCode::Char('a') if app.tab == Tab::Link => {
                        let cfg = Config::load(app.paths.config_file()).unwrap_or_default();
                        match ArmState::arm(app.paths.arm_file(), cfg.limits.arm_timeout_secs) {
                            Ok(s) => app.status = format!("ARMED until {:?}", s.until),
                            Err(e) => app.status = format!("arm failed: {e}"),
                        }
                    }
                    KeyCode::Char('d') if app.tab == Tab::Link => {
                        let _ = ArmState::disarm(app.paths.arm_file());
                        app.status = "disarmed".into();
                    }
                    KeyCode::Char('p') if app.tab == Tab::Peers || app.tab == Tab::Tools => {
                        if let Some(id) = selected_peer_id(app) {
                            app.status = format!("pinging {id}…");
                            // leave raw mode briefly for async? keep inside
                            match crate::probe::probe_ping(&app.paths, &id).await {
                                Ok(ms) => app.status = format!("ping {id}: {ms} ms"),
                                Err(e) => app.status = format!("ping failed: {e}"),
                            }
                        } else {
                            app.status = "no peer selected".into();
                        }
                    }
                    KeyCode::Char('b') if app.tab == Tab::Tools => {
                        if let Some(id) = selected_peer_id(app) {
                            app.status = format!("bandwidth test → {id} (1 MiB)…");
                            match crate::probe::probe_bandwidth(&app.paths, &id, 1024 * 1024).await
                            {
                                Ok(r) => {
                                    app.status = format!(
                                        "bw {:.2} Mbps ({} bytes in {} ms)",
                                        r.mbps, r.bytes, r.elapsed_ms
                                    )
                                }
                                Err(e) => app.status = format!("bw failed: {e}"),
                            }
                        }
                    }
                    KeyCode::Char('s') if app.tab == Tab::Service => {
                        match crate::install::cmd_service("start", false) {
                            Ok(()) => app.status = "service start ok".into(),
                            Err(e) => app.status = format!("start: {e}"),
                        }
                    }
                    KeyCode::Char('x') if app.tab == Tab::Service => {
                        match crate::install::cmd_service("stop", false) {
                            Ok(()) => app.status = "service stop ok".into(),
                            Err(e) => app.status = format!("stop: {e}"),
                        }
                    }
                    KeyCode::Char('y') if app.tab == Tab::Link => {
                        // accept first pending
                        if let Ok(joins) = JoinStore::open(app.paths.join_dir()) {
                            if let Ok(list) = joins.list_pending() {
                                if let Some(p) = list.first() {
                                    let _ = joins.write_decision(
                                        &p.device_id,
                                        mymesh_core::JoinDecision::Accept,
                                    );
                                    app.status = format!("accept written for {}", p.device_id.short());
                                } else {
                                    app.status = "no pending requests".into();
                                }
                            }
                        }
                    }
                    _ => {}
                },
                Event::Mouse(m) => {
                    if matches!(m.kind, MouseEventKind::Down(_)) && m.row <= 2 {
                        // tab bar click rough
                        let w = 16;
                        let idx = (m.column as usize) / w;
                        if idx < Tab::ALL.len() {
                            app.tab = Tab::from_idx(idx);
                        }
                    }
                }
                _ => {}
            }
        }
        if app.last_tick.elapsed() > Duration::from_secs(2) {
            app.last_tick = Instant::now();
        }
    }
    Ok(())
}

async fn handle_action(app: &mut App) {
    match app.tab {
        Tab::Peers => {
            if let Some(id) = selected_peer_id(app) {
                app.status = format!("shell → use CLI: mymesh shell {id}");
            }
        }
        Tab::Link => {
            app.status = "a arm · d disarm · y accept first pending".into();
        }
        Tab::Tools => {
            app.status = "p ping · b bandwidth".into();
        }
        Tab::Service => {
            app.status = "s start · x stop · or: mymesh service status".into();
        }
        Tab::Dashboard => {
            app.status = "1-5 tabs · q quit".into();
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

fn ui(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(3),
        ])
        .split(f.area());

    let titles: Vec<Line> = Tab::ALL
        .iter()
        .map(|t| Line::from(Span::raw(format!(" {} ", t.title()))))
        .collect();
    let tabs = Tabs::new(titles)
        .select(app.tab.idx())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" MyMesh ")
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );
    f.render_widget(tabs, chunks[0]);

    match app.tab {
        Tab::Dashboard => draw_dashboard(f, chunks[1], app),
        Tab::Peers => draw_peers(f, chunks[1], app),
        Tab::Link => draw_link(f, chunks[1], app),
        Tab::Tools => draw_tools(f, chunks[1], app),
        Tab::Service => draw_service(f, chunks[1], app),
    }

    let status = Paragraph::new(app.status.as_str())
        .block(Block::default().borders(Borders::ALL).title(" Status "));
    f.render_widget(status, chunks[2]);
}

fn draw_dashboard(f: &mut Frame, area: Rect, app: &App) {
    let id = Identity::load_or_create(app.paths.identity_file()).ok();
    let cfg = Config::load(app.paths.config_file()).unwrap_or_default();
    let store = DeviceStore::open(app.paths.devices_file()).ok();
    let arm = ArmState::load(app.paths.arm_file()).unwrap_or_default();
    let active = crate::install::service_is_active(false);

    let mut lines = vec![
        Line::from(vec![
            Span::styled("label  ", Style::default().fg(Color::DarkGray)),
            Span::raw(cfg.device_label.clone()),
        ]),
        Line::from(vec![
            Span::styled("service ", Style::default().fg(Color::DarkGray)),
            if active {
                Span::styled("active", Style::default().fg(Color::Green))
            } else {
                Span::styled("inactive", Style::default().fg(Color::Yellow))
            },
        ]),
        Line::from(vec![
            Span::styled("join    ", Style::default().fg(Color::DarkGray)),
            if arm.is_effectively_armed() {
                Span::styled(
                    format!("ARMED until {:?}", arm.until),
                    Style::default().fg(Color::Green),
                )
            } else {
                Span::styled("disarmed", Style::default().fg(Color::DarkGray))
            },
        ]),
        Line::from(vec![
            Span::styled("peers   ", Style::default().fg(Color::DarkGray)),
            Span::raw(format!(
                "{}",
                store.as_ref().map(|s| s.list().len()).unwrap_or(0)
            )),
        ]),
    ];
    if let Some(id) = id {
        let did = id.device_id();
        lines.push(Line::from(vec![
            Span::styled("hex     ", Style::default().fg(Color::DarkGray)),
            Span::raw(did.to_string()),
        ]));
        lines.push(Line::from(vec![
            Span::styled("short   ", Style::default().fg(Color::DarkGray)),
            Span::raw(did.short()),
        ]));
        if let Ok(w) = device_id_to_words(&did) {
            let short: String = w.split_whitespace().take(6).collect::<Vec<_>>().join(" ");
            lines.push(Line::from(vec![
                Span::styled("words   ", Style::default().fg(Color::DarkGray)),
                Span::raw(format!("{short} …")),
            ]));
        }
        if let Ok(uri) = device_join_uri(&did) {
            lines.push(Line::from(vec![
                Span::styled("uri     ", Style::default().fg(Color::DarkGray)),
                Span::raw(uri.clone()),
            ]));
            // tiny QR as braille-ish via qrcode unicode
            if let Ok(code) = qrcode::QrCode::new(uri.as_bytes()) {
                let qr = code
                    .render::<char>()
                    .quiet_zone(false)
                    .module_dimensions(1, 1)
                    .build();
                // only first few rows to fit
                for (i, row) in qr.lines().take(12).enumerate() {
                    if i == 0 {
                        lines.push(Line::from(Span::styled(
                            "qr      ",
                            Style::default().fg(Color::DarkGray),
                        )));
                    }
                    lines.push(Line::from(Span::raw(row.to_string())));
                }
            }
        }
    }
    let p = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(" This device "))
        .wrap(Wrap { trim: false });
    f.render_widget(p, area);
}

fn draw_peers(f: &mut Frame, area: Rect, app: &App) {
    let store = DeviceStore::open(app.paths.devices_file()).ok();
    let list = store.as_ref().map(|s| s.list()).unwrap_or_default();
    let items: Vec<ListItem> = if list.is_empty() {
        vec![ListItem::new("No linked peers — use Link tab or `mymesh link`")]
    } else {
        list.iter()
            .enumerate()
            .map(|(i, d)| {
                let m = PeerMetrics::load(app.paths.metrics_dir(), &d.id).ok();
                let rtt = m
                    .as_ref()
                    .and_then(|x| x.latest_rtt())
                    .map(|ms| format!("{ms}ms"))
                    .unwrap_or_else(|| "—".into());
                let rate = m
                    .as_ref()
                    .map(|x| format!("{:.0}%", x.success_rate() * 100.0))
                    .unwrap_or_else(|| "—".into());
                let n = m.as_ref().map(|x| x.samples.len()).unwrap_or(0);
                let sel = if i == app.peer_sel.min(list.len().saturating_sub(1)) {
                    "> "
                } else {
                    "  "
                };
                ListItem::new(format!(
                    "{sel}{}  {}  {:?}  rtt={rtt}  ok={rate}  n={n}",
                    d.id.short(),
                    d.label,
                    d.trust
                ))
            })
            .collect()
    };
    let w = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Peers (p = ping selected) "),
    );
    f.render_widget(w, area);
}

fn draw_link(f: &mut Frame, area: Rect, app: &App) {
    let arm = ArmState::load(app.paths.arm_file()).unwrap_or_default();
    let pending = JoinStore::open(app.paths.join_dir())
        .ok()
        .and_then(|j| j.list_pending().ok())
        .unwrap_or_default();
    let id = Identity::load_or_create(app.paths.identity_file()).ok();
    let mut text = String::new();
    text.push_str("Keys: a=arm  d=disarm  y=accept first pending\n\n");
    if arm.is_effectively_armed() {
        text.push_str(&format!("State: ARMED until {:?}\n", arm.until));
    } else {
        text.push_str("State: disarmed (joins rejected)\n");
    }
    if let Some(id) = id {
        text.push_str(&format!("\nYour hex:\n{}\n", id.device_id()));
        if let Ok(w) = device_id_to_words(&id.device_id()) {
            text.push_str(&format!("\nYour words:\n{w}\n"));
        }
    }
    text.push_str(&format!("\nPending requests: {}\n", pending.len()));
    for p in pending {
        text.push_str(&format!(
            "  {}  {}  fp={}\n",
            p.device_id.short(),
            p.label,
            p.fingerprint
        ));
    }
    let p = Paragraph::new(text)
        .block(Block::default().borders(Borders::ALL).title(" Link / join "))
        .wrap(Wrap { trim: false });
    f.render_widget(p, area);
}

fn draw_tools(f: &mut Frame, area: Rect, app: &App) {
    let store = DeviceStore::open(app.paths.devices_file()).ok();
    let list = store.as_ref().map(|s| s.list()).unwrap_or_default();
    let mut text = String::from("p = ping selected peer\nb = bandwidth test (1 MiB push)\n\n");
    if list.is_empty() {
        text.push_str("No peers.\n");
    } else {
        let i = app.peer_sel.min(list.len() - 1);
        let d = list[i];
        text.push_str(&format!("Selected: {} ({})\n", d.label, d.id.short()));
        if let Ok(m) = PeerMetrics::load(app.paths.metrics_dir(), &d.id) {
            text.push_str(&format!("Samples (last {}):\n", m.samples.len()));
            for s in m.samples.iter().rev().take(12) {
                text.push_str(&format!(
                    "  {}  {}\n",
                    s.at.format("%H:%M:%S"),
                    s.rtt_ms
                        .map(|ms| format!("{ms} ms"))
                        .unwrap_or_else(|| "fail".into())
                ));
            }
            if let Some(bw) = &m.last_bandwidth {
                text.push_str(&format!(
                    "\nLast bandwidth: {:.2} Mbps ({} bytes)\n",
                    bw.mbps, bw.bytes
                ));
            }
        }
    }
    // sparkline-ish of rtt
    let p = Paragraph::new(text)
        .block(Block::default().borders(Borders::ALL).title(" Tools / metrics "))
        .wrap(Wrap { trim: false });
    f.render_widget(p, area);
}

fn draw_service(f: &mut Frame, area: Rect, app: &App) {
    let active = crate::install::service_is_active(false);
    let marker = std::fs::read_to_string(app.paths.install_marker()).unwrap_or_default();
    let text = format!(
        "User service active: {}\n\n\
Keys: s=start  x=stop\n\n\
CLI:\n  mymesh install\n  mymesh uninstall [--purge]\n  mymesh service status|start|stop|restart\n  mymesh install --system   # root, warned\n\n\
Install marker:\n{}\n",
        if active { "yes" } else { "no" },
        if marker.is_empty() {
            "(not installed via mymesh install)".into()
        } else {
            marker
        }
    );
    let p = Paragraph::new(text)
        .block(Block::default().borders(Borders::ALL).title(" Service "))
        .wrap(Wrap { trim: false });
    f.render_widget(p, area);
}
