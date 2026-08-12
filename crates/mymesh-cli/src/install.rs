//! Install / uninstall / reset lifecycle + systemd units.
use anyhow::{bail, Context, Result};
use chrono::Utc;
use console::style;
use mymesh_core::{DeviceStore, Paths};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InstallMode {
    User,
    System,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InstallMarker {
    pub mode: InstallMode,
    pub binary_path: PathBuf,
    pub unit_path: PathBuf,
    pub runtime_user: String,
    pub installed_at: String,
    pub version: String,
}

fn current_user() -> String {
    env::var("USER")
        .or_else(|_| env::var("LOGNAME"))
        .unwrap_or_else(|_| "unknown".into())
}

fn is_root() -> bool {
    // portable-ish: uid 0
    #[cfg(unix)]
    {
        libc_geteuid() == 0
    }
    #[cfg(not(unix))]
    {
        false
    }
}

#[cfg(unix)]
fn libc_geteuid() -> u32 {
    // avoid libc crate: read /proc
    if let Ok(s) = fs::read_to_string("/proc/self/status") {
        for line in s.lines() {
            if let Some(rest) = line.strip_prefix("Uid:") {
                let uid: u32 = rest
                    .split_whitespace()
                    .next()
                    .unwrap_or("1")
                    .parse()
                    .unwrap_or(1);
                return uid;
            }
        }
    }
    1
}

fn exe_path() -> Result<PathBuf> {
    env::current_exe().context("current_exe")
}

fn user_bin_dir() -> PathBuf {
    env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".local/bin")
}

fn user_unit_dir() -> PathBuf {
    env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".config/systemd/user")
}

fn user_completion_dirs() -> (PathBuf, PathBuf) {
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    (
        home.join(".local/share/bash-completion/completions"),
        home.join(".local/share/zsh/site-functions"),
    )
}

fn system_unit_path() -> PathBuf {
    PathBuf::from("/etc/systemd/system/mymesh.service")
}

fn system_bin_path() -> PathBuf {
    PathBuf::from("/usr/local/bin/mymesh")
}

fn render_user_unit(binary: &Path) -> String {
    format!(
        r#"[Unit]
Description=MyMesh peer agent
Documentation=https://github.com/jtwolfe/MyMesh
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={bin} serve --foreground
Restart=always
RestartSec=3
Environment=RUST_LOG=mymesh=info

[Install]
WantedBy=default.target
"#,
        bin = binary.display()
    )
}

fn render_system_unit(binary: &Path, user: &str) -> String {
    format!(
        r#"[Unit]
Description=MyMesh peer agent
Documentation=https://github.com/jtwolfe/MyMesh
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User={user}
Group={user}
ExecStart={bin} serve --foreground
Restart=always
RestartSec=3
Environment=RUST_LOG=mymesh=info
# State lives in the service user's XDG dirs

[Install]
WantedBy=multi-user.target
"#,
        user = user,
        bin = binary.display()
    )
}

fn write_file(path: &Path, contents: &str, mode: u32) -> Result<()> {
    if let Some(p) = path.parent() {
        fs::create_dir_all(p)?;
    }
    fs::write(path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    let _ = mode;
    Ok(())
}

fn run(cmd: &str, args: &[&str]) -> Result<()> {
    let st = Command::new(cmd).args(args).status();
    match st {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => bail!("{cmd} {:?} failed with {s}", args),
        Err(e) => bail!("failed to run {cmd}: {e}"),
    }
}

fn try_run(cmd: &str, args: &[&str]) {
    let _ = Command::new(cmd).args(args).status();
}

pub fn cmd_install(
    paths: &Paths,
    system: bool,
    accept_root_agent: bool,
    runtime_user: Option<String>,
) -> Result<()> {
    paths.ensure()?;
    if system {
        return install_system(paths, accept_root_agent, runtime_user);
    }
    install_user(paths)
}

fn install_user(paths: &Paths) -> Result<()> {
    let user = current_user();
    let src = exe_path()?;
    let bin = user_bin_dir().join("mymesh");
    fs::create_dir_all(user_bin_dir())?;
    fs::copy(&src, &bin).with_context(|| format!("copy binary to {}", bin.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o755))?;
    }

    let unit_dir = user_unit_dir();
    let unit = unit_dir.join("mymesh.service");
    write_file(&unit, &render_user_unit(&bin), 0o644)?;

    // completions
    install_completions_user()?;

    let marker = InstallMarker {
        mode: InstallMode::User,
        binary_path: bin.clone(),
        unit_path: unit.clone(),
        runtime_user: user.clone(),
        installed_at: Utc::now().to_rfc3339(),
        version: env!("CARGO_PKG_VERSION").into(),
    };
    fs::write(
        paths.install_marker(),
        serde_json::to_string_pretty(&marker)?,
    )?;

    try_run("systemctl", &["--user", "daemon-reload"]);
    try_run(
        "systemctl",
        &["--user", "enable", "--now", "mymesh.service"],
    );

    println!(
        "{} user install as {}",
        style("ok").green().bold(),
        style(&user).cyan()
    );
    println!("  binary  {}", bin.display());
    println!("  unit    {}", unit.display());
    println!("  status  systemctl --user status mymesh");
    println!(
        "  note    enable lingering if needed: {}",
        style("loginctl enable-linger $USER").dim()
    );
    if !user_bin_dir_on_path() {
        println!(
            "  warn    add {} to PATH",
            style(user_bin_dir().display()).yellow()
        );
    }
    Ok(())
}

fn user_bin_dir_on_path() -> bool {
    let bin = user_bin_dir();
    env::var_os("PATH")
        .map(|p| env::split_paths(&p).any(|x| x == bin))
        .unwrap_or(false)
}

fn install_system(
    paths: &Paths,
    accept_root_agent: bool,
    runtime_user: Option<String>,
) -> Result<()> {
    if !is_root() {
        bail!("system install requires root (try: sudo mymesh install --system)");
    }

    println!(
        "{}",
        style("╔══════════════════════════════════════════════════════╗").red()
    );
    println!(
        "{}",
        style("║  SYSTEM INSTALL — privileged operation               ║").red()
    );
    println!(
        "{}",
        style("║  Default is user install without sudo.               ║").red()
    );
    println!(
        "{}",
        style("╚══════════════════════════════════════════════════════╝").red()
    );

    let user = runtime_user.unwrap_or_else(|| "mymesh".into());
    if user == "root" && !accept_root_agent {
        bail!(
            "refusing to run MyMesh agent as root.\n\
             Use --runtime-user <name> (default: mymesh) or pass --i-accept-root-agent"
        );
    }
    if user == "root" && accept_root_agent {
        println!(
            "{}",
            style("WARNING: agent will run as root — full machine access for any trusted peer")
                .red()
                .bold()
        );
    }

    // ensure runtime user exists for non-root
    if user != "root" {
        let id = Command::new("id").arg(&user).status();
        if !matches!(id, Ok(s) if s.success()) {
            println!("creating system user {user}…");
            // useradd -r -s /usr/sbin/nologin -d /var/lib/mymesh mymesh
            let _ = Command::new("useradd")
                .args([
                    "-r",
                    "-s",
                    "/usr/sbin/nologin",
                    "-d",
                    "/var/lib/mymesh",
                    "-U",
                    &user,
                ])
                .status();
            let _ = fs::create_dir_all("/var/lib/mymesh");
            let _ = Command::new("chown")
                .args([&format!("{user}:{user}"), "/var/lib/mymesh"])
                .status();
        }
    }

    let src = exe_path()?;
    let bin = system_bin_path();
    fs::copy(&src, &bin).with_context(|| format!("copy to {}", bin.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o755))?;
    }

    let unit = system_unit_path();
    write_file(&unit, &render_system_unit(&bin, &user), 0o644)?;

    // system completions
    let bash = PathBuf::from("/usr/share/bash-completion/completions/mymesh");
    let zsh = PathBuf::from("/usr/local/share/zsh/site-functions/_mymesh");
    let fish = PathBuf::from("/usr/share/fish/vendor_completions.d/mymesh.fish");
    write_completions_to(&bash, &zsh, Some(&fish))?;

    let marker = InstallMarker {
        mode: InstallMode::System,
        binary_path: bin.clone(),
        unit_path: unit.clone(),
        runtime_user: user.clone(),
        installed_at: Utc::now().to_rfc3339(),
        version: env!("CARGO_PKG_VERSION").into(),
    };
    // also store under /etc
    let _ = fs::create_dir_all("/etc/mymesh");
    fs::write(
        "/etc/mymesh/install.json",
        serde_json::to_string_pretty(&marker)?,
    )?;
    // and user paths if available
    let _ = fs::write(
        paths.install_marker(),
        serde_json::to_string_pretty(&marker)?,
    );

    run("systemctl", &["daemon-reload"])?;
    run("systemctl", &["enable", "--now", "mymesh.service"])?;

    println!(
        "{} system install runtime_user={}",
        style("ok").green().bold(),
        user
    );
    println!("  binary  {}", bin.display());
    println!("  unit    {}", unit.display());
    println!("  status  systemctl status mymesh");
    Ok(())
}

fn write_completions_to(bash: &Path, zsh: &Path, fish: Option<&Path>) -> Result<()> {
    use clap::CommandFactory;
    use clap_complete::{generate, shells::Bash, shells::Fish, shells::Zsh};
    use std::io::Write;

    // Rebuild command each time so generate state is clean.
    let write_one = |path: &Path, kind: &str| -> Result<()> {
        if let Some(p) = path.parent() {
            let _ = fs::create_dir_all(p);
        }
        let mut cmd = crate::Cli::command();
        let mut f = fs::File::create(path)?;
        match kind {
            "bash" => generate(Bash, &mut cmd, "mymesh", &mut f),
            "zsh" => generate(Zsh, &mut cmd, "mymesh", &mut f),
            "fish" => generate(Fish, &mut cmd, "mymesh", &mut f),
            _ => unreachable!(),
        }
        f.flush()?;
        Ok(())
    };
    write_one(bash, "bash")?;
    write_one(zsh, "zsh")?;
    if let Some(fish) = fish {
        write_one(fish, "fish")?;
    }
    Ok(())
}

fn install_completions_user() -> Result<()> {
    let (bash_dir, zsh_dir) = user_completion_dirs();
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let fish_dir = home.join(".config/fish/completions");
    let bash = bash_dir.join("mymesh");
    let zsh = zsh_dir.join("_mymesh");
    let fish = fish_dir.join("mymesh.fish");
    write_completions_to(&bash, &zsh, Some(&fish))?;
    println!(
        "  completions bash={} zsh={} fish={}",
        bash.display(),
        zsh.display(),
        fish.display()
    );
    println!(
        "  reload   {}",
        style("source the file or open a new shell").dim()
    );
    Ok(())
}

pub fn cmd_completions(shell: &str, out: Option<PathBuf>) -> Result<()> {
    use clap::CommandFactory;
    use clap_complete::{generate, shells::Bash, shells::Fish, shells::Zsh};
    use std::io::{self, Write};

    let mut cmd = crate::Cli::command();
    let mut buf = Vec::new();
    match shell {
        "bash" => generate(Bash, &mut cmd, "mymesh", &mut buf),
        "zsh" => generate(Zsh, &mut cmd, "mymesh", &mut buf),
        "fish" => generate(Fish, &mut cmd, "mymesh", &mut buf),
        other => bail!("unsupported shell '{other}' (use: bash | zsh | fish)"),
    }
    let text = std::str::from_utf8(&buf).unwrap_or("");
    completion_covers_surface(text)?;
    if let Some(path) = out {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        fs::write(&path, &buf)?;
        println!(
            "{} wrote {} bytes → {}",
            style("ok").green().bold(),
            buf.len(),
            path.display()
        );
    } else {
        io::stdout().write_all(&buf)?;
    }
    Ok(())
}

/// Assert generated completion script mentions key subcommands (used by install checks / tests).
pub fn completion_covers_surface(script: &str) -> Result<()> {
    let required = [
        "tui",
        "status",
        "init",
        "link",
        "connect-request",
        "requests",
        "devices",
        "shell",
        "cp",
        "ping",
        "bw",
        "serve",
        "install",
        "service",
        "mesh",
        "kick",
        "hosts",
        "label",
        "alias",
        "group",
        "resolve",
        "ssh-config",
        "proxy-ssh",
        "expose",
        "carrier",
        "magic",
        "firewall",
        "explain",
        "completions",
    ];
    let missing: Vec<_> = required
        .iter()
        .filter(|k| !script.contains(*k))
        .copied()
        .collect();
    if !missing.is_empty() {
        bail!("completion script missing subcommands: {missing:?}");
    }
    Ok(())
}

pub fn cmd_uninstall(paths: &Paths, purge: bool) -> Result<()> {
    let marker = load_marker(paths);
    match marker {
        Some(m) if m.mode == InstallMode::System => {
            if !is_root() {
                bail!("system uninstall requires root");
            }
            try_run("systemctl", &["disable", "--now", "mymesh.service"]);
            let _ = fs::remove_file(&m.unit_path);
            let _ = fs::remove_file(&m.binary_path);
            let _ = fs::remove_file("/etc/mymesh/install.json");
            try_run("systemctl", &["daemon-reload"]);
        }
        Some(m) => {
            try_run(
                "systemctl",
                &["--user", "disable", "--now", "mymesh.service"],
            );
            let _ = fs::remove_file(&m.unit_path);
            // only remove binary if it looks like our install path
            if m.binary_path.ends_with("mymesh") {
                let _ = fs::remove_file(&m.binary_path);
            }
            try_run("systemctl", &["--user", "daemon-reload"]);
        }
        None => {
            // best effort user unit
            try_run(
                "systemctl",
                &["--user", "disable", "--now", "mymesh.service"],
            );
            let _ = fs::remove_file(user_unit_dir().join("mymesh.service"));
        }
    }
    let _ = fs::remove_file(paths.install_marker());

    if purge {
        println!("purging identity, devices, config…");
        let _ = fs::remove_dir_all(&paths.data_dir);
        let _ = fs::remove_dir_all(&paths.config_dir);
        let _ = fs::remove_dir_all(&paths.cache_dir);
    }

    println!(
        "{} uninstalled{}",
        style("ok").green().bold(),
        if purge {
            " (purged data)"
        } else {
            " (data kept)"
        }
    );
    Ok(())
}

fn load_marker(paths: &Paths) -> Option<InstallMarker> {
    let p = paths.install_marker();
    if p.exists() {
        if let Ok(raw) = fs::read_to_string(p) {
            if let Ok(m) = serde_json::from_str(&raw) {
                return Some(m);
            }
        }
    }
    let p = PathBuf::from("/etc/mymesh/install.json");
    if p.exists() {
        if let Ok(raw) = fs::read_to_string(p) {
            if let Ok(m) = serde_json::from_str(&raw) {
                return Some(m);
            }
        }
    }
    None
}

pub fn cmd_reset(paths: &Paths, links: bool, identity: bool) -> Result<()> {
    if !links && !identity {
        bail!("specify --links and/or --identity");
    }
    paths.ensure()?;
    if links {
        let store = DeviceStore::open(paths.devices_file())?;
        // rewrite empty
        fs::write(paths.devices_file(), "{\"devices\":{}}\n")?;
        let _ = fs::remove_dir_all(paths.join_dir());
        let _ = fs::remove_dir_all(paths.metrics_dir());
        let _ = store; // opened to ensure path ok
        println!(
            "{} cleared device links + join/metrics state",
            style("ok").green().bold()
        );
    }
    if identity {
        let id_path = paths.identity_file();
        if id_path.exists() {
            fs::remove_file(&id_path)?;
        }
        println!(
            "{} removed identity — run `mymesh init` (peers must re-link)",
            style("ok").green().bold()
        );
    }
    Ok(())
}

pub fn cmd_service(action: &str, system: bool) -> Result<()> {
    let user = !system;
    match action {
        "status" => {
            if user {
                run("systemctl", &["--user", "status", "mymesh.service"])?;
            } else {
                run("systemctl", &["status", "mymesh.service"])?;
            }
        }
        "start" => {
            if user {
                run("systemctl", &["--user", "start", "mymesh.service"])?;
            } else {
                run("systemctl", &["start", "mymesh.service"])?;
            }
            println!("{} started", style("ok").green().bold());
        }
        "stop" => {
            if user {
                run("systemctl", &["--user", "stop", "mymesh.service"])?;
            } else {
                run("systemctl", &["stop", "mymesh.service"])?;
            }
            println!("{} stopped", style("ok").green().bold());
        }
        "restart" => {
            if user {
                run("systemctl", &["--user", "restart", "mymesh.service"])?;
            } else {
                run("systemctl", &["restart", "mymesh.service"])?;
            }
            println!("{} restarted", style("ok").green().bold());
        }
        other => bail!("unknown service action {other}"),
    }
    Ok(())
}

pub fn service_is_active(system: bool) -> bool {
    let mut c = Command::new("systemctl");
    if !system {
        c.arg("--user");
    }
    matches!(
        c.args(["is-active", "--quiet", "mymesh.service"]).status(),
        Ok(s) if s.success()
    )
}
