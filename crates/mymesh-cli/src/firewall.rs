//! Explicit host firewall helpers (ufw / firewalld). Never auto-run on install/serve.
use anyhow::{bail, Context, Result};
use console::style;
use std::path::PathBuf;
use std::process::Command;

/// Ports MyMesh may need inbound on a LAN-facing host.
pub const CARRIER_TCP: u16 = 17878;
pub const RULE_COMMENT: &str = "mymesh-carrier";

/// Absolute path to this running binary (best effort).
pub fn mymesh_bin() -> PathBuf {
    std::env::current_exe().unwrap_or_else(|_| PathBuf::from("mymesh"))
}

/// Exact sudo invocation for a firewall subcommand, e.g. `ufw allow`.
pub fn sudo_firewall_cmd(rest: &str) -> String {
    let bin = mymesh_bin();
    format!("sudo {} firewall {}", bin.display(), rest.trim())
}

fn root_required_msg(action: &str) -> String {
    format!(
        "firewall {action} requires root (elevated privileges).\n\n\
         From a terminal, run exactly:\n\n  {}\n\n\
         Tip: use the installed path if different from this binary.\n\
         Polkit GUI (if available): pkexec {} firewall {action}",
        sudo_firewall_cmd(action),
        mymesh_bin().display()
    )
}

pub fn print_help() {
    println!(
        r#"{}

MyMesh does not open firewall ports automatically. Use these commands only
when you want LAN clients (e.g. a phone for connect-by-carrier) to reach this
machine.

{}
  TCP {}   connect-by-carrier web page  (mymesh carrier)
           bind: 0.0.0.0 — blocked by default UFW on many desktops

{} (normally no firewall rule)
  127.0.0.1:5353    magic DNS (*.mym)
  127.0.0.1:18080   magic SOCKS5
  127.64.x.y:*      mesh-IP port forwards (loopback)

{}
  Mesh SSH (mymesh proxy-ssh / ssh host.mym) uses the iroh P2P path, then the
  peer agent dials 127.0.0.1:22 locally. UFW on the peer usually does NOT block
  that localhost hop.

{}
  mymesh firewall explain
  mymesh firewall status
  mymesh firewall ufw status|allow|deny
  mymesh firewall firewalld status|allow|deny

allow/deny require root. If you are not root, re-run with:

  {}
  {}

TUI can try pkexec (graphical polkit) when available; otherwise use the sudo line above.
"#,
        style("MyMesh firewall helper").bold(),
        style("LAN-facing (consider opening)").cyan().bold(),
        CARRIER_TCP,
        style("Loopback-only").cyan().bold(),
        style("About SSH / mesh").cyan().bold(),
        style("Commands").cyan().bold(),
        sudo_firewall_cmd("ufw allow"),
        sudo_firewall_cmd("firewalld allow"),
    );
}

pub fn cmd_status() -> Result<()> {
    print_help();
    println!("{}", style("Detected tools").bold());
    println!("  ufw        {}", tool_line("ufw"));
    println!("  firewalld  {}", tool_line("firewall-cmd"));
    println!("  binary     {}", mymesh_bin().display());
    println!();
    if which("ufw") {
        println!("{}", style("ufw status").dim());
        let _ = run_show(&["ufw", "status", "verbose"]);
        println!();
    }
    if which("firewall-cmd") {
        println!("{}", style("firewalld").dim());
        let _ = run_show(&["firewall-cmd", "--state"]);
        let _ = run_show(&["firewall-cmd", "--list-ports"]);
        println!();
    }
    println!(
        "To open carrier port (TCP {CARRIER_TCP}):\n  {}\n  {}",
        sudo_firewall_cmd("ufw allow"),
        sudo_firewall_cmd("firewalld allow")
    );
    Ok(())
}

fn tool_line(bin: &str) -> String {
    if which(bin) {
        style("present").green().to_string()
    } else {
        style("not found").dim().to_string()
    }
}

fn which(bin: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {bin} >/dev/null 2>&1"))
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn run_show(argv: &[&str]) -> Result<()> {
    let out = Command::new(argv[0])
        .args(&argv[1..])
        .output()
        .with_context(|| format!("run {}", argv[0]))?;
    let s = String::from_utf8_lossy(&out.stdout);
    let e = String::from_utf8_lossy(&out.stderr);
    print!("{s}");
    if !e.trim().is_empty() {
        eprint!("{e}");
    }
    Ok(())
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn need_root(action: &str) -> Result<()> {
    if !is_root() {
        bail!("{}", root_required_msg(action));
    }
    Ok(())
}

/// Try graphical elevation via pkexec; returns Ok(true) if command ran elevated.
pub fn try_pkexec(args: &[&str]) -> Result<bool> {
    if is_root() {
        return Ok(false);
    }
    if !which("pkexec") {
        return Ok(false);
    }
    let bin = mymesh_bin();
    let mut c = Command::new("pkexec");
    c.arg(&bin).arg("firewall");
    for a in args {
        c.arg(a);
    }
    let st = c.status().context("pkexec")?;
    if st.success() {
        Ok(true)
    } else {
        bail!(
            "pkexec failed ({st}). Run manually:\n  {}",
            sudo_firewall_cmd(&args.join(" "))
        )
    }
}

// ── ufw ──────────────────────────────────────────────────────────────

pub fn ufw_status() -> Result<()> {
    if !which("ufw") {
        bail!("ufw not found on PATH");
    }
    println!("MyMesh expects inbound TCP {CARRIER_TCP} (comment '{RULE_COMMENT}') for carrier.");
    run_show(&["ufw", "status", "numbered"])?;
    Ok(())
}

pub fn ufw_allow() -> Result<()> {
    if !is_root() {
        if try_pkexec(&["ufw", "allow"])? {
            return Ok(());
        }
        need_root("ufw allow")?;
    }
    if !which("ufw") {
        bail!("ufw not found on PATH");
    }
    println!(
        "{} ufw allow {CARRIER_TCP}/tcp comment '{RULE_COMMENT}'",
        style("plan").yellow().bold()
    );
    println!("  purpose: mymesh carrier (LAN phone page)");
    let st = Command::new("ufw")
        .args([
            "allow",
            &format!("{CARRIER_TCP}/tcp"),
            "comment",
            RULE_COMMENT,
        ])
        .status()
        .context("ufw allow")?;
    if !st.success() {
        bail!("ufw allow failed ({st})");
    }
    println!(
        "{} rule added — ensure ufw is enabled: {}",
        style("ok").green().bold(),
        style("sudo ufw status").dim()
    );
    println!("  if inactive: sudo ufw enable   (review rules first!)");
    Ok(())
}

pub fn ufw_deny() -> Result<()> {
    if !is_root() {
        if try_pkexec(&["ufw", "deny"])? {
            return Ok(());
        }
        need_root("ufw deny")?;
    }
    if !which("ufw") {
        bail!("ufw not found on PATH");
    }
    println!(
        "{} ufw delete allow {CARRIER_TCP}/tcp",
        style("plan").yellow().bold()
    );
    let st = Command::new("ufw")
        .args(["delete", "allow", &format!("{CARRIER_TCP}/tcp")])
        .status()
        .context("ufw delete")?;
    if !st.success() {
        eprintln!("delete by port may have failed; check: sudo ufw status numbered");
        bail!(
            "ufw delete failed ({st})\n{}",
            root_required_msg("ufw deny")
        );
    }
    println!(
        "{} removed allow {CARRIER_TCP}/tcp (if present)",
        style("ok").green().bold()
    );
    Ok(())
}

// ── firewalld ────────────────────────────────────────────────────────

pub fn firewalld_status() -> Result<()> {
    if !which("firewall-cmd") {
        bail!("firewall-cmd not found on PATH");
    }
    println!("MyMesh expects inbound TCP {CARRIER_TCP} for carrier.");
    run_show(&["firewall-cmd", "--state"])?;
    run_show(&["firewall-cmd", "--list-ports"])?;
    run_show(&["firewall-cmd", "--list-all"])?;
    Ok(())
}

pub fn firewalld_allow() -> Result<()> {
    if !is_root() {
        if try_pkexec(&["firewalld", "allow"])? {
            return Ok(());
        }
        need_root("firewalld allow")?;
    }
    if !which("firewall-cmd") {
        bail!("firewall-cmd not found on PATH");
    }
    let port = format!("{CARRIER_TCP}/tcp");
    println!(
        "{} firewall-cmd --permanent --add-port={port} && --reload",
        style("plan").yellow().bold()
    );
    let st = Command::new("firewall-cmd")
        .args(["--permanent", &format!("--add-port={port}")])
        .status()
        .context("firewall-cmd add-port")?;
    if !st.success() {
        bail!("firewall-cmd --add-port failed ({st})");
    }
    let st = Command::new("firewall-cmd")
        .args(["--reload"])
        .status()
        .context("firewall-cmd --reload")?;
    if !st.success() {
        bail!("firewall-cmd --reload failed ({st})");
    }
    println!(
        "{} opened {port} (permanent + reload)",
        style("ok").green().bold()
    );
    Ok(())
}

pub fn firewalld_deny() -> Result<()> {
    if !is_root() {
        if try_pkexec(&["firewalld", "deny"])? {
            return Ok(());
        }
        need_root("firewalld deny")?;
    }
    if !which("firewall-cmd") {
        bail!("firewall-cmd not found on PATH");
    }
    let port = format!("{CARRIER_TCP}/tcp");
    println!(
        "{} firewall-cmd --permanent --remove-port={port} && --reload",
        style("plan").yellow().bold()
    );
    let st = Command::new("firewall-cmd")
        .args(["--permanent", &format!("--remove-port={port}")])
        .status()
        .context("firewall-cmd remove-port")?;
    if !st.success() {
        bail!(
            "firewall-cmd --remove-port failed ({st}) — port may not have been open\n{}",
            root_required_msg("firewalld deny")
        );
    }
    let st = Command::new("firewall-cmd")
        .args(["--reload"])
        .status()
        .context("firewall-cmd --reload")?;
    if !st.success() {
        bail!("firewall-cmd --reload failed ({st})");
    }
    println!("{} removed {port}", style("ok").green().bold());
    Ok(())
}

/// Short summary for TUI status pane.
pub fn tui_summary() -> String {
    let mut s = format!(
        "Carrier needs inbound TCP {CARRIER_TCP} on this host.\n\
         Binary: {}\n\
         ufw: {}   firewalld: {}\n\n\
         Open (as root):\n  {}\n  {}\n\n\
         Or from TUI: Status → [fw open] (tries pkexec, else shows this).\n",
        mymesh_bin().display(),
        if which("ufw") { "yes" } else { "no" },
        if which("firewall-cmd") { "yes" } else { "no" },
        sudo_firewall_cmd("ufw allow"),
        sudo_firewall_cmd("firewalld allow"),
    );
    if is_root() {
        s.push_str("\n(current process is root)\n");
    }
    s
}

pub fn tui_try_open_carrier() -> Result<String> {
    if which("ufw") {
        ufw_allow()?;
        return Ok(format!("ufw allow ok — {}", sudo_firewall_cmd("ufw allow")));
    }
    if which("firewall-cmd") {
        firewalld_allow()?;
        return Ok("firewalld allow ok".into());
    }
    bail!(
        "no ufw/firewalld found.\nOpen TCP {CARRIER_TCP} manually, or install ufw.\n{}",
        sudo_firewall_cmd("ufw allow")
    )
}
