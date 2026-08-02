//! Explicit host firewall helpers (ufw / firewalld). Never auto-run on install/serve.
use anyhow::{bail, Context, Result};
use console::style;
use std::process::Command;

/// Ports MyMesh may need inbound on a LAN-facing host.
pub const CARRIER_TCP: u16 = 17878;
pub const RULE_COMMENT: &str = "mymesh-carrier";

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
  that localhost hop. If mesh ping/shell work but carrier from a phone fails,
  open carrier only. If mesh itself fails, check outbound UDP + iroh relays —
  not only TCP 17878.

{}
  mymesh firewall explain
  mymesh firewall status
  mymesh firewall ufw status|allow|deny
  mymesh firewall firewalld status|allow|deny

allow/deny require root (sudo). Rules are tagged so deny only removes MyMesh
entries where possible.
"#,
        style("MyMesh firewall helper").bold(),
        style("LAN-facing (consider opening)").cyan().bold(),
        CARRIER_TCP,
        style("Loopback-only").cyan().bold(),
        style("About SSH / mesh").cyan().bold(),
        style("Commands").cyan().bold(),
    );
}

pub fn cmd_status() -> Result<()> {
    print_help();
    println!("{}", style("Detected tools").bold());
    println!("  ufw        {}", tool_line("ufw"));
    println!("  firewalld  {}", tool_line("firewall-cmd"));
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
        "Hint: for carrier on this host:\n  sudo mymesh firewall ufw allow\n  # or\n  sudo mymesh firewall firewalld allow"
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

fn need_root() -> Result<()> {
    let uid = unsafe { libc::geteuid() };
    if uid != 0 {
        bail!("firewall allow/deny require root — re-run with sudo");
    }
    Ok(())
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
    need_root()?;
    if !which("ufw") {
        bail!("ufw not found on PATH");
    }
    println!(
        "{} ufw allow {CARRIER_TCP}/tcp comment '{RULE_COMMENT}'",
        style("plan").yellow().bold()
    );
    println!("  purpose: mymesh carrier (LAN phone page)");
    println!("  scope:   any source (tighten manually if you prefer LAN-only)");
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
    // ensure ufw is active? don't force enable — user policy
    println!(
        "{} rule added — ensure ufw is enabled: {}",
        style("ok").green().bold(),
        style("sudo ufw status").dim()
    );
    println!("  if inactive: sudo ufw enable   (review rules first!)");
    Ok(())
}

pub fn ufw_deny() -> Result<()> {
    need_root()?;
    if !which("ufw") {
        bail!("ufw not found on PATH");
    }
    // Prefer delete by rule text
    println!(
        "{} ufw delete allow {CARRIER_TCP}/tcp",
        style("plan").yellow().bold()
    );
    let st = Command::new("ufw")
        .args(["delete", "allow", &format!("{CARRIER_TCP}/tcp")])
        .status()
        .context("ufw delete")?;
    if !st.success() {
        // try numbered list hint
        eprintln!("delete by port may have failed; check: sudo ufw status numbered");
        bail!("ufw delete failed ({st})");
    }
    println!("{} removed allow {CARRIER_TCP}/tcp (if present)", style("ok").green().bold());
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
    need_root()?;
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
    need_root()?;
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
        bail!("firewall-cmd --remove-port failed ({st}) — port may not have been open");
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
