//! Explicit host firewall helpers (ufw / firewalld). Never auto-run on install/serve.
//!
//! Note: Carrier HTTP pairing removed per REWORK-UNIFY.md. MyMesh typically does not
//! require inbound firewall rules since iroh uses outbound + relay connections.
use anyhow::{bail, Context, Result};
use console::style;
use std::path::PathBuf;
use std::process::Command;

/// Absolute path to this running binary (best effort).
pub fn mymesh_bin() -> PathBuf {
    std::env::current_exe().unwrap_or_else(|_| PathBuf::from("mymesh"))
}

pub fn print_help() {
    println!(
        r#"{}

MyMesh typically does NOT require firewall rules because:
  - iroh uses outbound QUIC + relay fallback (no listening port)
  - Magic DNS and SOCKS bind to loopback only
  - Mesh SSH tunnels through the iroh P2P path

{}
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
  mymesh firewall ufw
  mymesh firewall firewalld
"#,
        style("MyMesh firewall helper").bold(),
        style("Loopback-only (no firewall rule needed)").cyan().bold(),
        style("About SSH / mesh").cyan().bold(),
        style("Commands").cyan().bold(),
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
    println!("MyMesh typically does not need inbound firewall rules.");
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

// ── ufw ──────────────────────────────────────────────────────────────

pub fn ufw_status() -> Result<()> {
    if !which("ufw") {
        bail!("ufw not found on PATH");
    }
    println!("MyMesh typically does not require inbound firewall rules.");
    run_show(&["ufw", "status", "numbered"])?;
    Ok(())
}

// ── firewalld ────────────────────────────────────────────────────────

pub fn firewalld_status() -> Result<()> {
    if !which("firewall-cmd") {
        bail!("firewall-cmd not found on PATH");
    }
    println!("MyMesh typically does not require inbound firewall rules.");
    run_show(&["firewall-cmd", "--state"])?;
    run_show(&["firewall-cmd", "--list-ports"])?;
    run_show(&["firewall-cmd", "--list-all"])?;
    Ok(())
}

/// Short summary for TUI status pane.
pub fn tui_summary() -> String {
    format!(
        "MyMesh typically does not need inbound firewall rules.\n\
         Binary: {}\n\
         ufw: {}   firewalld: {}\n\n\
         iroh uses outbound QUIC + relay fallback.\n\
         Magic DNS/SOCKS bind to loopback only.\n",
        mymesh_bin().display(),
        if which("ufw") { "yes" } else { "no" },
        if which("firewall-cmd") { "yes" } else { "no" },
    )
}
