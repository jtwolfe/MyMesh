//! Dial peers via the local agent proxy (single iroh endpoint).
use anyhow::{bail, Result};
use mymesh_core::{Capability, Config, DeviceStore, Paths};
use mymesh_crypto::Identity;
use mymesh_net::IrohTransport;
use mymesh_session::Session;

/// Open an authenticated session to a trusted peer.
/// Returns (session, optional direct transport to shut down if not using agent proxy).
pub async fn open_trusted_session(
    paths: &Paths,
    device: &str,
) -> Result<(Session, Option<IrohTransport>, mymesh_core::DeviceId)> {
    let identity = Identity::load_or_create(paths.identity_file())?;
    let cfg = Config::load(paths.config_file())?;
    let store = DeviceStore::open(paths.devices_file())?;
    let peer = crate::resolve_device(&store, device)?;
    if !store.is_trusted(&peer) {
        bail!("device not trusted — link first");
    }
    open_to_peer(paths, &identity, &cfg, &store, peer).await
}

pub async fn open_to_peer(
    paths: &Paths,
    identity: &Identity,
    cfg: &Config,
    store: &DeviceStore,
    peer: mymesh_core::DeviceId,
) -> Result<(Session, Option<IrohTransport>, mymesh_core::DeviceId)> {
    let _ = paths;
    let sock = std::path::PathBuf::from(&cfg.daemon.control_socket);
    let (conn, transport) = mymesh_net::connect_mesh(identity, peer, &sock).await?;
    let session =
        Session::handshake_dialer(conn, identity, &cfg.device_label, store, Capability::all())
            .await?;
    Ok((session, transport, peer))
}

pub async fn connect_raw(
    identity: &Identity,
    cfg: &Config,
    peer: mymesh_core::DeviceId,
) -> Result<(Box<dyn mymesh_net::PeerConnection>, Option<IrohTransport>)> {
    let sock = std::path::PathBuf::from(&cfg.daemon.control_socket);
    mymesh_net::connect_mesh(identity, peer, &sock)
        .await
        .map_err(Into::into)
}

pub async fn shutdown_opt(t: Option<IrohTransport>) {
    if let Some(tr) = t {
        tr.shutdown().await;
    }
}
