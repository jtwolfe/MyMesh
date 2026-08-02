//! TCP tunnels over MyMesh sessions (magic hostname / socks / expose).
use mymesh_core::Result;
use mymesh_net::PeerConnection;
use mymesh_protocol::{decode_msg, encode_msg, ChannelId, ChannelKind, Frame, TcpMessage};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::debug;

const CH: u32 = 1;

fn tcp_frame(msg: &TcpMessage) -> Result<Frame> {
    Ok(Frame {
        channel: ChannelId::tcp(CH),
        payload: encode_msg(msg)?,
    })
}

/// Client: after handshake, dial remote host:port and bridge `local`.
pub async fn client_bridge(
    conn: Box<dyn PeerConnection>,
    local: TcpStream,
    port: u16,
    host: Option<String>,
) -> Result<()> {
    conn.send_frame(tcp_frame(&TcpMessage::Dial { port, host })?)
        .await?;
    loop {
        let frame = conn.recv_frame().await?;
        if frame.channel.kind != ChannelKind::Tcp {
            continue;
        }
        match decode_msg::<TcpMessage>(&frame.payload)? {
            TcpMessage::DialOk => break,
            TcpMessage::DialErr { message } => {
                return Err(mymesh_core::Error::Network(message));
            }
            TcpMessage::Close { reason } => {
                return Err(mymesh_core::Error::Network(reason));
            }
            _ => {}
        }
    }
    pipe_conn_stream(conn, local).await
}

/// Host: handle an already-handshaked connection that will speak TCP first.
pub async fn host_bridge(conn: Box<dyn PeerConnection>, first_payload: &[u8]) -> Result<()> {
    let first: TcpMessage = decode_msg(first_payload)?;
    let (port, host) = match first {
        TcpMessage::Dial { port, host } => (port, host),
        other => {
            return Err(mymesh_core::Error::Protocol(format!(
                "expected Tcp Dial, got {other:?}"
            )));
        }
    };
    let target = host.unwrap_or_else(|| "127.0.0.1".into());
    let addr = format!("{target}:{port}");
    match TcpStream::connect(&addr).await {
        Ok(remote) => {
            conn.send_frame(tcp_frame(&TcpMessage::DialOk)?).await?;
            pipe_conn_stream(conn, remote).await
        }
        Err(e) => {
            conn.send_frame(tcp_frame(&TcpMessage::DialErr {
                message: format!("connect {addr}: {e}"),
            })?)
            .await?;
            let _ = conn.close().await;
            Ok(())
        }
    }
}

async fn pipe_conn_stream(conn: Box<dyn PeerConnection>, stream: TcpStream) -> Result<()> {
    let conn = Arc::new(Mutex::new(conn));
    let (mut rd, mut wr) = stream.into_split();

    let c_up = conn.clone();
    let up = async move {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let n = match rd.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            let fr = match tcp_frame(&TcpMessage::Data {
                data: buf[..n].to_vec(),
            }) {
                Ok(f) => f,
                Err(_) => break,
            };
            if c_up.lock().await.send_frame(fr).await.is_err() {
                break;
            }
        }
        if let Ok(fr) = tcp_frame(&TcpMessage::Close {
            reason: "eof".into(),
        }) {
            let _ = c_up.lock().await.send_frame(fr).await;
        }
    };

    let c_dn = conn.clone();
    let down = async move {
        loop {
            let frame = {
                let g = c_dn.lock().await;
                g.recv_frame().await
            };
            let frame = match frame {
                Ok(f) => f,
                Err(_) => break,
            };
            if frame.channel.kind != ChannelKind::Tcp {
                continue;
            }
            match decode_msg::<TcpMessage>(&frame.payload) {
                Ok(TcpMessage::Data { data }) => {
                    if wr.write_all(&data).await.is_err() {
                        break;
                    }
                }
                Ok(TcpMessage::Close { .. }) => break,
                Ok(_) => {}
                Err(_) => break,
            }
        }
    };

    tokio::select! {
        _ = up => {}
        _ = down => {}
    }
    debug!("tcp pipe done");
    let _ = conn.lock().await.close().await;
    Ok(())
}
