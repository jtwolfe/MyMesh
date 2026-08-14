use crate::ChannelId;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
const HEADER_LEN: usize = 4 + 1 + 4; // len + kind + stream

#[derive(Clone, Debug)]
pub struct Frame {
    pub channel: ChannelId,
    pub payload: Bytes,
}

pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, frame: &Frame) -> io::Result<()> {
    if frame.payload.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame too large",
        ));
    }
    let len = (HEADER_LEN - 4 + frame.payload.len()) as u32;
    let mut hdr = BytesMut::with_capacity(HEADER_LEN);
    hdr.put_u32(len);
    hdr.put_u8(frame.channel.kind as u8);
    hdr.put_u32(frame.channel.stream);
    w.write_all(&hdr).await?;
    w.write_all(&frame.payload).await?;
    w.flush().await?;
    Ok(())
}

/// Consecutive unknown kinds a new peer will skip before tearing down.
const MAX_UNKNOWN_KIND_SKIPS: u32 = 16;

pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Frame> {
    let mut skipped = 0u32;
    loop {
        let mut hdr = [0u8; HEADER_LEN];
        r.read_exact(&mut hdr).await?;
        let mut cur = &hdr[..];
        let len = cur.get_u32() as usize;
        if len < 5 || len - 5 > MAX_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid frame length",
            ));
        }
        let kind_u8 = cur.get_u8();
        let stream = cur.get_u32();
        let payload_len = len - 5;
        let mut payload = vec![0u8; payload_len];
        r.read_exact(&mut payload).await?;
        // F5: new peers skip unknown kinds (consume length, continue). Do not
        // send kind 6 this wave — old peers still tear down (KD-F17).
        let Some(kind) = crate::ChannelKind::from_u8(kind_u8) else {
            skipped = skipped.saturating_add(1);
            if skipped > MAX_UNKNOWN_KIND_SKIPS {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "too many unknown channel kinds",
                ));
            }
            continue;
        };
        return Ok(Frame {
            channel: ChannelId { kind, stream },
            payload: Bytes::from(payload),
        });
    }
}

pub fn encode_msg<T: Serialize>(msg: &T) -> mymesh_core::Result<Bytes> {
    bincode::serialize(msg)
        .map(Bytes::from)
        .map_err(|e| mymesh_core::Error::Protocol(e.to_string()))
}

pub fn decode_msg<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> mymesh_core::Result<T> {
    bincode::deserialize(bytes).map_err(|e| mymesh_core::Error::Protocol(e.to_string()))
}

/// Maximum size for length-prefixed JSON messages (1 MiB).
pub const MAX_JSON_MSG_BYTES: usize = 1024 * 1024;

/// Encode a message as length-prefixed JSON (4-byte big-endian length + UTF-8 JSON).
/// Used by the enrollment protocol (ALPN `mymesh-enroll/1`).
pub fn encode_json_msg<T: Serialize>(msg: &T) -> mymesh_core::Result<Bytes> {
    let json = serde_json::to_vec(msg).map_err(|e| mymesh_core::Error::Protocol(e.to_string()))?;
    if json.len() > MAX_JSON_MSG_BYTES {
        return Err(mymesh_core::Error::Protocol(
            "JSON message too large".into(),
        ));
    }
    let len = json.len() as u32;
    let mut out = BytesMut::with_capacity(4 + json.len());
    out.put_u32(len);
    out.extend_from_slice(&json);
    Ok(out.freeze())
}

/// Decode a length-prefixed JSON message from raw bytes (4-byte big-endian length + UTF-8 JSON).
pub fn decode_json_msg<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> mymesh_core::Result<T> {
    if bytes.len() < 4 {
        return Err(mymesh_core::Error::Protocol(
            "JSON message too short for length prefix".into(),
        ));
    }
    let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if bytes.len() < 4 + len {
        return Err(mymesh_core::Error::Protocol(
            "JSON message truncated".into(),
        ));
    }
    let json = &bytes[4..4 + len];
    serde_json::from_slice(json).map_err(|e| mymesh_core::Error::Protocol(e.to_string()))
}

/// Read a length-prefixed JSON message from an async reader.
pub async fn read_json_msg<R: AsyncRead + Unpin, T: for<'de> Deserialize<'de>>(
    r: &mut R,
) -> io::Result<T> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_JSON_MSG_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "JSON message too large",
        ));
    }
    let mut json_buf = vec![0u8; len];
    r.read_exact(&mut json_buf).await?;
    serde_json::from_slice(&json_buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

/// Write a length-prefixed JSON message to an async writer.
pub async fn write_json_msg<W: AsyncWrite + Unpin, T: Serialize>(
    w: &mut W,
    msg: &T,
) -> io::Result<()> {
    let json = serde_json::to_vec(msg)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    if json.len() > MAX_JSON_MSG_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "JSON message too large",
        ));
    }
    let len = json.len() as u32;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(&json).await?;
    w.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ChannelKind;

    #[tokio::test]
    async fn skip_unknown_kind_then_read_known() {
        let (mut w, mut r) = tokio::io::duplex(64 * 1024);
        let unknown_payload = b"kind-6-reserved";
        let len = (5 + unknown_payload.len()) as u32;
        let mut unknown = Vec::with_capacity(HEADER_LEN + unknown_payload.len());
        unknown.extend_from_slice(&len.to_be_bytes());
        unknown.push(6);
        unknown.extend_from_slice(&0u32.to_be_bytes());
        unknown.extend_from_slice(unknown_payload);
        w.write_all(&unknown).await.unwrap();
        let known = Frame {
            channel: ChannelId::control(),
            payload: Bytes::from_static(b"hello"),
        };
        write_frame(&mut w, &known).await.unwrap();
        let got = read_frame(&mut r).await.unwrap();
        assert_eq!(got.channel.kind, ChannelKind::Control);
        assert_eq!(&got.payload[..], b"hello");
    }

    #[tokio::test]
    async fn too_many_unknown_kinds_tears_down() {
        let (mut w, mut r) = tokio::io::duplex(64 * 1024);
        for _ in 0..(MAX_UNKNOWN_KIND_SKIPS + 1) {
            let len = 5u32;
            let mut unknown = Vec::from(len.to_be_bytes());
            unknown.push(6);
            unknown.extend_from_slice(&0u32.to_be_bytes());
            w.write_all(&unknown).await.unwrap();
        }
        let err = read_frame(&mut r).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
