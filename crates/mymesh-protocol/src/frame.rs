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

pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Frame> {
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
}
