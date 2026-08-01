use crate::PathSandbox;
use mymesh_core::{Error, Result};
use mymesh_protocol::{FileEntry, FileMessage};
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use tracing::debug;

const CHUNK: u64 = 64 * 1024;

pub struct FileTransferEngine {
    sandbox: PathSandbox,
}

impl FileTransferEngine {
    pub fn new(sandbox: PathSandbox) -> Self {
        Self { sandbox }
    }

    pub fn sandbox(&self) -> &PathSandbox {
        &self.sandbox
    }
}

/// Handle a file protocol message on the host side; may return zero or more replies.
pub fn apply_host_message(
    engine: &FileTransferEngine,
    msg: FileMessage,
) -> Result<Vec<FileMessage>> {
    match msg {
        FileMessage::List { path } => {
            let p = engine.sandbox.resolve(&path)?;
            let mut entries = Vec::new();
            for ent in fs::read_dir(&p).map_err(Error::Io)? {
                let ent = ent.map_err(Error::Io)?;
                let meta = ent.metadata().map_err(Error::Io)?;
                let name = ent.file_name().to_string_lossy().into_owned();
                entries.push(FileEntry {
                    name: name.clone(),
                    path: format!("{}/{}", path.trim_end_matches('/'), name),
                    is_dir: meta.is_dir(),
                    size: meta.len(),
                    modified: meta.modified().ok().and_then(|t| {
                        t.duration_since(std::time::UNIX_EPOCH)
                            .ok()
                            .map(|d| d.as_secs() as i64)
                    }),
                    mode: file_mode(&meta),
                });
            }
            entries.sort_by(|a, b| a.name.cmp(&b.name));
            Ok(vec![FileMessage::ListResult { entries }])
        }
        FileMessage::Stat { path } => {
            let p = engine.sandbox.resolve(&path)?;
            let meta = fs::metadata(&p).map_err(Error::Io)?;
            Ok(vec![FileMessage::StatResult {
                entry: FileEntry {
                    name: p
                        .file_name()
                        .map(|s| s.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                    path,
                    is_dir: meta.is_dir(),
                    size: meta.len(),
                    modified: meta.modified().ok().and_then(|t| {
                        t.duration_since(std::time::UNIX_EPOCH)
                            .ok()
                            .map(|d| d.as_secs() as i64)
                    }),
                    mode: file_mode(&meta),
                },
            }])
        }
        FileMessage::Get {
            path,
            offset,
            length,
        } => {
            let p = engine.sandbox.resolve(&path)?;
            let mut f = fs::File::open(&p).map_err(Error::Io)?;
            f.seek(SeekFrom::Start(offset)).map_err(Error::Io)?;
            let mut remaining = length.unwrap_or(u64::MAX);
            let mut out = Vec::new();
            let mut pos = offset;
            let mut buf = vec![0u8; CHUNK as usize];
            while remaining > 0 {
                let want = remaining.min(CHUNK) as usize;
                let n = f.read(&mut buf[..want]).map_err(Error::Io)?;
                if n == 0 {
                    break;
                }
                out.push(FileMessage::Chunk {
                    offset: pos,
                    data: buf[..n].to_vec(),
                });
                pos += n as u64;
                remaining -= n as u64;
            }
            out.push(FileMessage::Done {
                path,
                bytes: pos.saturating_sub(offset),
            });
            Ok(out)
        }
        FileMessage::Put {
            path,
            size,
            mode: _,
            resume_from,
        } => {
            debug!(%path, size, resume_from, "put announced — waiting for chunks");
            // Create/truncate as needed; chunks arrive as follow-ups.
            let p = engine.sandbox.resolve(&path)?;
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent).map_err(Error::Io)?;
            }
            let f = fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(resume_from == 0)
                .open(&p)
                .map_err(Error::Io)?;
            drop(f);
            Ok(vec![])
        }
        FileMessage::Chunk { offset, data } => {
            // Caller must track active put path; for the engine API we expose write_chunk.
            let _ = (offset, data);
            Err(Error::Protocol(
                "Chunk must be handled via write_chunk with active path".into(),
            ))
        }
        FileMessage::Mkdir { path } => {
            let p = engine.sandbox.resolve(&path)?;
            fs::create_dir_all(p).map_err(Error::Io)?;
            Ok(vec![FileMessage::Done { path, bytes: 0 }])
        }
        FileMessage::Remove { path, recursive } => {
            let p = engine.sandbox.resolve(&path)?;
            if recursive {
                fs::remove_dir_all(&p)
                    .or_else(|_| fs::remove_file(&p))
                    .map_err(Error::Io)?;
            } else if p.is_dir() {
                fs::remove_dir(&p).map_err(Error::Io)?;
            } else {
                fs::remove_file(&p).map_err(Error::Io)?;
            }
            Ok(vec![FileMessage::Done { path, bytes: 0 }])
        }
        FileMessage::Rename { from, to } => {
            let a = engine.sandbox.resolve(&from)?;
            let b = engine.sandbox.resolve(&to)?;
            fs::rename(a, b).map_err(Error::Io)?;
            Ok(vec![FileMessage::Done { path: to, bytes: 0 }])
        }
        other => Ok(vec![FileMessage::Error {
            message: format!("host cannot handle {other:?}"),
        }]),
    }
}

impl FileTransferEngine {
    pub fn write_chunk(&self, path: &str, offset: u64, data: &[u8]) -> Result<()> {
        let p = self.sandbox.resolve(path)?;
        let mut f = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(p)
            .map_err(Error::Io)?;
        f.seek(SeekFrom::Start(offset)).map_err(Error::Io)?;
        f.write_all(data).map_err(Error::Io)?;
        Ok(())
    }
}

#[cfg(unix)]
fn file_mode(meta: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode()
}

#[cfg(not(unix))]
fn file_mode(_meta: &fs::Metadata) -> u32 {
    0o644
}
