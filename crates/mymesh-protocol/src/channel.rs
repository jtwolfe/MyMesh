use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ChannelKind {
    Control = 1,
    Terminal = 2,
    Files = 3,
    Desktop = 4,
    Tcp = 5,
}

impl ChannelKind {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Control),
            2 => Some(Self::Terminal),
            3 => Some(Self::Files),
            4 => Some(Self::Desktop),
            5 => Some(Self::Tcp),
            _ => None,
        }
    }
}

/// Stream / channel identifier within a session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChannelId {
    pub kind: ChannelKind,
    pub stream: u32,
}

impl ChannelId {
    pub fn control() -> Self {
        Self {
            kind: ChannelKind::Control,
            stream: 0,
        }
    }

    pub fn terminal(stream: u32) -> Self {
        Self {
            kind: ChannelKind::Terminal,
            stream,
        }
    }

    pub fn files(stream: u32) -> Self {
        Self {
            kind: ChannelKind::Files,
            stream,
        }
    }

    pub fn desktop(stream: u32) -> Self {
        Self {
            kind: ChannelKind::Desktop,
            stream,
        }
    }

    pub fn tcp(stream: u32) -> Self {
        Self {
            kind: ChannelKind::Tcp,
            stream,
        }
    }
}
