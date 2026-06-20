//! Carrier seams — the bring-your-own-carrier boundary (conventions doc §7).
//!
//! The library owns envelope codecs, framing, and lifecycle; the *carrier* (the
//! byte/datagram transport) is injected. A host supplies QUIC, WebRTC, a platform
//! media stack, or anything else by implementing one of these traits — without
//! changing the library.

use crate::conventions::{MAX_FRAME_DEFAULT, Result, TransportError};
use std::io::{Read, Write};

/// A stream/frame carrier: sends and receives one *delimited message* at a time.
/// Used by CSIL-RPC and CSIL-Events. Built-in implementations frame with a 4-byte
/// big-endian length prefix; a host may implement this over WebSocket binary
/// frames, a WebTransport stream, etc.
pub trait FrameCarrier {
    fn send_frame(&mut self, bytes: &[u8]) -> Result<()>;
    /// Receive the next frame, or `None` at a clean end of stream.
    fn recv_frame(&mut self) -> Result<Option<Vec<u8>>>;
}

/// A datagram carrier: sends and receives one self-contained datagram (each within
/// the channel MTU), with no delivery or ordering guarantee. Used by CSIL-Datagrams.
/// Built-in over UDP; a host plugs WebRTC unreliable channels, QUIC datagrams, etc.
pub trait DatagramCarrier {
    fn send_datagram(&mut self, bytes: &[u8]) -> Result<()>;
    /// Receive the next datagram, or `None` if the carrier is closed.
    fn recv_datagram(&mut self) -> Result<Option<Vec<u8>>>;
}

/// Write a 4-byte big-endian length prefix followed by `bytes` (CSIL stream framing).
pub fn write_length_prefixed<W: Write>(w: &mut W, bytes: &[u8], max: usize) -> Result<()> {
    if bytes.len() > max {
        return Err(TransportError::FrameTooLarge {
            got: bytes.len(),
            max,
        });
    }
    let len = u32::try_from(bytes.len()).map_err(|_| TransportError::FrameTooLarge {
        got: bytes.len(),
        max,
    })?;
    w.write_all(&len.to_be_bytes())
        .map_err(|e| TransportError::Carrier(e.to_string()))?;
    w.write_all(bytes)
        .map_err(|e| TransportError::Carrier(e.to_string()))?;
    w.flush()
        .map_err(|e| TransportError::Carrier(e.to_string()))?;
    Ok(())
}

/// Read one length-prefixed frame, enforcing the max-frame guard before allocating.
/// Returns `None` at a clean EOF before any byte of a frame.
pub fn read_length_prefixed<R: Read>(r: &mut R, max: usize) -> Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(TransportError::Carrier(e.to_string())),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max {
        return Err(TransportError::FrameTooLarge { got: len, max });
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)
        .map_err(|e| TransportError::Carrier(e.to_string()))?;
    Ok(Some(buf))
}

/// A `FrameCarrier` over any `Read + Write` byte stream (TCP, TLS, Unix socket),
/// using the canonical 4-byte length-prefix framing.
pub struct StreamCarrier<S: Read + Write> {
    stream: S,
    max_frame: usize,
}

impl<S: Read + Write> StreamCarrier<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            max_frame: MAX_FRAME_DEFAULT,
        }
    }

    pub fn with_max_frame(stream: S, max_frame: usize) -> Self {
        Self { stream, max_frame }
    }

    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S: Read + Write> FrameCarrier for StreamCarrier<S> {
    fn send_frame(&mut self, bytes: &[u8]) -> Result<()> {
        write_length_prefixed(&mut self.stream, bytes, self.max_frame)
    }

    fn recv_frame(&mut self) -> Result<Option<Vec<u8>>> {
        read_length_prefixed(&mut self.stream, self.max_frame)
    }
}

/// An in-memory `FrameCarrier` backed by a queue of frames — for tests and for
/// driving the codec without a socket.
#[derive(Default)]
pub struct LoopbackFrameCarrier {
    pub outbound: std::collections::VecDeque<Vec<u8>>,
    pub inbound: std::collections::VecDeque<Vec<u8>>,
}

impl LoopbackFrameCarrier {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue a frame that a subsequent `recv_frame` will return.
    pub fn push_inbound(&mut self, bytes: Vec<u8>) {
        self.inbound.push_back(bytes);
    }

    /// Take the next frame that was sent via `send_frame`.
    pub fn take_outbound(&mut self) -> Option<Vec<u8>> {
        self.outbound.pop_front()
    }
}

impl FrameCarrier for LoopbackFrameCarrier {
    fn send_frame(&mut self, bytes: &[u8]) -> Result<()> {
        self.outbound.push_back(bytes.to_vec());
        Ok(())
    }

    fn recv_frame(&mut self) -> Result<Option<Vec<u8>>> {
        Ok(self.inbound.pop_front())
    }
}

/// An in-memory `DatagramCarrier` — for tests and codec drives.
#[derive(Default)]
pub struct LoopbackDatagramCarrier {
    pub outbound: std::collections::VecDeque<Vec<u8>>,
    pub inbound: std::collections::VecDeque<Vec<u8>>,
}

impl LoopbackDatagramCarrier {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_inbound(&mut self, bytes: Vec<u8>) {
        self.inbound.push_back(bytes);
    }

    pub fn take_outbound(&mut self) -> Option<Vec<u8>> {
        self.outbound.pop_front()
    }
}

impl DatagramCarrier for LoopbackDatagramCarrier {
    fn send_datagram(&mut self, bytes: &[u8]) -> Result<()> {
        self.outbound.push_back(bytes.to_vec());
        Ok(())
    }

    fn recv_datagram(&mut self) -> Result<Option<Vec<u8>>> {
        Ok(self.inbound.pop_front())
    }
}
