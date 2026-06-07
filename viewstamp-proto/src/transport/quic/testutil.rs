//! In-memory datagram pipe for QUIC bridge tests: a virtual UDP link with no
//! loss or reordering, used to ferry `(from, bytes)` between two `Bridge`s.

use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr};

/// A loopback `SocketAddr` on `port`, used to give each test bridge a stable
/// "local" address to tag its outbound datagrams with.
pub(crate) fn addr(port: u16) -> SocketAddr {
  SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

/// A FIFO of `(source_addr, datagram)` pairs standing in for a UDP socket
/// buffer. The test pushes one side's transmits in and pops them out to deliver
/// to the other side; ordering is preserved and nothing is dropped.
#[derive(Default)]
pub(crate) struct PacketPipe {
  pub q: VecDeque<(SocketAddr, Vec<u8>)>,
}

impl PacketPipe {
  /// Enqueue a datagram tagged with the address it was sent from.
  pub(crate) fn push(&mut self, from: SocketAddr, bytes: Vec<u8>) {
    self.q.push_back((from, bytes));
  }

  /// Dequeue the oldest `(from, bytes)` pair, or `None` when the pipe is empty.
  pub(crate) fn pop(&mut self) -> Option<(SocketAddr, Vec<u8>)> {
    self.q.pop_front()
  }
}
