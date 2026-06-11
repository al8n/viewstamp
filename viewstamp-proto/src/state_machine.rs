use bytes::Bytes;

use crate::OpNumber;

/// The replicated application driven by the consensus log.
///
/// `apply` must be deterministic and side-effect-free apart from mutating `self`:
/// every replica applies the same committed ops in the same order and must reach
/// identical state.
///
/// `snapshot` and `restore` support checkpoints and state-sync: a primary can
/// capture its full applied state with `snapshot`, ship the opaque bytes to a
/// lagging replica, and that replica calls `restore` to fast-forward without
/// replaying the entire log.
pub trait StateMachine {
  /// Applies a committed operation and returns the reply payload.
  ///
  /// **Reply-size bound (embedder obligation):** the returned reply must be at most
  /// [`max_reply_body_len`](crate::max_reply_body_len) bytes. The reply ships to the client as ONE
  /// `Reply` message, and a reply whose encoding exceeds the transport's frame cap is refused on the
  /// send path — with no in-protocol recovery, because the op is ALREADY COMMITTED by the time the
  /// reply exists (the request cannot be re-executed, and every resend of the cached reply re-fails
  /// the same way). The endpoint `debug_assert`s the bound at both apply sites, so a violation fails
  /// loudly in tests/sims; in release the over-bound reply is the embedder's bug to prevent, exactly
  /// as the driver-side `max_request_body_len()` bounds the request body at submit.
  fn apply(&mut self, op: OpNumber, body: &[u8]) -> Bytes;
  /// A deterministic, opaque snapshot of all applied state (for checkpoints + state-sync).
  ///
  /// **No frame-size bound:** the checkpoint envelope — this snapshot plus the client-session
  /// table (with cached replies) — ships to a lagging replica as one `SyncCheckpoint` when it fits
  /// a single transport frame, and is otherwise transferred chunked (announce + offset-addressed
  /// pulls), so a snapshot of any size remains state-sync-servable. Larger snapshots only cost
  /// proportionally more transfer round trips.
  fn snapshot(&self) -> Bytes;
  /// Restores state from a snapshot produced by [`StateMachine::snapshot`].
  fn restore(&mut self, snapshot: &[u8]);
}
