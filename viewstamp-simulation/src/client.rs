use core::time::Duration;

use bytes::Bytes;
use viewstamp_proto::{ClientId, Instant, Message, Request, RequestNumber};

const REQUEST_TIMEOUT: Duration = Duration::from_millis(200);

/// A simple closed-loop client: one request in flight; on reply, record it and
/// issue the next, until `total` requests have committed.
#[derive(Debug)]
pub struct ClientModel {
  id: ClientId,
  total: u64,
  next_request: u64,
  replies: Vec<(u64, Bytes)>,
  inflight: Option<Request>,
  /// Last instant at which the inflight request was transmitted; `None` means
  /// "not yet sent this cycle" so the next `pending` call must transmit.
  last_sent: Option<Instant>,
}

impl ClientModel {
  /// Creates a client that will issue `total` requests, numbered 1..=total.
  pub fn new(id: u128, total: u64) -> Self {
    Self {
      id: ClientId::new(id),
      total,
      next_request: 1,
      replies: Vec::new(),
      inflight: None,
      last_sent: None,
    }
  }

  /// The client id.
  pub fn id(&self) -> ClientId {
    self.id
  }

  /// The replies received so far.
  pub fn replies(&self) -> &[(u64, Bytes)] {
    &self.replies
  }

  /// True once every request has received its reply.
  pub fn is_done(&self) -> bool {
    self.replies.len() as u64 == self.total
  }

  /// Returns the request to (re)send this instant, if any: mints the next request
  /// when idle, and (re)transmits the in-flight request when first sent or when
  /// `REQUEST_TIMEOUT` has elapsed since the last send. Returns `None` otherwise.
  pub fn pending(&mut self, now: Instant) -> Option<Request> {
    if self.inflight.is_none() && self.next_request <= self.total {
      let body = Bytes::from(self.next_request.to_be_bytes().to_vec());
      self.inflight = Some(Request::new(
        self.id,
        RequestNumber::with(self.next_request),
        body,
      ));
      self.last_sent = None;
    }
    let due = match self.last_sent {
      None => true,
      Some(t) => now.saturating_duration_since(t) >= REQUEST_TIMEOUT,
    };
    if self.inflight.is_some() && due {
      self.last_sent = Some(now);
      self.inflight.clone()
    } else {
      None
    }
  }

  /// Handles a reply: if it matches the in-flight request, record it and advance.
  pub fn handle(&mut self, msg: Message) {
    if let Message::Reply(r) = msg {
      if let Some(req) = &self.inflight {
        if req.request() == r.request() {
          self.replies.push((r.request().get(), r.body_bytes()));
          self.inflight = None;
          self.last_sent = None;
          self.next_request += 1;
        }
      }
    }
  }
}
