use vsrr_proto::{ClientId, Message, Reply, Request, RequestNumber};

/// A simple closed-loop client: one request in flight; on reply, record it and
/// issue the next, until `total` requests have committed.
#[derive(Debug)]
pub struct ClientModel {
  id: ClientId,
  total: u64,
  next_request: u64,
  replies: Vec<(u64, Vec<u8>)>,
  inflight: Option<Request>,
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
    }
  }

  /// The client id.
  pub fn id(&self) -> ClientId {
    self.id
  }

  /// The replies received so far.
  pub fn replies(&self) -> &[(u64, Vec<u8>)] {
    &self.replies
  }

  /// True once every request has received its reply.
  pub fn is_done(&self) -> bool {
    self.replies.len() as u64 == self.total
  }

  /// Returns the in-flight request to (re)send, minting the next one if idle and
  /// not finished. Returns `None` when finished.
  pub fn pending(&mut self) -> Option<Request> {
    if self.inflight.is_none() && self.next_request <= self.total {
      let body = self.next_request.to_be_bytes().to_vec();
      self.inflight = Some(Request {
        client: self.id,
        request: RequestNumber::with(self.next_request),
        body,
      });
    }
    self.inflight.clone()
  }

  /// Handles a reply: if it matches the in-flight request, record it and advance.
  pub fn handle(&mut self, msg: Message) {
    if let Message::Reply(Reply { request, body, .. }) = msg {
      if let Some(req) = &self.inflight {
        if req.request == request {
          self.replies.push((request.get(), body));
          self.inflight = None;
          self.next_request += 1;
        }
      }
    }
  }
}
