//! Sans-I/O QUIC transport over `quinn_proto`: the driver pumps UDP datagrams; the
//! consensus `Endpoint` and the deterministic oracle stay I/O-free. Std-only.

mod bridge;
mod conn;
mod crypto;
#[cfg(test)]
mod datagram_sim;
mod identity;
pub(crate) mod layout;
#[cfg(test)]
mod loopback;
mod table;
#[cfg(test)]
mod testutil;

pub use bridge::DialError;
pub use crypto::{ClusterTls, QuicOptions, QuicTuning};
pub use identity::{
  AttestedId, CertOid, Hello, Identified, IdentityConfig, IdentityCtx, IdentityOutcome,
  IdentitySource, ProvidedIdentity,
};
pub use layout::StreamLayout;

use std::{net::SocketAddr, time::Duration};

use quinn_proto::{ConnectionHandle, EcnCodepoint};

use bridge::Bridge;
use layout::StreamClass;

use std::collections::BTreeSet;

use crate::{
  Endpoint, Event, Instant, MemberId, Message, OpNumber, Outgoing, Peer, Recipient, ReplicaId,
  Request, SingleChange, SingleVoterDelta, StateMachine, Superblock, Wal,
  endpoint::ProposeMembershipError,
};

/// Derive the SNI server-name a dial presents for `expected` in `cluster`, matching the per-replica
/// cert SAN minted by `ClusterTls`' issuer (`replica-<idx>.<cluster-hex>.viewstamp`). The stock
/// `WebPkiServerVerifier` validates this against the server cert's SAN, so it is part of the
/// cluster-separation guarantee, not cosmetic. A client target (never dialed by a replica
/// coordinator) gets an analogous `client-<id-hex>.<cluster-hex>.viewstamp` form for totality.
fn sni_for(expected: Peer, cluster: u128) -> String {
  match expected {
    Peer::Replica(r) => format!("replica-{}.{:032x}.viewstamp", r.get(), cluster),
    Peer::Client(c) => format!("client-{:032x}.{:032x}.viewstamp", c.get(), cluster),
  }
}

/// The Sans-I/O QUIC super-state-machine: the consensus [`Endpoint<S>`] composed with the
/// quinn-proto `Bridge`, routing per-peer bidi streams partitioned by class under the configured
/// [`StreamLayout`] (control vs bulk; `Single` collapses to a single stream).
///
/// The coordinator is the driver surface: it consumes UDP datagrams (`handle_udp`), fires timers
/// (`handle_timeout`), and produces outbound datagrams (`poll_transmit`) — quinn and the consensus
/// endpoint stay I/O-free underneath. Storage (`W`/`B`) is the third orthogonal axis, threaded into
/// every `handle_*` call.
///
/// # Identity
///
/// `I: IdentitySource` extracts an UNTRUSTED candidate [`Peer`] from post-handshake material (a
/// certificate extension, or a control-stream preface). The COORDINATOR — never the source — owns
/// the binding policy: a `cluster == Config.cluster` cross-check, then dialed→match-or-abort /
/// accepted→adopt. Only after that does the connection reach `Validated` and carry consensus frames.
///
/// For the PROVIDED sources ([`Self::with_identity`]) the cross-check is an un-bypassable cluster
/// guard: [`Hello`]/[`CertOid`] report the genuine attested cluster from the handshake material, so a
/// wrong-cluster peer is rejected here. A [`Self::dangerous_custom_identity`] source, by its named
/// hazard, owns its own attested cluster (it may report any cluster), so the coordinator's check only
/// re-confirms what that source asserts — the un-bypassable guarantee is scoped to the provided
/// sources. Build the common case with [`Self::with_identity`] (the sealed [`ProvidedIdentity`]).
///
/// The coordinator owns the viewstamp↔std clock adapter — its surface speaks the viewstamp
/// [`Instant`] (matching the consensus endpoint), converting to [`std::time::Instant`] at every
/// quinn boundary.
pub struct QuicCoordinator<S, I> {
  endpoint: Endpoint<S, SingleChange>,
  bridge: Bridge,
  /// The identity source: extracts the candidate peer the coordinator's binding policy then checks.
  identity: I,
  /// The stream layout, snapshotted from `QuicOptions` at construction. The send path consults
  /// [`layout::partition`] with this to pick the [`StreamClass`] each consensus message rides; the
  /// bridge holds its own per-connection copy (to open the right streams), so this is the coordinator's
  /// single source for the routing decision.
  layout: StreamLayout,
  /// The viewstamp↔std clock anchor, captured LAZILY on the first [`Self::quinn_now`] (the first
  /// `handle_*` / `connect`), NOT at construction: `(vsr_base, std_base)` is the driver's first-seen
  /// viewstamp `now` paired with the real `std::time::Instant` at that same moment. `None` until that
  /// first call.
  ///
  /// Anchoring on the first-seen `now` (rather than `Instant::ZERO`) is load-bearing for a driver
  /// whose monotonic clock does NOT start at zero. The crate `Instant` is driver-epoch based; a
  /// coordinator first driven at viewstamp epoch `E` must map quinn time as `std_base + (now - E)`,
  /// so `poll_timeout` returns std deadlines offset by quinn's small timer (tens of ms), not by the
  /// absolute epoch `E`. A fixed `vsr_base = ZERO` would map the first `now` to `std_base + E`,
  /// pushing every quinn deadline `E` into the future — a real driver would sleep far too long for
  /// handshake-retransmit / auth-reap / close-drain timers. Identity-anchoring makes
  /// `quinn_now(first_now) == std_base`.
  clock_anchor: Option<(Instant, std::time::Instant)>,
  /// Test-only: count of consensus frames `drain_bridge` decoded and fed to the endpoint. The
  /// per-pump receive-pacing test reads this before/after each pump to assert ONE budget's worth is
  /// delivered per pump and that the whole burst eventually arrives.
  #[cfg(test)]
  consensus_frames_delivered: u64,
}

impl<S, I> core::fmt::Debug for QuicCoordinator<S, I> {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("QuicCoordinator").finish_non_exhaustive()
  }
}

impl<S: StateMachine> QuicCoordinator<S, ProvidedIdentity> {
  /// Wrap a (driver-built) consensus endpoint in a coordinator using one of the two PROVIDED
  /// identity schemes selected by `config` (the common, sealed path). `opts` MUST carry the
  /// cluster-private mandatory-mTLS config built by [`ClusterTls::build`] (so `opts.requires_client_auth()`
  /// is `true`); `rng_seed` seeds the endpoint's connection-ID / token RNG (`None` = OS entropy).
  ///
  /// The provided sources are SAFE only BECAUSE the connection is mutually authenticated over
  /// cluster-private roots: [`Hello`] binds an accepted connection from a self-claimed control preface,
  /// and that self-claim is trustworthy only when mandatory client auth has already proven the peer
  /// holds a cluster cert. Arbitrary / no-auth [`QuicOptions`] therefore belong ONLY behind the named
  /// [`Self::dangerous_custom_identity`] hazard, where the embedder owns the trust boundary.
  ///
  /// # Panics
  ///
  /// Panics if `opts` was not built with mandatory client-certificate authentication
  /// (`opts.requires_client_auth()` is `false`) — i.e. it is not a [`ClusterTls::build`] bundle. The
  /// provided-identity invariant is mandatory mTLS over cluster-private roots; without it the `Hello`
  /// self-claim has no cryptographic backstop, turning sender identity into unauthenticated labeling.
  /// This is a construction-time invariant, asserted here rather than surfaced as a fallible result.
  ///
  /// Panics if `config`'s cluster does not equal the endpoint's `Config.cluster`. The coordinator
  /// single-sources the binding cross-check from the endpoint, and the source's
  /// `write_control_preface` encodes ITS configured cluster into the hello it sends; if the two
  /// disagree this node would advertise a cluster it does not actually serve (its own hello would be
  /// wrong, and every peer would reject it). The equality is a construction-time invariant, not a
  /// runtime condition, so it is asserted here rather than surfaced as a fallible result.
  pub fn with_identity(
    endpoint: Endpoint<S, SingleChange>,
    opts: QuicOptions,
    rng_seed: Option<[u8; 32]>,
    config: IdentityConfig,
  ) -> Self {
    assert!(
      opts.requires_client_auth(),
      "the provided identity sources require mandatory mTLS: build `opts` with `ClusterTls::build` \
       (so `requires_client_auth()` is true). Without mandatory client auth a `Hello` preface is a \
       self-claim with no cryptographic backstop; arbitrary/no-auth options belong only behind \
       `dangerous_custom_identity`",
    );
    assert_eq!(
      config.cluster(),
      endpoint.cluster(),
      "IdentityConfig.cluster ({:#x}) must equal the endpoint's Config.cluster ({:#x}): the source's \
       control preface encodes its own cluster, which must match the endpoint it authenticates for",
      config.cluster(),
      endpoint.cluster(),
    );
    let identity = config.into_source();
    Self::build(endpoint, opts, rng_seed, identity)
  }
}

impl<S: StateMachine, I: IdentitySource> QuicCoordinator<S, I> {
  /// Wrap a consensus endpoint in a coordinator using a CALLER-SUPPLIED [`IdentitySource`].
  ///
  /// # Hazard
  ///
  /// This is the escape hatch from the two provided schemes ([`Self::with_identity`]). The embedder
  /// then OWNS the identity-binding correctness of `src`, INCLUDING the attested cluster:
  /// `authenticate` must return only an untrusted candidate derived from genuine handshake material
  /// (the validated cert chain or the control preface), report the cluster it ACTUALLY attested, and
  /// never collapse the authenticator into a self-claim. The coordinator re-runs its dialed
  /// match-or-abort and its `cluster == Config.cluster` cross-check, but for a custom source that
  /// cross-check only re-confirms the cluster the source reported — a source that mints an
  /// `Identified` with this endpoint's cluster for a foreign-cluster peer passes it. So the cluster
  /// guard is NOT un-bypassable here (unlike the provided sources, which report the genuine attested
  /// cluster): a source that mis-derives the candidate OR mis-reports the cluster can bind the wrong
  /// peer. Prefer [`Self::with_identity`] unless a custom scheme is genuinely required.
  pub fn dangerous_custom_identity(
    endpoint: Endpoint<S, SingleChange>,
    opts: QuicOptions,
    rng_seed: Option<[u8; 32]>,
    src: I,
  ) -> Self {
    Self::build(endpoint, opts, rng_seed, src)
  }

  /// Shared constructor body. The viewstamp↔std clock anchor is NOT captured here — it is set
  /// lazily on the first `quinn_now` (the first `handle_*` / `connect`), so the adapter is anchored at
  /// the driver's ACTUAL first-seen `now`, not at construction time / `Instant::ZERO` (see
  /// [`Self::clock_anchor`]).
  ///
  /// The connection cap is sized to the configured membership here: the effective `max_connections`
  /// is RAISED to [`crypto::mesh_connection_floor`] of the endpoint's `node_count` whenever the
  /// caller-configured cap is lower, so the bridge can never refuse a legitimate steady-state
  /// mutual-dial mesh connection (each peer pair keeps two connections, so an `N`-member node needs
  /// `2*(N-1)` plus reconnect headroom). The cap still bounds an untrusted-network flood; it is just
  /// sized to the full membership (voters plus non-voting members) rather than a fixed constant.
  fn build(
    endpoint: Endpoint<S, SingleChange>,
    opts: QuicOptions,
    rng_seed: Option<[u8; 32]>,
    identity: I,
  ) -> Self {
    let layout = opts.layout();
    let mesh_floor = crypto::mesh_connection_floor(endpoint.node_count());
    let effective_cap = opts.max_connections().max(mesh_floor);
    let opts = opts.with_max_connections(effective_cap);
    Self {
      endpoint,
      bridge: Bridge::new(&opts, rng_seed),
      identity,
      layout,
      clock_anchor: None,
      #[cfg(test)]
      consensus_frames_delivered: 0,
    }
  }

  /// A reference to the underlying consensus endpoint (status / view / state-machine observers).
  pub const fn endpoint(&self) -> &Endpoint<S, SingleChange> {
    &self.endpoint
  }

  /// Proposes a single-member reconfiguration to the consensus endpoint.
  ///
  /// Delegates directly to [`Endpoint::propose_membership`]. The coordinator owns `&mut self.endpoint`
  /// so the call is sequenced after any in-progress pump — no concurrent borrow is possible.
  pub fn propose_membership<W: Wal>(
    &mut self,
    now: Instant,
    wal: &mut W,
    delta: SingleVoterDelta,
  ) -> Result<OpNumber, ProposeMembershipError> {
    self.endpoint.propose_membership(now, wal, delta)
  }

  /// The set of voter [`MemberId`]s that acknowledged an in-flight prepare within the last
  /// `window` ops, as a liveness hint for the reconfiguration executor.
  pub fn recently_acked_voters(&self, window: u64) -> BTreeSet<MemberId> {
    self.endpoint.recently_acked_voters(window)
  }

  /// The cluster id this coordinator authenticates for, single-sourced from the consensus endpoint's
  /// `Config` (no duplicate field). The binding policy's unconditional cross-check uses this.
  #[inline(always)]
  fn cluster(&self) -> u128 {
    self.endpoint.cluster()
  }

  /// This node's own attested identity (its stable [`MemberId`]), single-sourced from the endpoint's
  /// `Config` (no duplicate field). Written into the control-stream preface so peers learn who
  /// dialed/accepted them, and compared (by member id) in the self-reject. Attesting the stable member
  /// id — not the slot it currently occupies — is what lets a peer resolve it against ITS active
  /// membership.
  #[inline(always)]
  fn me(&self) -> AttestedId {
    AttestedId::Replica(self.endpoint.local())
  }

  /// `now` mapped onto quinn's `std::time::Instant` clock: the std anchor plus the viewstamp nanos
  /// elapsed since the viewstamp anchor. The anchor `(vsr_base, std_base)` is captured LAZILY on the
  /// FIRST call (see [`Self::clock_anchor`] for why first-seen-`now`, not `ZERO`), so
  /// `quinn_now(first_now) == std_base` regardless of the driver's epoch.
  ///
  /// Saturating arithmetic on the viewstamp side clamps a `now` before the anchor; the `std` add is
  /// monotone for any `now >= vsr_base` (the steady state). `&mut self` because the first call sets the
  /// anchor — the lazy anchoring is a mutation.
  fn quinn_now(&mut self, now: Instant) -> std::time::Instant {
    let (vsr_base, std_base) = *self
      .clock_anchor
      .get_or_insert_with(|| (now, std::time::Instant::now()));
    std_base + Duration::from_nanos(now.saturating_duration_since(vsr_base).as_nanos() as u64)
  }

  /// Dial the replica `expected` at `remote`. The dial records `expected` as the connection's
  /// expectation (the binding policy later requires the authenticated identity to match it) and
  /// derives the SNI server-name from `expected` + the cluster so the dialer's stock
  /// `WebPkiServerVerifier` matches it against the server cert's SAN (the B1
  /// `replica-<idx>.<cluster-hex>.viewstamp` form). On success the handshake Initial is queued for the
  /// next [`Self::poll_transmit`].
  ///
  /// Returns [`DialError`] when the dial is refused — the typed reason is SURFACED, not swallowed, so
  /// a caller can back off, report saturation, or test the cap at this boundary. [`DialError::AtCapacity`]
  /// means the bridge already holds `max_connections` live connections (dialed + accepted): the dial is
  /// skipped BEFORE any quinn `Connection` is allocated, so a refused dial leaves the table and the
  /// endpoint slab unchanged. A consensus-driven dialer may simply retry on its own timer; the error is
  /// returned rather than dropped so over-cap saturation is no longer indistinguishable from a scheduled
  /// dial.
  pub fn connect(
    &mut self,
    now: Instant,
    remote: SocketAddr,
    expected: Peer,
  ) -> Result<(), DialError> {
    let server_name = sni_for(expected, self.cluster());
    let std_now = self.quinn_now(now);
    self
      .bridge
      .connect(std_now, remote, &server_name, expected)?;
    Ok(())
  }

  /// Feed one inbound UDP datagram from `remote` into the QUIC stack, then drain the bridge's
  /// connection events (bind newly-connected peers, decode readable streams into consensus
  /// messages) and pump the endpoint's resulting outgoing messages back out over the streams.
  pub fn handle_udp<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    remote: SocketAddr,
    ecn: Option<EcnCodepoint>,
    data: &[u8],
    wal: &mut W,
    sb: &mut B,
  ) {
    let std_now = self.quinn_now(now);
    self.bridge.handle_datagram(std_now, remote, ecn, data);
    self.drain_bridge(now, wal, sb);
    self.pump(now);
  }

  /// Fire all QUIC + consensus timers at `now`, then drain the bridge and pump.
  pub fn handle_timeout<W: Wal, B: Superblock>(&mut self, now: Instant, wal: &mut W, sb: &mut B) {
    let std_now = self.quinn_now(now);
    self.bridge.handle_timeout(std_now);
    self.endpoint.handle_timeout(now, wal, sb);
    self.drain_bridge(now, wal, sb);
    self.pump(now);
  }

  /// Drive storage completions through the consensus endpoint, then pump its resulting messages.
  pub fn handle_storage<W: Wal, B: Superblock>(&mut self, now: Instant, wal: &mut W, sb: &mut B) {
    self.endpoint.handle_storage(now, wal, sb);
    self.drain_bridge(now, wal, sb);
    self.pump(now);
  }

  /// Pop one outbound datagram (destination + owned bytes), or `None` when the queue is empty.
  pub fn poll_transmit(&mut self) -> Option<(SocketAddr, Vec<u8>)> {
    self.bridge.poll_transmit()
  }

  /// The wall-clock deadline the driver should arm a real timer against before pumping the QUIC stack
  /// again: the earliest QUIC timer across all connections (with the auth deadline folded in), OR an
  /// IMMEDIATE deadline when the bridge holds deferred work that must be applied without an inbound
  /// datagram (the one-tick endpoint-event feedback, a coordinator-facing event a `service` pass
  /// enqueued after this pass's `drain_bridge`, or a half-drained receive stream). Returned as-is in
  /// `std::time::Instant` (quinn's currency); the consensus deadline (a viewstamp `Instant`) is the
  /// driver's to fold in alongside via [`Endpoint::poll_timeout`] on [`Self::endpoint`].
  pub fn poll_timeout(&mut self) -> Option<std::time::Instant> {
    self.bridge.poll_timeout()
  }

  /// Pop the next consensus application [`Event`] the endpoint produced (a committed op, …), or
  /// `None` when the queue is empty. This is the driver's drain for the events QUIC-delivered messages
  /// cause the endpoint to emit: [`Self::handle_udp`] / [`Self::handle_timeout`] / [`Self::handle_storage`]
  /// feed the endpoint, which enqueues an [`Event`] per commit; without a public drain those entries
  /// would accumulate unbounded in the endpoint and never reach the driver. Mirrors
  /// `StreamCoordinator::poll_event` (the byte-stream transport) — the only consensus output the
  /// coordinator exposes by-value rather than through the immutable [`Self::endpoint`] observer.
  pub fn poll_event(&mut self) -> Option<Event> {
    self.endpoint.poll_event()
  }

  /// Whether a BOUND (identity-validated) connection to `peer` currently exists — the link the
  /// `Backups`/`AllReplicas` fan-out routes consensus frames over. A driver polls this to redial a
  /// configured peer whose connection idled out or was lost: without redial a dead mesh edge stays
  /// dead (retransmits route to no bound conn) until the peer happens to dial back. `false` also
  /// while a dial/handshake is still in flight, so a redialing caller must pace itself (back off)
  /// rather than treat every `false` as dead-link proof.
  pub fn has_bound_conn(&self, peer: Peer) -> bool {
    self.bridge.handle_for(peer).is_some()
  }

  /// Close the connection bound under `Peer::Replica(slot)` if one exists, so the peer can
  /// reconnect under its new slot identity after a membership shift moves a member to a different
  /// slot. The slot routing index holds the OLD slot key; tearing it down lets the redial path
  /// re-establish under the new slot. A no-op if no connection is bound for that slot.
  pub fn close_peer_by_slot(&mut self, now: Instant, slot: ReplicaId) {
    if let Some(h) = self.bridge.handle_for(Peer::Replica(slot)) {
      let std_now = self.quinn_now(now);
      self.bridge.close_local(std_now, h);
    }
  }

  /// The `config_id` of the currently active membership — a cheap scalar read, no clone required.
  /// Drivers compare this against a stored last-known value to detect a membership swap without
  /// cloning the full `Membership` on every loop iteration.
  pub fn membership_config_id(&self) -> u128 {
    self.endpoint.config_id()
  }

  /// A clone of the endpoint's currently-installed membership. Called at most once per config
  /// change in `rekey_peers`; the hot path uses `membership_config_id()` to detect whether a
  /// clone is needed at all.
  pub fn live_membership(&self) -> crate::Membership {
    self.endpoint.membership_clone()
  }

  /// The number of outgoing protocol messages this coordinator refused to send because their encoded
  /// frame would exceed `MAX_FRAME_LEN` (the inbound frame cap). Such a message — e.g. a large
  /// checkpoint / view-change carrier awaiting deferred snapshot chunking — cannot be framed, so the send
  /// path drops it visibly instead of emitting a frame the peer's decoder would fatally reject; consensus
  /// retransmission only re-drops it, so a non-zero, growing count is the operator's signal that chunking
  /// is required. Forwards the bridge's counter, mirroring `StreamCoordinator::oversized_outbound_dropped`.
  pub fn oversized_outbound_dropped(&self) -> u64 {
    self.bridge.oversized_dropped()
  }

  /// Submit a client request originating at this node's local application.
  ///
  /// Delivers the request to this replica (served immediately iff this replica is the primary for the
  /// current view) and broadcasts it to the other replicas so whichever holds the primary role serves
  /// it — mirroring the simulation client, which broadcasts and lets the primary act. `on_request`
  /// ignores the transport sender (it keys on the embedded `ClientId`), so a relayed copy is served
  /// normally. The committed reply is surfaced through [`Self::poll_event`] as
  /// [`crate::Event::Committed`] once this replica applies the op (every replica applies committed ops).
  ///
  /// A request whose body exceeds [`max_request_body_len`](crate::transport::frame::max_request_body_len)
  /// is DROPPED here — not delivered to the endpoint and not routed to backups (the same
  /// transport-ingress gate `Self::deliver_decoded` applies to a relayed inbound `Request`). Such a
  /// body would frame past [`MAX_FRAME_LEN`](crate::transport::frame::MAX_FRAME_LEN) as the resulting
  /// `Prepare`, so the primary could append an op it can never replicate; rejecting it before any
  /// session/log mutation keeps the consensus core transport-agnostic.
  pub fn submit_client_request<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    request: Request,
  ) {
    if request.body().len() > crate::transport::frame::max_request_body_len() {
      return;
    }
    let self_id = self.endpoint.replica();
    self.endpoint.handle_message(
      now,
      wal,
      sb,
      Peer::Client(request.client()),
      Message::Request(request.clone()),
    );
    let std_now = self.quinn_now(now);
    self.route(
      std_now,
      Recipient::Backups,
      &Message::Request(request),
      self_id,
    );
    self.pump(now);
  }

  /// Drain the bridge's connection-event queues:
  /// - `connected` → open the send stream + write the identity preface as its FIRST frame, then
  ///   attempt `authenticate` from the validated cert (the `CertOid` scheme binds here; `Hello`
  ///   stays `Authenticating` until its peer's preface frame arrives);
  /// - `stream_ready` → flush staged sends AND read frames off the recv streams, routing each by the
  ///   connection's phase: an `Authenticating` connection's first CONTROL frame goes to
  ///   `authenticate`; a `Validated` connection's frames decode to consensus [`Message`]s fed to the
  ///   endpoint. Both classes are read for a `Validated` connection — Control AND Bulk — since
  ///   `partition` may have routed a message to either; Bulk carries no preface and no pre-`Validated`
  ///   frames, so it is read as consensus only. The ready handles are taken as a UNIQUE list
  ///   ([`Bridge::take_ready_unique`], folding in the previous pump's deferred reads), so each
  ///   connection is read at most ONE per-pass budget per pump; a read that stops on its budget with
  ///   stream bytes still readable defers the connection to the NEXT pump, so a buffered receive window
  ///   drains one budget per pump rather than all at once;
  /// - `lost` → reap the closed connection.
  fn drain_bridge<W: Wal, B: Superblock>(&mut self, now: Instant, wal: &mut W, sb: &mut B) {
    let std_now = self.quinn_now(now);
    while let Some(h) = self.bridge.take_connected() {
      // Open the send stream and write our control preface as frame-0. `Hello` writes the hello
      // bytes; `CertOid` writes nothing (its identity rides in the cert). The send stream is empty
      // here (consensus frames are gated until `Validated`), so the preface leads the stream.
      let mut preface = Vec::new();
      self.identity.write_control_preface(self.me(), &mut preface);
      self.bridge.open_send_and_preface(std_now, h, &preface);
      // Attempt to bind from the cert immediately — the cert-only probe: NO control frame has been
      // delivered yet, passed as `None` so a preface source can tell it apart from a (later) delivered
      // frame. The cert chain is already validated by the TLS handshake; for `CertOid` this yields the
      // candidate now, with no control bytes. `Hello` returns `Pending` on the `None` and stays
      // `Authenticating` until its peer's first recv frame is delivered to `authenticate` below.
      let certs = self.bridge.peer_certs(h);
      let outcome = self
        .identity
        .authenticate(&IdentityCtx::new(&certs, None, self.cluster()));
      self.apply_outcome(std_now, h, outcome);
    }
    // Take this pump's stream-ready work as an order-preserving UNIQUE list (deferred reads from the
    // previous pump folded in, duplicate handles collapsed), so each handle is read at most one budget per
    // pump — the receive-pacing bound (see `take_ready_unique`). A read that leaves bytes re-defers onto
    // `deferred_ready`, picked up next pump.
    for h in self.bridge.take_ready_unique() {
      // A `Writable` event means a formerly-blocked send may now make progress: retry the staged
      // outbound (a no-op when nothing is staged or the connection is not yet `Validated`). A
      // `Readable` event means new bytes to decode.
      self.bridge.flush_stream(std_now, h);
      // Fill the decoders from the recv streams and classify any fatal close. `ingest_recv` returns
      // `true` ONLY when it reaped the connection INLINE with nothing queued to deliver (see its bool
      // contract); a DEFERRED close records its disposition on `pending_fin_close` for the teardown below
      // and returns `false`. So this `continue` is a perf skip of a provably-empty frame drain — NOT a
      // skip that could drop a queued frame, since deliver-before-close holds whether or not it is taken.
      if self.bridge.ingest_recv(std_now, h) {
        continue;
      }
      // The CONTROL class carries the identity preface first (the `Authenticating`→`Validated` flip)
      // then consensus frames. Pull frames one at a time, routing by phase. The phase can FLIP
      // mid-batch: an `Authenticating` connection whose preface frame validates becomes `Validated`,
      // after which the remaining Control frames in this same batch are consensus messages.
      while let Some(payload) = self.bridge.next_frame(h, StreamClass::Control) {
        if self.bridge.is_authenticating(h) {
          // The first control frame is the peer's identity preface — authenticate, NOT decode. It is
          // delivered as `Some(&payload)` (a COMPLETE popped frame), so a preface source treats it as
          // the sole Hello opportunity: a short/empty/partial first frame is REJECTED here, never left
          // `Pending` for a later frame to bind.
          let certs = self.bridge.peer_certs(h);
          let outcome =
            self
              .identity
              .authenticate(&IdentityCtx::new(&certs, Some(&payload), self.cluster()));
          self.apply_outcome(std_now, h, outcome);
          // If the binding rejected (or the candidate mismatched), the connection is now closed and
          // queued onto `lost`; stop pulling frames from it.
          if !self.bridge.is_validated(h) {
            break;
          }
        } else if self.bridge.is_validated(h) {
          // A validated connection: the frame is a consensus message. A frame that fails to decode
          // is dropped (the consensus layer retransmits); keep draining the rest of the batch.
          if let (Some(from), Ok(msg)) = (self.bridge.bound_peer_of(h), Message::decode(&payload)) {
            self.deliver_decoded(now, wal, sb, from, msg);
          }
        } else {
          // `Closed` (or otherwise no longer routable): drop the remaining frames.
          break;
        }
      }
      // The BULK class carries NO preface and no pre-`Validated` frames (consensus frames are gated
      // behind `Validated`), so it is drained as consensus ONLY for a `Validated` connection. A `Single`-layout connection
      // never opens a Bulk recv stream, so this is an empty drain there. The proto tolerates reorder,
      // so interleaving Bulk frames with the Control batch above is safe.
      if self.bridge.is_validated(h) {
        while let Some(payload) = self.bridge.next_frame(h, StreamClass::Bulk) {
          if let (Some(from), Ok(msg)) = (self.bridge.bound_peer_of(h), Message::decode(&payload)) {
            self.deliver_decoded(now, wal, sb, from, msg);
          }
        }
      }
    }
    // A class whose recv took a DEFERRED fatal close this pump (a graceful FIN, or an over-cap framing
    // error behind a complete prefix) decoded its pre-fault bytes into the decoder, and the frame drains
    // above just DELIVERED those queued frames (the faulting handle was in `take_ready_unique` — its FIN
    // arrived as a readable STREAM frame). Only NOW run the deferred teardown, so a final vote/commit the
    // peer wrote immediately before finishing its send half — or queued ahead of a torn/over-cap frame —
    // reached the consensus layer first. `finish_fin_close` applies the disposition recorded at fault
    // time: `Clean` runs the class-split (Control reaps the connection, Bulk retires the stream in place),
    // `Truncated` reaps the whole connection. An abandoned (peer RESET / closed) fatal with nothing to
    // deliver already tore down INLINE in `ingest_recv` (its bytes were discarded), so it never lands here.
    while let Some((h, class, disposition)) = self.bridge.take_pending_fin_close() {
      self.bridge.finish_fin_close(std_now, h, class, disposition);
    }
    while let Some(h) = self.bridge.take_lost() {
      self.bridge.reap(h);
    }
  }

  /// Deliver one decoded inbound `(from, msg)` to the consensus endpoint, enforcing the transport's
  /// deliverable-body bound at this ingress: a `Message::Request` whose body exceeds
  /// [`max_request_body_len`](crate::transport::frame::max_request_body_len) is DROPPED before it
  /// reaches the endpoint, so no op is appended, no client session row is created, and no `Prepare` is
  /// routed.
  ///
  /// This ingress accepts a `Request` RELAYED by another replica (not only one straight from
  /// the client). A buggy or version-skewed member could relay a `Request` that fits the `Request`
  /// frame yet whose resulting `Prepare` would exceed
  /// [`MAX_FRAME_LEN`](crate::transport::frame::MAX_FRAME_LEN) — the primary would log an op it can then
  /// never replicate (the oversized `Prepare` is dropped by the send path), wedging that op. Gating at
  /// the coordinator — which owns `MAX_FRAME_LEN` — keeps the consensus core (`Endpoint`)
  /// transport-agnostic: it never learns the frame limit. Every other message kind is forwarded
  /// unchanged. Single chokepoint for both decoded stream classes (Control and Bulk).
  fn deliver_decoded<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    from: Peer,
    msg: Message,
  ) {
    if let Message::Request(r) = &msg
      && r.body().len() > crate::transport::frame::max_request_body_len()
    {
      return;
    }
    self.endpoint.handle_message(now, wal, sb, from, msg);
    #[cfg(test)]
    {
      self.consensus_frames_delivered += 1;
    }
  }

  /// Apply the coordinator-owned binding policy to an [`IdentityOutcome`] for connection `h`.
  ///
  /// - `Identified(candidate)`: the candidate's attested cluster MUST equal this endpoint's
  ///   `Config.cluster` (the cross-check the COORDINATOR owns); the candidate must be a REPLICA whose
  ///   attested stable [`MemberId`] is IN the active membership — resolved to a routing slot via
  ///   `Endpoint::slot_of` (an absent member is REJECTED: it is not part of the active configuration);
  ///   and it must NOT be THIS node's own member id (a replica never binds a peer claiming to be
  ///   itself — the gate an ACCEPTED connection's absent dialed expectation would otherwise miss). Then
  ///   a DIALED connection requires the resolved routing peer to equal the dialed expectation
  ///   (match-or-abort) while an ACCEPTED connection ADOPTS it. On acceptance the peer is bound (keyed
  ///   by its routing slot `Peer::Replica(slot)`) and the connection promoted to `Validated` (flushing
  ///   staged consensus); on any mismatch the connection is closed + reaped.
  /// - `Pending`: more control bytes are needed — leave the connection `Authenticating`.
  /// - `Rejected`: close + reap.
  ///
  /// The attestation + admission are MemberId-based; the ConnTable routing stays keyed by the resolved
  /// `Peer::Replica(slot)`. For the PROVIDED sources the cluster cross-check is un-bypassable (they
  /// report the genuine attested cluster parsed from the handshake material); a
  /// [`Self::dangerous_custom_identity`] source owns its own attested cluster, so the check there only
  /// re-confirms what the source reports.
  fn apply_outcome(
    &mut self,
    std_now: std::time::Instant,
    h: ConnectionHandle,
    outcome: IdentityOutcome,
  ) {
    let identified = match outcome {
      IdentityOutcome::Identified(id) => id,
      IdentityOutcome::Pending => return,
      IdentityOutcome::Rejected => {
        self.bridge.close_local(std_now, h);
        return;
      }
    };
    // Cluster cross-check, OWNED by the coordinator: the attested cluster the source REPORTS must
    // equal this endpoint's `Config.cluster`, asserted BEFORE the membership resolution and the
    // dialed-match/adopt. For the PROVIDED sources this is un-bypassable: `Hello`/`CertOid` report the
    // genuine cluster parsed from the handshake material, so a misconfigured-field source still keys off
    // the endpoint cluster and a wrong-cluster peer is rejected here. A `dangerous_custom_identity`
    // source owns its own attested cluster (it may report any cluster), so this only re-confirms what
    // that source asserts — the embedder owns that correctness per the named hazard.
    if identified.cluster() != self.cluster() {
      self.bridge.close_local(std_now, h);
      return;
    }
    // The attested identity must be a REPLICA's stable `MemberId` (a CLIENT identity uses a separate
    // endpoint, so `as_replica()` is `None` → reject).
    let Some(member_id) = identified.id().as_replica() else {
      self.bridge.close_local(std_now, h);
      return;
    };
    // A replica must NEVER bind a peer claiming to be ITSELF, keyed on the stable member id. An ACCEPTED
    // connection has no dialed expectation, so without this gate a duplicate-id / misconfigured member
    // presenting a valid cluster cert for THIS node's own member id would bind AS this node — and that
    // bound peer becomes the `from` a consensus frame is delivered under, satisfying the endpoint's
    // sender check for a network-supplied self-identifying message. In-model duplicate-identity (it
    // needs a valid cluster cert for our id), not a Byzantine claim. Checked BEFORE the membership
    // resolution: a node IS in its own membership, so resolving first would admit the self-claim.
    if member_id == self.endpoint.local() {
      self.bridge.close_local(std_now, h);
      return;
    }
    // Resolve the attested stable `MemberId` to its routing slot against the ACTIVE membership. `Some`
    // ⇒ the peer is a member of the active configuration; bind it under `Peer::Replica(slot)`. `None` ⇒
    // the member is NOT in the active membership (a retired / not-yet-added / foreign-but-cluster-valid
    // cert), so REJECT: without this gate such a peer would consume a slot and join the
    // `Backups`/`AllReplicas` fanout, yet the endpoint's own `sender_matches` then drops every inbound
    // consensus frame from it. In-model misconfiguration, not a Byzantine claim.
    let Some(slot) = self.endpoint.slot_of(member_id) else {
      self.bridge.close_local(std_now, h);
      return;
    };
    let routing_peer = Peer::Replica(slot);
    match self.bridge.dialed_expectation_of(h) {
      // Dialed: the resolved routing peer must be exactly the peer we meant to reach.
      Some(expected) if routing_peer != expected => {
        self.bridge.close_local(std_now, h);
        return;
      }
      // Dialed-and-matched, or accepted (adopt): fall through to bind.
      _ => {}
    }
    self.bridge.bind_validated(std_now, h, routing_peer);
  }

  /// Drain the endpoint's outgoing backlog into an owned `Vec` (releasing the endpoint borrow),
  /// route each message over the resolved peers' streams, then run ONE unconditional
  /// [`Bridge::service`] over the whole bridge. Routing inside the poll loop would not borrow-check
  /// (the bridge write needs `&mut self.bridge` while the poll borrows the endpoint).
  ///
  /// **The pump-end `service` is the single, correct-by-construction wakeup mechanism for the QUIC
  /// transport.** This `pump` is the last step of EVERY coordinator pass — `handle_udp`,
  /// `handle_timeout`, `handle_storage` (and the test receive pump) all run `drain_bridge` then this
  /// `pump`. So this final `service` runs AFTER all of `drain_bridge`'s connection mutations
  /// (`ingest_recv` reads + credit, `flush_stream`, `bind_validated`, the accept-loop `stop`,
  /// `close_local`, …) AND after this `pump`'s own routing `write_framed`s. quinn collects a
  /// connection's queued transmit / credit / control frames (`RESET_STREAM` / `STOP_SENDING` /
  /// `MAX_DATA` / STREAM data) only when `service` polls it (see [`Bridge::service`] step 4), so this
  /// guarantees every frame any mutation queued THIS pass reaches `Bridge::out` THIS pass — it cannot
  /// be stranded in quinn (invisible to both `poll_transmit` and `has_pending_work`) until unrelated
  /// activity wakes a `poll_timeout`-driven driver. The mechanism is by construction, not per-operation:
  /// a future mutation added to `drain_bridge` or the send path needs NO `service` plumbing of its own
  /// to be wakeup-safe — this final pass collects whatever it queued.
  ///
  /// Not a busy-loop or a re-entrancy hazard: an idle connection's `service` produces nothing, the
  /// endpoint-event feedback it defers is one-tick work `has_pending_work` already reports for the next
  /// pass, and `service` is invoked here OUTSIDE any in-progress `service` pass — so it never re-enters.
  fn pump(&mut self, now: Instant) {
    let mut outgoing: Vec<Outgoing> = Vec::new();
    while let Some(o) = self.endpoint.poll_message() {
      outgoing.push(o);
    }
    let self_id = self.endpoint.replica();
    let std_now = self.quinn_now(now);
    for o in outgoing {
      self.route(std_now, o.to(), o.msg_ref(), self_id);
    }
    // The single correct-by-construction wakeup: collect into `out` every frame ANY mutation this pass
    // queued (see the doc above), so none is stranded in quinn until unrelated traffic wakes the driver.
    self.bridge.service(std_now);
  }

  /// Resolve `to` to the set of bound replica peers and frame-write `msg` to each peer's stream.
  /// Like the stream transport's router, resolution reaches only peers the bridge actually holds a
  /// connection for (never a bare `0..replica_count` enumeration):
  /// - `To(peer)` → that single peer;
  /// - `Backups` → every bound replica peer except this replica;
  /// - `AllReplicas` → every bound replica peer except this replica (self-loopback is the driver's
  ///   concern per [`Recipient`], and self is never in the bridge's peer set in any case).
  ///
  /// A peer with no validated connection is skipped — the consensus layer retransmits.
  fn route(
    &mut self,
    std_now: std::time::Instant,
    to: Recipient,
    msg: &Message,
    self_id: ReplicaId,
  ) {
    let self_peer = Peer::Replica(self_id);
    match to {
      Recipient::To(peer) => self.write_to_peer(std_now, peer, msg),
      Recipient::Backups | Recipient::AllReplicas => {
        for peer in self.bridge.bound_replica_peers(Some(self_peer)) {
          self.write_to_peer(std_now, peer, msg);
        }
      }
    }
  }

  /// Write `msg` to `peer`'s stream if a connection is bound for it; otherwise drop (retransmitted).
  ///
  /// The class is chosen by [`layout::partition`] from the coordinator's `layout`: under `Single`
  /// everything rides Control; under `ControlBulk` state-transfer carriers and large `Prepare`s ride
  /// Bulk so they cannot head-of-line block latency-critical control traffic. The peer reads both
  /// classes (see [`Self::drain_bridge`]).
  fn write_to_peer(&mut self, std_now: std::time::Instant, peer: Peer, msg: &Message) {
    if let Some(h) = self.bridge.handle_for(peer) {
      let class = layout::partition(msg, self.layout);
      self.bridge.write_framed(std_now, h, class, msg);
    }
  }

  /// Feeds one message through the inbound ingress (`deliver_decoded`, so the deliverable-body gate
  /// applies) then pumps — the test shortcut for the decode path, mirroring
  /// `StreamCoordinator::inject_message_for_test`. The live caller is the two-replica loopback, which
  /// seeds the primary with a client request once the link is up.
  #[cfg(test)]
  #[allow(dead_code)]
  pub(crate) fn inject_message_for_test<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    from: Peer,
    msg: Message,
  ) {
    self.deliver_decoded(now, wal, sb, from, msg);
    self.pump(now);
  }

  /// Count of consensus frames `drain_bridge` decoded and fed to the endpoint so far (the
  /// receive-pacing test reads it before/after each pump).
  #[cfg(test)]
  pub(crate) fn consensus_frames_delivered(&self) -> u64 {
    self.consensus_frames_delivered
  }

  /// The bridge's count of connections deferred for the next read budget (the receive-pacing test
  /// uses it to know whether a buffered receive window still has another budget to drain).
  #[cfg(test)]
  pub(crate) fn bridge_deferred_ready_len(&self) -> usize {
    self.bridge.deferred_ready_len()
  }

  /// Feed one datagram into the QUIC stack WITHOUT running `drain_bridge` — the stream bytes buffer in
  /// quinn's reassembly without any frame being popped to the endpoint. Lets the receive-pacing test
  /// pre-load a multi-budget receive window, then measure how many separate pumps drain it.
  #[cfg(test)]
  pub(crate) fn feed_datagram_for_test(&mut self, now: Instant, remote: SocketAddr, data: &[u8]) {
    let std_now = self.quinn_now(now);
    self.bridge.handle_datagram(std_now, remote, None, data);
  }

  /// Route one outbound `msg` through the PRODUCTION send path (`route` → `write_to_peer` →
  /// `Bridge::write_framed`) exactly as `pump` does for an endpoint-emitted message. The
  /// oversized-outbound public-API test uses this to drive one over-`MAX_FRAME_LEN` message to a bound
  /// peer and then read the drop through the PUBLIC [`Self::oversized_outbound_dropped`], without
  /// having to coax the consensus endpoint into emitting a 16 MiB frame of its own.
  #[cfg(test)]
  pub(crate) fn route_message_for_test(&mut self, now: Instant, to: Recipient, msg: &Message) {
    let self_id = self.endpoint.replica();
    let std_now = self.quinn_now(now);
    self.route(std_now, to, msg, self_id);
  }

  /// Stage a pre-framed `blob` onto `peer`'s bound Control send stream and flush it, so the peer's
  /// transmits carry the whole burst. Mirrors a prior `Blocked` write having left bytes staged.
  #[cfg(test)]
  pub(crate) fn stage_control_burst_for_test(&mut self, now: Instant, peer: Peer, blob: &[u8]) {
    if let Some(h) = self.bridge.handle_for(peer) {
      let std_now = self.quinn_now(now);
      self
        .bridge
        .stage_class_outbound(h, StreamClass::Control, blob);
      self.bridge.flush_stream(std_now, h);
    }
  }

  /// Run ONE receive pump — `drain_bridge` then `pump` — WITHOUT ingesting a new datagram or firing
  /// timers. This is the coordinator's pure receive-side progress step: it promotes deferred reads,
  /// reads at most one budget per connection, feeds the decoded frames to the endpoint, and pumps the
  /// endpoint's replies. The receive-pacing test calls it repeatedly to drain a buffered window one
  /// budget at a time.
  #[cfg(test)]
  pub(crate) fn receive_pump_for_test<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
  ) {
    self.drain_bridge(now, wal, sb);
    self.pump(now);
  }

  /// The number of live entries in the bridge's connection table (test observable for the dial-cap
  /// boundary test and the membership-range loopback: a rejected candidate must not pin a slot).
  #[cfg(test)]
  pub(crate) fn bridge_table_len(&self) -> usize {
    self.bridge.table_len()
  }

  /// The number of connections the bridge's quinn endpoint still tracks in its slab (test observable
  /// for the dial-cap boundary test: a refused dial must allocate neither a table entry nor a slab
  /// slot).
  #[cfg(test)]
  fn bridge_endpoint_open_connections(&self) -> usize {
    self.bridge.endpoint_open_connections()
  }

  /// Every replica peer the bridge holds a bound (validated) connection for — the `Backups`/
  /// `AllReplicas` outbound fanout. The membership-range loopback test reads it to assert an
  /// out-of-membership candidate is NOT bound (never enters the fanout) while an in-range one is.
  #[cfg(test)]
  pub(crate) fn bound_replica_peers_for_test(&self) -> Vec<Peer> {
    self.bridge.bound_replica_peers(None)
  }

  /// The effective live-connection cap the bridge enforces. The mutual-dial-mesh sizing test reads it
  /// to assert the cap derived from `replica_count` covers `2*(replica_count - 1)` plus headroom.
  #[cfg(test)]
  pub(crate) fn max_connections_for_test(&self) -> usize {
    self.bridge.max_connections()
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{
    Config, Endpoint, Instant, MemberId, Peer, ReplicaId, SingleChange,
    transport::{
      quic::{crypto::test_ca, testutil::addr},
      testutil::{CountSm, genesis},
    },
  };

  /// A mandatory-mTLS [`QuicOptions`] for `cluster` (a fresh `ClusterTls` bundle), so `with_identity`'s
  /// `requires_client_auth()` invariant holds. These coordinator tests exercise dial-cap / clock-anchor
  /// behavior, not identity, but `with_identity` (correctly) refuses a no-auth options bundle, so they
  /// must build a real cluster-private mTLS config rather than the accept-any test path.
  fn mtls_opts(cluster: u128) -> QuicOptions {
    let ca = test_ca();
    let cert = ca.issue_replica(0, cluster);
    ClusterTls::new(ca.roots(), cert.chain(), cert.key()).build()
  }

  #[test]
  fn connect_emits_an_initial_datagram() {
    let cluster = 0x5151;
    let cfg = Config::try_new(cluster, MemberId::new(0)).unwrap();
    let mut c = QuicCoordinator::with_identity(
      Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(2), 1, CountSm::default()),
      mtls_opts(cluster),
      Some([0u8; 32]),
      IdentityConfig::Hello { cluster },
    );
    c.connect(Instant::ZERO, addr(2), Peer::Replica(ReplicaId::new(1)))
      .expect("the first dial on a fresh coordinator is under the cap");
    let dgram = c.poll_transmit();
    assert!(dgram.is_some(), "dialing must produce an Initial datagram");
    assert_eq!(
      dgram.unwrap().0,
      addr(2),
      "the Initial is addressed to the dialed peer"
    );
  }

  #[test]
  fn sni_for_matches_the_replica_cert_san_form() {
    // The dialer's SNI must equal the SAN the ClusterTls issuer mints (B1), so the stock
    // WebPkiServerVerifier matches it.
    assert_eq!(
      sni_for(Peer::Replica(ReplicaId::new(1)), 0x5151),
      "replica-1.00000000000000000000000000005151.viewstamp"
    );
  }

  /// The connection cap is surfaced at the PUBLIC coordinator boundary: once the effective cap's worth
  /// of dials are live, the NEXT `connect` returns `Err(DialError::AtCapacity { cap })`, leaving the
  /// bridge's table and the quinn endpoint slab unchanged. The coordinator used to swallow the bridge's
  /// typed `DialError` (a `let _ =`), so an over-cap dial was indistinguishable from a scheduled one;
  /// surfacing it lets a caller back off / report saturation / test the cap here.
  ///
  /// The effective cap is the membership-sized one the coordinator derives (the explicit `1` here is
  /// RAISED to the mutual-dial-mesh floor), so the test fills exactly `cap` dials and asserts the
  /// `cap+1`th is refused — robust to the membership sizing rather than assuming a literal `1`.
  #[test]
  fn a_public_connect_over_the_cap_returns_at_capacity_and_allocates_nothing() {
    let cluster = 0x5151;
    let cfg = Config::try_new(cluster, MemberId::new(0)).unwrap();
    let mut c = QuicCoordinator::with_identity(
      Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(2), 1, CountSm::default()),
      // Explicit `1` is floored up to the mutual-dial-mesh minimum; read the effective cap below.
      mtls_opts(cluster).with_max_connections(1),
      Some([0u8; 32]),
      IdentityConfig::Hello { cluster },
    );
    let cap = c.max_connections_for_test();

    // Fill the cap with distinct dials (distinct expected peer + address each): all admitted, each
    // allocating one table entry and one slab slot.
    for i in 0..cap {
      c.connect(
        Instant::ZERO,
        addr(1000 + i as u16),
        Peer::Replica(ReplicaId::new(1 + i as u16)),
      )
      .expect("a dial under the cap is admitted");
    }
    assert_eq!(
      c.bridge_table_len(),
      cap,
      "the cap's worth of dials are live"
    );
    assert_eq!(
      c.bridge_endpoint_open_connections(),
      cap,
      "each admitted dial allocates one endpoint slab slot"
    );

    // The next dial is AT the cap: the PUBLIC API must surface the typed AtCapacity error (carrying the
    // effective cap) and allocate nothing — the gate runs before `endpoint.connect`, so no partial state.
    let over = c.connect(Instant::ZERO, addr(2000), Peer::Replica(ReplicaId::new(0)));
    assert_eq!(
      over,
      Err(DialError::AtCapacity { cap }),
      "an over-cap public dial returns the typed AtCapacity error carrying the effective cap"
    );
    assert_eq!(
      c.bridge_table_len(),
      cap,
      "a refused dial must NOT add a table entry past the cap"
    );
    assert_eq!(
      c.bridge_endpoint_open_connections(),
      cap,
      "a refused dial must NOT allocate an endpoint slab slot past the cap"
    );
  }

  /// `DialError` is nameable through the crate's PUBLIC re-export, exactly as an external caller would
  /// reach it (`viewstamp_proto::DialError`). The `transport` / `quic` / `bridge` modules are all
  /// private, so before the crate-root re-export an external caller received `connect`'s typed error
  /// but could not name it or `match` its `AtCapacity` variant — the error was `pub` but unreachable.
  ///
  /// This test deliberately refers to the type ONLY via `crate::DialError` (the in-crate spelling of
  /// the public path), NOT via the private `super::DialError` / `bridge::DialError` module path the
  /// other dial-cap tests use, so it fails to compile if the crate-root re-export regresses. It drives
  /// a public `connect` over the cap and `match`es the typed variant the public API returns.
  #[test]
  fn dial_error_is_nameable_through_the_public_reexport() {
    // Bind the type through the PUBLIC re-export path. An external crate would write
    // `use viewstamp_proto::DialError;`; in-crate that public item is `crate::DialError`.
    use crate::DialError;

    let cluster = 0x5151;
    let cfg = Config::try_new(cluster, MemberId::new(0)).unwrap();
    let mut c = QuicCoordinator::with_identity(
      Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(2), 1, CountSm::default()),
      // Explicit `1` is floored up to the mutual-dial-mesh minimum; read the effective cap below.
      mtls_opts(cluster).with_max_connections(1),
      Some([0u8; 32]),
      IdentityConfig::Hello { cluster },
    );
    let effective_cap = c.max_connections_for_test();

    // Fill the effective cap with distinct dials, all under the cap.
    for i in 0..effective_cap {
      c.connect(
        Instant::ZERO,
        addr(1000 + i as u16),
        Peer::Replica(ReplicaId::new(1 + i as u16)),
      )
      .expect("a dial under the cap is admitted");
    }

    // The over-cap dial returns the typed error, named + destructured through the public re-export.
    let cap = match c.connect(Instant::ZERO, addr(2000), Peer::Replica(ReplicaId::new(0))) {
      Err(DialError::AtCapacity { cap }) => cap,
      other => panic!("expected Err(DialError::AtCapacity) from the public API, got {other:?}"),
    };
    assert_eq!(
      cap, effective_cap,
      "the typed AtCapacity carries the effective (membership-sized) cap"
    );
  }

  /// A coordinator FIRST driven at a non-zero viewstamp epoch maps quinn time anchored at that epoch,
  /// so `poll_timeout` reports quinn's small real timer — NOT a deadline pushed the whole epoch into
  /// the future.
  ///
  /// The clock adapter is anchored LAZILY on the first `quinn_now` (here the first `connect`) to the
  /// driver's actual first-seen `now`, so `quinn_now(first_now) == std_base` (the real instant captured
  /// then). A real driver's monotonic clock does NOT start at zero; a freshly-dialed connection arms
  /// quinn's handshake/initial timer tens-to-hundreds of ms out, and `poll_timeout` must return that —
  /// a deadline within a small delta of real-now — so a sleep-until-`poll_timeout` driver wakes to
  /// retransmit the handshake on time (and likewise reaps auth / drains closes on time).
  ///
  /// This drives the FIRST `connect` at viewstamp epoch 10 s and asserts the reported `poll_timeout`
  /// deadline is well under 1 s past real-now — i.e. quinn's handshake timer, not an epoch-shifted one.
  ///
  /// NEUTER CHECK: anchor `vsr_base = Instant::ZERO` (the old `build`) instead of lazily to the first
  /// `now`, and `quinn_now(10s) == std_base + 10s`, so the connection's timers — and the reported
  /// deadline — sit ~10 s in the future: the assertion below (deadline < real-now + 1 s) fails, exactly
  /// the over-long sleep this fixes.
  #[test]
  fn poll_timeout_is_anchored_to_a_non_zero_driver_epoch() {
    use core::time::Duration;

    let cluster = 0x5151;
    let cfg = Config::try_new(cluster, MemberId::new(0)).unwrap();
    let mut c = QuicCoordinator::with_identity(
      Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(2), 1, CountSm::default()),
      mtls_opts(cluster),
      Some([0u8; 32]),
      IdentityConfig::Hello { cluster },
    );

    // A driver whose monotonic clock starts well past zero: the FIRST drive is at viewstamp epoch 10 s.
    // The lazy anchor pins (vsr_base, std_base) = (10 s, real-now) on this call.
    let epoch = Instant::from_nanos(10_000_000_000);
    let real_before = std::time::Instant::now();
    c.connect(epoch, addr(2), Peer::Replica(ReplicaId::new(1)))
      .expect("the first dial on a fresh coordinator is under the cap");
    let real_after = std::time::Instant::now();

    // The dialed connection arms quinn's handshake/initial timer (tens-to-hundreds of ms out). The
    // reported deadline must be that timer measured from REAL now — NOT offset by the 10 s epoch.
    let deadline = c
      .poll_timeout()
      .expect("a freshly-dialed connection arms a quinn timer");
    let ahead = deadline.saturating_duration_since(real_before);
    assert!(
      ahead < Duration::from_secs(1),
      "poll_timeout must report quinn's handshake timer anchored at the driver's real epoch (< 1 s \
       ahead of real-now), not a deadline shifted by the 10 s viewstamp epoch; got {ahead:?} ahead"
    );
    // And it is a genuine FUTURE timer, not already elapsed — i.e. the dial really armed one. (Allow
    // for the tiny real-time the dial itself consumed between `real_before` and `real_after`.)
    assert!(
      deadline >= real_after || deadline.saturating_duration_since(real_before) > Duration::ZERO,
      "the reported deadline is quinn's armed handshake timer, in the (near) future"
    );
  }

  /// The SAFE provided-identity constructor enforces the load-bearing invariant: it REJECTS a
  /// `QuicOptions` that lacks mandatory client-certificate auth. The provided `Hello` source binds an
  /// accepted connection from a SELF-CLAIMED control preface; that self-claim is trustworthy only
  /// because mandatory mTLS over cluster-private roots has already proven the peer holds a cluster
  /// cert. A no-auth options bundle (the `accept_any_for_test` path, `requires_client_auth() == false`)
  /// would turn sender identity into unauthenticated labeling, so `with_identity` panics on it — arbitrary
  /// / no-auth options belong only behind the named `dangerous_custom_identity` hazard.
  ///
  /// NEUTER CHECK: drop the `opts.requires_client_auth()` assert in `with_identity`, and this no-auth
  /// bundle is accepted — exactly the unauthenticated-`Hello`-binding hole the assert closes.
  #[test]
  #[should_panic(expected = "mandatory mTLS")]
  fn with_identity_rejects_options_without_mandatory_client_auth() {
    let cluster = 0x5151;
    let cfg = Config::try_new(cluster, MemberId::new(0)).unwrap();
    // `accept_any_for_test` builds a server WITHOUT client auth (`requires_client_auth() == false`):
    // the provided-identity invariant forbids it on the safe path.
    let _ = QuicCoordinator::with_identity(
      Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(2), 1, CountSm::default()),
      QuicOptions::accept_any_for_test(),
      Some([0u8; 32]),
      IdentityConfig::Hello { cluster },
    );
  }

  /// The companion to the rejection above: a `ClusterTls::build` bundle (mandatory mTLS over
  /// cluster-private roots, `requires_client_auth() == true`) is ACCEPTED by `with_identity`, so the
  /// invariant gates the unsafe options without blocking the intended cluster-private path.
  #[test]
  fn with_identity_accepts_cluster_tls_mandatory_mtls_options() {
    let cluster = 0x5151;
    let opts = mtls_opts(cluster);
    assert!(
      opts.requires_client_auth(),
      "a ClusterTls::build bundle carries mandatory client auth"
    );
    let cfg = Config::try_new(cluster, MemberId::new(0)).unwrap();
    // Must not panic: the safe provided-identity path accepts a mandatory-mTLS options bundle.
    let c = QuicCoordinator::with_identity(
      Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(2), 1, CountSm::default()),
      opts,
      Some([0u8; 32]),
      IdentityConfig::Hello { cluster },
    );
    assert_eq!(
      c.endpoint().cluster(),
      cluster,
      "the coordinator wraps the endpoint for the configured cluster"
    );
  }

  /// Build a coordinator for a `replica_count`-replica cluster (this node `Replica(0)`), optionally
  /// overriding the connection cap, and return the EFFECTIVE cap the bridge ended up with.
  fn effective_cap(replica_count: u8, override_cap: Option<usize>) -> usize {
    let cluster = 0x5151;
    let cfg = Config::try_new(cluster, MemberId::new(0)).unwrap();
    let mut opts = mtls_opts(cluster);
    if let Some(cap) = override_cap {
      opts = opts.with_max_connections(cap);
    }
    let c = QuicCoordinator::with_identity(
      Endpoint::<_, SingleChange>::with_reconfig(
        cfg,
        genesis(replica_count),
        1,
        CountSm::default(),
      ),
      opts,
      Some([0u8; 32]),
      IdentityConfig::Hello { cluster },
    );
    c.max_connections_for_test()
  }

  /// The effective connection cap is sized to the configured membership so it covers the full
  /// mutual-dial mesh (`2*(replica_count - 1)` connections) for any supported cluster — the 64 default
  /// alone would refuse mesh dials past ~33 replicas (a liveness failure at scale). The coordinator
  /// RAISES the cap to `mesh_connection_floor(replica_count)` (`3*(N-1)`, floored) at construction.
  ///
  /// NEUTER CHECK: drop the `with_max_connections(...max(mesh_floor))` raise in `build` and the N=64
  /// effective cap stays at the 64 default — below the `2*63 = 126` mesh need — so the `>= 126`
  /// assertion fails, exactly the at-scale mesh starvation this fixes.
  #[test]
  fn the_connection_cap_covers_the_mutual_dial_mesh_for_the_configured_membership() {
    // A small cluster: the derived cap must cover the steady-state mesh (`2*(5-1) = 8`).
    let n5 = effective_cap(5, None);
    assert!(
      n5 >= 2 * (5 - 1),
      "a 5-replica node's cap ({n5}) must cover its {}-connection mutual-dial mesh",
      2 * (5 - 1)
    );

    // The supported maximum (64 replicas): the bare mesh is `2*63 = 126`; the derived cap must be at
    // least that, so the whole mesh forms before the cap refuses anything.
    let n64 = effective_cap(64, None);
    assert!(
      n64 >= 126,
      "a 64-replica node's effective cap ({n64}) must be >= 126 (the 2*(64-1) steady-state mesh); the \
       64 default would starve the mesh past ~33 replicas"
    );

    // An EXPLICIT override BELOW the mesh need is raised to the floor (the cap must never refuse a
    // legitimate steady-state mesh connection), while an override ABOVE the floor is honoured as-is.
    let raised = effective_cap(5, Some(2));
    assert!(
      raised >= 2 * (5 - 1),
      "an explicit cap below the mesh need ({raised}) must be raised to cover the 5-replica mesh"
    );
    let generous = effective_cap(5, Some(1000));
    assert_eq!(
      generous, 1000,
      "an explicit cap above the mesh floor is honoured as-is (a larger flood budget)"
    );
  }

  /// A 1-replica cluster (no peers, so a zero-connection mesh) still keeps the small constant floor, so
  /// a degenerate single-node config is not capped to zero admissible connections.
  #[test]
  fn the_connection_cap_keeps_a_floor_for_a_tiny_cluster() {
    let n1 = effective_cap(1, Some(1));
    assert!(
      n1 >= 4,
      "even a 1-replica node keeps a small connection floor ({n1}) for accept/reconnect headroom"
    );
  }

  /// A relayed (replica-sent) `Request` whose body is ONE byte over the deliverable maximum is dropped
  /// at the QUIC transport ingress BEFORE the endpoint: it appends no op and is never fed to
  /// `handle_message` (the consensus-frame counter does not advance). The hazard: a buggy /
  /// version-skewed member relays a `Request` that fits its own frame but whose resulting `Prepare`
  /// would exceed `MAX_FRAME_LEN`, so the primary would log an op it can never replicate. The
  /// at-maximum body, by contrast, is served
  /// and reaches the endpoint — the boundary is usable. The gate keeps the consensus `Endpoint`
  /// transport-agnostic.
  #[test]
  fn a_relayed_over_max_request_is_dropped_at_quic_ingress_with_no_side_effects() {
    use crate::{
      ClientId, Message, Request, RequestNumber,
      transport::{
        frame::{MAX_FRAME_LEN, max_request_body_len},
        testutil::{TestSb, TestWal},
      },
    };
    use bytes::Bytes;

    let cluster = 0x5151;
    // Replica 0 is the primary of view 0, so an admitted relayed Request would be served.
    let cfg = Config::try_new(cluster, MemberId::new(0)).unwrap();
    let mut wal = TestWal::default();
    let mut sb = TestSb::default();
    let mut c = QuicCoordinator::with_identity(
      Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(3), 1, CountSm::default()),
      mtls_opts(cluster),
      Some([0u8; 32]),
      IdentityConfig::Hello { cluster },
    );
    assert_eq!(c.endpoint().op().get(), 0, "no op before any request");
    assert_eq!(
      c.consensus_frames_delivered(),
      0,
      "no consensus frame delivered yet"
    );

    // A relayed Request (from a configured REPLICA — the replica-relayed ingress this gate guards)
    // whose body is one byte past the deliverable maximum: its resulting Prepare would exceed
    // MAX_FRAME_LEN.
    let over = Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(1),
      Bytes::from(vec![0u8; max_request_body_len() + 1]),
    ));
    c.inject_message_for_test(
      Instant::ZERO,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(1)),
      over,
    );
    assert_eq!(
      c.endpoint().op().get(),
      0,
      "an over-max relayed request appends no op (dropped before the endpoint)"
    );
    assert_eq!(
      c.consensus_frames_delivered(),
      0,
      "an over-max relayed request is never fed to handle_message (dropped at ingress)"
    );

    // The BOUNDARY: a body of EXACTLY max_request_body_len() reaches the endpoint and is served.
    assert!(
      max_request_body_len() < MAX_FRAME_LEN as usize,
      "the deliverable max is under the frame cap by the request overhead"
    );
    let at_max = Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(1),
      Bytes::from(vec![0u8; max_request_body_len()]),
    ));
    c.inject_message_for_test(
      Instant::ZERO,
      &mut wal,
      &mut sb,
      Peer::Replica(ReplicaId::new(1)),
      at_max,
    );
    assert_eq!(
      c.consensus_frames_delivered(),
      1,
      "an at-maximum relayed request IS delivered to the endpoint (the boundary is usable)"
    );
    assert_eq!(
      c.endpoint().op().get(),
      1,
      "and it IS served: one op appended (the gate admits exactly the max)"
    );
  }
}
