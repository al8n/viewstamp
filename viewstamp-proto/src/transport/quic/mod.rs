//! Sans-I/O QUIC transport over `quinn_proto`: the driver pumps UDP datagrams; the
//! consensus `Endpoint` and the deterministic oracle stay I/O-free. Std-only.
//!
//! **Compatibility with `quinn-proto`.** The bridge's reassembly sizing and its unsolicited-half
//! classifier were verified against `quinn-proto` 0.11.17, and both rest on behaviour that crate keeps
//! private: the per-stream span ceiling the window is sized against, the compaction rule that merges
//! only spans under 5/6 utilization, `Readable` being raised for a frame that arrived, and a reset
//! clearing the assembler before the application drains the event. The dependency is a plain `0.11`
//! range, so a newer patch release resolves without ceremony — this repository's own CI resolves fresh
//! and runs `a_full_stream_window_of_unread_packets_stays_within_the_reassembly_bound` and the
//! receiver-side span regression against whatever it picks. An embedder who pins or upgrades
//! `quinn-proto` themselves does not get that for free: run those two regressions as the compatibility
//! check.

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
pub use crypto::{
  ClusterTls, DEFAULT_CONNECTION_RECEIVE_WINDOW, DEFAULT_IDLE_TIMEOUT_MILLIS,
  DEFAULT_INITIAL_RTT_MILLIS, DEFAULT_STREAM_RECEIVE_WINDOW, MAX_STREAM_RECEIVE_WINDOW,
  QuicOptions, QuicTuning, StreamWindowTooLarge,
};
pub use identity::{
  AttestedId, CertOid, Hello, Identified, IdentityConfig, IdentityCtx, IdentityOutcome,
  IdentitySource, ProvidedIdentity,
};
pub use layout::StreamLayout;

use core::{net::SocketAddr, time::Duration};

use quinn_proto::{ConnectionHandle, EcnCodepoint};

use bridge::Bridge;
use layout::StreamClass;

use std::collections::BTreeSet;

use bytes::Bytes;

use crate::{
  AcceptReducedFaultTolerance, BlockStore, Endpoint, Event, Instant, MemberId, Message, OpNumber,
  Outgoing, Peer, Recipient, ReplicaId, Request, SingleChange, SingleVoterDelta, StateMachine,
  Superblock, Wal, decode_message, endpoint::ProposeMembershipError, storage::Storage,
};

/// Derive the SNI server-name a dial presents for `peer` in `cluster`.
///
/// The cert SAN minted by `ClusterTls`' issuer is keyed to the STABLE `MemberId`
/// (`replica-<MemberId>.<cluster-hex>.viewstamp`), so the dial MUST present the stable-id form.
/// The `Peer::Member` arm is therefore the normal dial path: `connect` resolves the dialed slot to
/// its stable `MemberId` and passes `Peer::Member(m)` here. The `Peer::Replica` arm is a fallback
/// for the initial dial before membership is installed (where slot == MemberId by genesis
/// convention) and for internal test helpers where the same property holds by construction. The
/// stock `WebPkiServerVerifier` validates the SNI against the server cert's SAN, so the cluster +
/// member binding is the per-connection cluster-separation guarantee.
fn sni_for(peer: Peer, cluster: u128) -> String {
  match peer {
    // Stable-id form: the cert SAN and this SNI agree on `MemberId`.
    Peer::Member(m) => format!("replica-{}.{:032x}.viewstamp", m.get(), cluster),
    // Slot-keyed fallback: valid only when slot == MemberId (genesis / no shift yet). Used by
    // internal test helpers that construct a coordinator directly and dial before a config change.
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
/// endpoint stay I/O-free underneath. Storage (the [`Storage`] session over `W`/`B`) is the third
/// orthogonal axis, threaded into every `handle_*` call.
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
pub struct QuicCoordinator<S: StateMachine, I> {
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
  /// The `config_id` the routing table was last reconciled against. A membership INSTALL happens
  /// INSIDE a `handle_*` pass (the endpoint advance can install a `MembershipChanged` or a cross-epoch
  /// sync membership), so [`Self::reconcile_routing`] runs after the advance and before the pump on
  /// every entry; comparing the endpoint's current `config_id` against this scalar makes that check a
  /// no-op unless the membership actually changed. Seeded from the endpoint's `config_id` at
  /// construction (the genesis config is already reconciled by construction — every bound peer was
  /// dialed/accepted under it).
  last_reconciled_config_id: u128,
  /// The execution-order witness of this coordinator's inline storage lane — one cursor per LANE, so
  /// a job executed out of the order the endpoint issued it fail-stops before it touches the store.
  block_lane: crate::BlockJobCursor,
  /// Test-only: count of consensus frames `drain_bridge` decoded and fed to the endpoint. The
  /// per-pump receive-pacing test reads this before/after each pump to assert ONE budget's worth is
  /// delivered per pump and that the whole burst eventually arrives.
  #[cfg(test)]
  consensus_frames_delivered: u64,
}

impl<S: StateMachine, I> core::fmt::Debug for QuicCoordinator<S, I> {
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
  ///
  /// The floor itself RESERVES [`Self::QUARANTINE_CONN_LIMIT`] on top of the mesh: the pre-identity
  /// capacity gate admits a connection into the bridge table BEFORE its attested id is resolved, so a
  /// burst of quarantined (attested-but-unresolvable) members would otherwise occupy mesh slots and let
  /// the bridge refuse a real replica's dial before the post-identity quarantine eviction can run.
  /// Raising the floor to `mesh_connection_floor + QUARANTINE_CONN_LIMIT` keeps the full mesh capacity
  /// available for authoritative members even when quarantine is saturated. An operator cap ABOVE that
  /// floor is honoured as-is (it is the operator's flood budget, already covering the mesh plus reserve);
  /// only a cap BELOW the floor is raised. The `max` (not an addition to the operator cap) avoids
  /// overflowing a `usize::MAX` override — the reserve is a floor GUARANTEE, not an increment.
  fn build(
    endpoint: Endpoint<S, SingleChange>,
    opts: QuicOptions,
    rng_seed: Option<[u8; 32]>,
    identity: I,
  ) -> Self {
    let layout = opts.layout();
    // `mesh_connection_floor` is bounded (at most `3*(node_count-1)` with `node_count <= 64`), so the
    // reserve addition here cannot overflow; the operator cap is folded in with a `max`, never an add.
    let floor_with_reserve = crypto::mesh_connection_floor(endpoint.node_count())
      .saturating_add(Self::QUARANTINE_CONN_LIMIT);
    let effective_cap = opts.max_connections().max(floor_with_reserve);
    let opts = opts.with_max_connections(effective_cap);
    let last_reconciled_config_id = endpoint.config_id();
    Self {
      endpoint,
      bridge: Bridge::new(&opts, rng_seed),
      identity,
      layout,
      clock_anchor: None,
      last_reconciled_config_id,
      block_lane: crate::BlockJobCursor::new(),
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
  pub fn propose_membership<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    storage: &mut Storage<W, B, S>,
    delta: SingleVoterDelta,
    ack: Option<AcceptReducedFaultTolerance>,
  ) -> Result<OpNumber, ProposeMembershipError> {
    self.endpoint.propose_membership(now, storage, delta, ack)
  }

  /// Solicit a voter-liveness-probe round — one `RequestHealthProof` per current voter — so the
  /// reconfiguration shrink executor can gate a removal on fresh per-round liveness. Delegates to
  /// [`Endpoint::solicit_health_proofs`]; a no-op off a Normal primary.
  pub fn solicit_health_proofs(&mut self, now: Instant, lifetime: Duration) {
    self.endpoint.solicit_health_proofs(now, lifetime);
  }

  /// The set of voter [`MemberId`]s PROVEN LIVE by the outstanding liveness-probe round (fail-closed
  /// empty when no fresh round exists) — the reconfiguration shrink executor's sole positive liveness
  /// evidence. Delegates to [`Endpoint::proven_live_voters`].
  pub fn proven_live_voters(&self, now: Instant) -> BTreeSet<MemberId> {
    self.endpoint.proven_live_voters(now)
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

  /// Resolve the SNI server name for dialing `slot`: the cert SAN is keyed to the stable
  /// [`MemberId`], so the dial MUST present that id, not the routing slot. When `slot` resolves to
  /// a `MemberId` in the active membership, `Peer::Member(id)` is passed to [`sni_for`]; when it
  /// does not (a dial before the first membership install, where genesis makes slot == MemberId),
  /// `Peer::Replica(slot)` is the fallback — the two produce identical output by genesis convention.
  fn sni_for_slot(&self, slot: ReplicaId) -> String {
    let peer = match self.endpoint.member_at(slot) {
      Some(m) => Peer::Member(m),
      None => Peer::Replica(slot),
    };
    sni_for(peer, self.cluster())
  }

  /// Dial the replica `expected` at `remote`. The dial records `expected` as the connection's
  /// expectation (the binding policy later requires the authenticated identity to match it).
  ///
  /// The SNI is derived from the dialed peer's STABLE `MemberId` (resolved from the slot via the
  /// active membership), not the routing slot. The cert SAN is minted per stable identity
  /// (`replica-<MemberId>.<cluster-hex>.viewstamp`), so a slot-keyed SNI fails TLS verification
  /// after any reconfiguration that shifts a member to a different slot. When the slot resolves to
  /// a `MemberId` in the active membership, `Peer::Member(id)` is used for the SNI; when it does
  /// not (only possible for a dial before the first membership install, where genesis convention
  /// makes slot == MemberId), `Peer::Replica(slot)` is the fallback — identical result by genesis.
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
    let server_name = match expected {
      Peer::Replica(slot) => self.sni_for_slot(slot),
      other => sni_for(other, self.cluster()),
    };
    let std_now = self.quinn_now(now);
    self
      .bridge
      .connect(std_now, remote, &server_name, expected)?;
    Ok(())
  }

  /// The SNI server name `connect` would present for `slot` — the stable-MemberId form
  /// (`replica-<MemberId>.<cluster-hex>.viewstamp`) when the slot resolves in the active
  /// membership, or the slot-keyed form for a pre-install dial where slot == MemberId by genesis.
  /// Test-only: used by the dial-SNI regression to assert the correct form without performing a
  /// real dial.
  #[cfg(test)]
  pub(crate) fn dial_sni_for_slot_for_test(&self, slot: ReplicaId) -> String {
    self.sni_for_slot(slot)
  }

  /// Feed one inbound UDP datagram from `remote` into the QUIC stack, then drain the bridge's
  /// connection events (bind newly-connected peers, decode readable streams into consensus
  /// messages) and pump the endpoint's resulting outgoing messages back out over the streams.
  #[allow(clippy::too_many_arguments)]
  pub fn handle_udp<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    remote: SocketAddr,
    ecn: Option<EcnCodepoint>,
    data: &[u8],
    storage: &mut Storage<W, B, S>,
  ) {
    let std_now = self.quinn_now(now);
    self.bridge.handle_datagram(std_now, remote, ecn, data);
    self.drain_bridge(now, storage);
    // The just-completed drain may have delivered a frame that INSTALLED a new membership; reconcile
    // routing against it BEFORE the pump routes this pass's outputs, so they never ride a stale slot.
    self.reconcile_routing(now);
    self.pump(now);
  }

  /// Fire all QUIC + consensus timers at `now`, then drain the bridge and pump.
  pub fn handle_timeout<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    storage: &mut Storage<W, B, S>,
  ) {
    let std_now = self.quinn_now(now);
    self.bridge.handle_timeout(std_now);
    self.endpoint.handle_timeout(now, storage);
    self.drain_bridge(now, storage);
    // A timeout-driven advance (or a frame the drain delivered) may have installed a new membership;
    // reconcile routing against it BEFORE the pump, so no current-config output rides a stale slot.
    self.reconcile_routing(now);
    self.pump(now);
  }

  /// Runs every block job the endpoint has queued against `blocks`, feeding each completion back,
  /// and re-drains WAL/superblock completions between jobs — a completion can submit the superblock
  /// write it gates (a materialized checkpoint publishing its snapshot), and a superblock completion
  /// can queue the next job. The loop settles once neither side produces work.
  ///
  /// This is the coordinator's INLINE storage lane, and the ONLY place it holds a block store. It
  /// satisfies the executor contract by construction: jobs execute strictly in poll order on ONE
  /// cursor, and their completions are fed back in that same order.
  fn drain_storage<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    storage: &mut Storage<W, B, S>,
    blocks: &mut dyn BlockStore,
  ) {
    loop {
      self.endpoint.handle_storage(now, storage);
      let Some(job) = storage.poll_block_job() else {
        break;
      };
      let done = crate::execute_block_job(&mut self.block_lane, job, blocks);
      self.endpoint.on_block_done(now, storage, done);
    }
  }

  /// Drive storage completions through the consensus endpoint, then pump its resulting messages.
  pub fn handle_storage<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    storage: &mut Storage<W, B, S>,
    blocks: &mut dyn BlockStore,
  ) {
    self.drain_storage(now, storage, blocks);
    self.settle(now, storage);
  }

  /// Drive WAL/superblock completions through the consensus endpoint and pump, leaving the block
  /// jobs the pass queued for an EXTERNAL storage lane: the caller drains them with
  /// [`Storage::poll_block_job`](crate::Storage::poll_block_job) — the queue is the lane's, so it
  /// comes off the session — and answers each with [`Self::on_block_done`].
  ///
  /// The lane-placement alternative to [`Self::handle_storage`]: that one holds the store and
  /// executes every job on the calling thread, this one holds no store at all, so a long
  /// materialize occupies the lane rather than the thread that pumps consensus. The caller owns
  /// the [`BlockJobCursor`](crate::BlockJobCursor) and therefore the serial-in-issue-order
  /// obligation the inline lane satisfies by construction.
  pub fn handle_storage_deferred<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    storage: &mut Storage<W, B, S>,
  ) {
    self.endpoint.handle_storage(now, storage);
    self.settle(now, storage);
  }

  /// Feeds back the completion of a block job an external storage lane executed, then pumps.
  ///
  /// Completions MUST arrive in the order their jobs were polled; the endpoint fail-stops on any
  /// other order.
  pub fn on_block_done<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    storage: &mut Storage<W, B, S>,
    done: crate::BlockJobDone<S>,
  ) {
    self.endpoint.on_block_done(now, storage, done);
    self.settle(now, storage);
  }

  /// The tail every storage-advancing entry point shares: drain the bridge (a completion can
  /// release consensus messages that arrive as frames), reconcile routing against a membership the
  /// advance may have installed — BEFORE the pump, so this pass's outputs use the new slots — then
  /// pump the endpoint's outputs.
  fn settle<W: Wal, B: Superblock>(&mut self, now: Instant, storage: &mut Storage<W, B, S>) {
    self.drain_bridge(now, storage);
    self.reconcile_routing(now);
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

  /// Reconcile the routing table against the currently-installed membership, closing every validated
  /// connection whose attested member was REMOVED or SHIFTED to a different slot. Called inside every
  /// endpoint-advancing entry (`handle_udp` / `handle_timeout` / `handle_storage`) AFTER the advance
  /// (which may have installed a `MembershipChanged` or a cross-epoch sync membership) and BEFORE the
  /// pump, so no current-config output is ever routed on a stale slot table.
  ///
  /// Cheap by default: a scalar `config_id` compare short-circuits when the membership is unchanged, so
  /// this runs the connection walk only on the rare pass that installed a new config. When it does run,
  /// each VALIDATED connection's attested STABLE member id is re-resolved against the NEW membership:
  ///
  /// - the member is NO LONGER present (removed, or this connection is for a member outside the new
  ///   config) → CLOSE the connection. `close_local` clears its `by_peer` routing slot, so it leaves the
  ///   `Backups`/`AllReplicas` fanout AT ONCE; the driver's dial-of-added-members rebuild will not redial
  ///   it (it is not in the new membership), so its redial is suppressed by construction.
  /// - the member's slot CHANGED → CLOSE so the connection re-handshakes; `apply_outcome` then resolves
  ///   the member's NEW slot via `slot_of` (against the already-installed membership) and re-binds under
  ///   `Peer::Replica(new_slot)`. The mutual-dial sibling reconnects under the new slot too.
  /// - the member's slot is UNCHANGED → leave it bound (the steady case for a retained member whose slot
  ///   did not move).
  ///
  /// This closes EVERY stale connection a removed/shifted member holds (the walk is over ALL validated
  /// connections, not just the authoritative routing target), so the slot table never routes to a
  /// removed old slot or misses a retained member's new slot. Safety is unchanged: the close only
  /// retires ROUTING — `sender_matches` / `epoch_authority_admits` still drop any stale-epoch frame.
  pub fn reconcile_routing(&mut self, now: Instant) {
    let current = self.endpoint.config_id();
    if current == self.last_reconciled_config_id {
      return;
    }
    let std_now = self.quinn_now(now);
    for (h, member, bound_peer) in self.bridge.validated_member_conns() {
      match self.endpoint.slot_of(member) {
        // Still unresolvable in the new config. A RESOLVED (`Peer::Replica`) member that dropped out
        // is removed: close + drop routing (redial suppressed) — it re-dials and binds QUARANTINED,
        // the intended posture for a node removed while offline. A member ALREADY quarantined
        // (`Peer::Member`) that still does not resolve is KEPT: its learn lane must persist until the
        // config catches up (or it idles out), never churned every install.
        None => {
          if bound_peer.is_replica() {
            self
              .bridge
              .close_local(std_now, h, crate::transport::CloseCause::Superseded);
          }
        }
        // Resolved to a DIFFERENT routing peer than it is bound under — a retained member whose slot
        // shifted, OR a quarantined member the new config now RESOLVES (`Peer::Member(id)` != any
        // `Peer::Replica(slot)`): close so it reconnects and binds under its slot. This completes the
        // stranded-laggard rejoin — the laggard's install resolves its donors, and they re-bind normally.
        Some(new_slot) if Peer::Replica(new_slot) != bound_peer => {
          self
            .bridge
            .close_local(std_now, h, crate::transport::CloseCause::Superseded);
        }
        // Slot unchanged: keep the connection bound (no churn for an unmoved retained member).
        Some(_) => {}
      }
    }
    self.last_reconciled_config_id = current;
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

  /// The number of connection closes attributed to `cause` so far — counted once per connection at
  /// the shared teardown tail, whichever side (a local fatal, a peer loss, an idle expiry, a
  /// membership-change retirement) tore it down first. The QUIC analogue of the stream drivers'
  /// per-cause close observability; test/diagnostic surface, not a stable embedder API.
  #[doc(hidden)]
  pub fn conn_close_count(&self, cause: crate::transport::CloseCause) -> u64 {
    self.bridge.conn_close_count(cause)
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
    storage: &mut Storage<W, B, S>,
    request: Request,
  ) {
    if request.body().len() > crate::transport::frame::max_request_body_len() {
      return;
    }
    // A removed local member owns no slot; route nothing (graceful no-op, not a panic).
    let Some(self_id) = self.endpoint.local_slot_opt() else {
      return;
    };
    self.endpoint.handle_message(
      now,
      storage,
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
  fn drain_bridge<W: Wal, B: Superblock>(&mut self, now: Instant, storage: &mut Storage<W, B, S>) {
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
          // is dropped (the consensus layer retransmits); keep draining the rest of the batch. That
          // single drop now covers BOTH a forward-compatible unrecognized message (a newer peer's
          // additive body — `CodecError::UnknownMessage`) and a genuinely malformed frame: QUIC has
          // always been lossy on a validated conn, so unlike the stream transport it needs no
          // skip-vs-terminate split — both simply fall out of this `if let (Some(from), Ok(msg))`.
          if let (Some(from), Ok(msg)) = (
            self.bridge.bound_peer_of(h),
            decode_message(Bytes::from(payload)),
          ) {
            self.deliver_decoded(now, storage, from, msg);
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
          if let (Some(from), Ok(msg)) = (
            self.bridge.bound_peer_of(h),
            decode_message(Bytes::from(payload)),
          ) {
            self.deliver_decoded(now, storage, from, msg);
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
    storage: &mut Storage<W, B, S>,
    from: Peer,
    msg: Message,
  ) {
    if let Message::Request(r) = &msg
      && r.body().len() > crate::transport::frame::max_request_body_len()
    {
      return;
    }
    self.endpoint.handle_message(now, storage, from, msg);
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
        self
          .bridge
          .close_local(std_now, h, crate::transport::CloseCause::IdentityRejected);
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
      self
        .bridge
        .close_local(std_now, h, crate::transport::CloseCause::IdentityRejected);
      return;
    }
    // The attested identity must be a REPLICA's stable `MemberId` (a CLIENT identity uses a separate
    // endpoint, so `as_replica()` is `None` → reject).
    let Some(member_id) = identified.id().as_replica() else {
      self
        .bridge
        .close_local(std_now, h, crate::transport::CloseCause::IdentityRejected);
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
      self
        .bridge
        .close_local(std_now, h, crate::transport::CloseCause::IdentityRejected);
      return;
    }
    // Resolve the attested stable `MemberId` to its routing slot against the ACTIVE membership. `Some`
    // ⇒ the peer is a member of the active configuration; bind it under `Peer::Replica(slot)`. `None` ⇒
    // the member is authenticated but NOT in our active membership (a retained member offline across a
    // rolling replacement, a node removed while offline, a not-yet-added one) — QUARANTINE it: bind
    // under the never-routable `Peer::Member(id)` so it can ride the no-authority config-learning lane
    // (state-sync + the epoch-ahead hint) to rejoin or learn its own retirement, while `as_replica()`
    // being `None` keeps it out of every vote / lead / view / fanout path at the endpoint by
    // construction. In-model misconfiguration, never a Byzantine claim.
    let routing_peer = match self.endpoint.slot_of(member_id) {
      Some(slot) => {
        let resolved = Peer::Replica(slot);
        match self.bridge.dialed_expectation_of(h) {
          // Dialed: the resolved routing peer must be exactly the peer we meant to reach.
          Some(expected) if resolved != expected => {
            self
              .bridge
              .close_local(std_now, h, crate::transport::CloseCause::IdentityRejected);
            return;
          }
          // Dialed-and-matched, or accepted (adopt): fall through to bind.
          _ => {}
        }
        resolved
      }
      None => {
        // We DIAL only members we expect to resolve; a dialed conn whose expectation no longer
        // resolves is a stale target — reject rather than quarantine (quarantine is for ACCEPTED
        // inbound from a member that cannot yet resolve us).
        if self.bridge.dialed_expectation_of(h).is_some() {
          self
            .bridge
            .close_local(std_now, h, crate::transport::CloseCause::IdentityRejected);
          return;
        }
        // Cap the quarantined population (newest-wins): a misconfigured fleet of valid-cert but
        // unresolvable ids must not fill the connection table. The id space is already bounded by
        // issued cluster certs; this bounds the LIVE quarantined-conn count as defense-in-depth.
        self.evict_quarantined_if_full(std_now);
        Peer::Member(member_id)
      }
    };
    self.bridge.bind_validated(std_now, h, routing_peer);
    // Record the attested STABLE member id alongside the bind. For a `Peer::Replica` the slot is the
    // routing key and the id is the cross-config invariant `reconcile_routing` re-resolves after a
    // membership shift; for a quarantined `Peer::Member` the id IS the routing key, and the reconcile
    // re-resolves it on every install (now-`Some` ⇒ close so it re-handshakes into its slot). Set only
    // after a successful bind.
    self.bridge.set_attested_member(h, member_id);
  }

  /// The maximum live QUARANTINED (`Peer::Member`) connections — attested members our active
  /// membership does not resolve, riding the no-authority learn lane. Sized generously above the
  /// legitimate transient population (a member offline across a rolling replacement; a node awaiting
  /// its own retirement) while bounding a misconfigured fleet's footprint on the connection table.
  const QUARANTINE_CONN_LIMIT: usize = 8;

  /// Close the oldest quarantined connection if the quarantined population is already at
  /// [`Self::QUARANTINE_CONN_LIMIT`], making room for a fresh quarantine bind (newest-wins). A no-op
  /// below the cap. Quarantined conns carry only the no-authority learn lane, so evicting one at most
  /// delays that member's rejoin until it re-dials — never a safety or a live-config consequence.
  fn evict_quarantined_if_full(&mut self, std_now: std::time::Instant) {
    let quarantined: Vec<ConnectionHandle> = self
      .bridge
      .validated_member_conns()
      .into_iter()
      .filter(|(_, _, bound_peer)| bound_peer.is_member())
      .map(|(h, _, _)| h)
      .collect();
    if quarantined.len() < Self::QUARANTINE_CONN_LIMIT {
      return;
    }
    // The table enumerates in `HashMap` order (nondeterministic), so pick the victim explicitly:
    // the lowest connection handle is a deterministic, oldest-biased choice (quinn allocates handles
    // monotonically). Any victim is correct — every quarantined conn is an equivalent no-authority
    // learn lane — but a deterministic one keeps behavior reproducible.
    if let Some(victim) = quarantined.into_iter().min() {
      self
        .bridge
        .close_local(std_now, victim, crate::transport::CloseCause::Superseded);
    }
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
    let std_now = self.quinn_now(now);
    // A removed local member owns no slot; route nothing, but still service the bridge below.
    if let Some(self_id) = self.endpoint.local_slot_opt() {
      for o in outgoing {
        self.route(std_now, o.to(), o.msg_ref(), self_id);
      }
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
    storage: &mut Storage<W, B, S>,
    from: Peer,
    msg: Message,
  ) {
    self.deliver_decoded(now, storage, from, msg);
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
    storage: &mut Storage<W, B, S>,
  ) {
    self.drain_bridge(now, storage);
    self.pump(now);
  }

  /// The number of live entries in the bridge's connection table (test observable for the dial-cap
  /// boundary test and the membership-range loopback: a rejected candidate must not pin a slot).
  /// STREAM frames the connection bound to `peer` has RECEIVED — the receiver-side span count the
  /// sender-segmentation regression measures (see [`Bridge::rx_stream_frames`]).
  #[cfg(test)]
  pub(crate) fn rx_stream_frames_for_test(&mut self) -> u64 {
    self.bridge.rx_stream_frames_total()
  }

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

  /// Every stable [`MemberId`](crate::MemberId) currently bound under a QUARANTINED (`Peer::Member`)
  /// connection — an authenticated member the active membership does not resolve, riding the
  /// no-authority learn lane. The membership-range loopback test reads it to assert an accepted
  /// out-of-membership member is QUARANTINED (present here, absent from the replica fanout) rather
  /// than either bound as a replica or rejected.
  #[cfg(test)]
  pub(crate) fn quarantined_members_for_test(&self) -> Vec<crate::MemberId> {
    self
      .bridge
      .validated_member_conns()
      .into_iter()
      .filter(|(_, _, bound_peer)| bound_peer.is_member())
      .map(|(_, member, _)| member)
      .collect()
  }

  /// The effective live-connection cap the bridge enforces. The mutual-dial-mesh sizing test reads it
  /// to assert the cap derived from `replica_count` covers `2*(replica_count - 1)` plus headroom.
  #[cfg(test)]
  pub(crate) fn max_connections_for_test(&self) -> usize {
    self.bridge.max_connections()
  }
}

#[cfg(test)]
mod tests;
