use super::*;

fn cfg(auto_units: u64) -> BatchingConfig {
  BatchingConfig {
    seed: 7,
    client: 1,
    max_rate: 2,
    group_denom: 5,
    max_unit_len: 16,
    auto_units,
  }
}

#[test]
fn packing_is_fifo_and_respects_the_byte_budget() {
  let mut b = BatchingClient::new(cfg(0));
  // Three units whose encoded sizes force a byte-budget split: each costs 4 + 400, the body
  // budget is 1024, so two fit (4 + 808 = 812) and the third (1216) defers.
  for tag in [1u8, 2, 3] {
    b.enqueue_unit(Bytes::from(vec![tag; 400]));
  }
  let body1 = b.pack(1).expect("queued units pack");
  let view = viewstamp_proto::BatchView::parse(&body1).expect("codec-built");
  assert_eq!(
    view.len(),
    2,
    "two 400-byte units fill the 1024-byte budget"
  );
  assert_eq!(view.unit(0).map(|u| u[0]), Some(1), "FIFO order");
  assert_eq!(view.unit(1).map(|u| u[0]), Some(2));
  let body2 = b.pack(2).expect("the deferred unit leads the next body");
  let view = viewstamp_proto::BatchView::parse(&body2).expect("codec-built");
  assert_eq!(view.len(), 1);
  assert_eq!(view.unit(0).map(|u| u[0]), Some(3));
  assert!(b.pack(3).is_none(), "an empty queue packs nothing");
  assert_eq!(b.bodies_with_multiple_units(), 1);
  assert_eq!(b.max_units_per_body(), 2);
}

#[test]
fn packing_respects_the_reply_side_unit_cap() {
  let mut b = BatchingClient::new(cfg(0));
  // Tiny units: the byte budget would admit ~200, but the reply-side cap binds first.
  for _ in 0..sim_max_units_per_body() + 3 {
    b.enqueue_unit(Bytes::from_static(b"u"));
  }
  let body = b.pack(1).expect("packs");
  let view = viewstamp_proto::BatchView::parse(&body).expect("codec-built");
  assert_eq!(
    view.len(),
    sim_max_units_per_body(),
    "the ceiling-priced reply budget caps the unit count"
  );
  let rest = b.pack(2).expect("the excess leads the next body");
  assert_eq!(
    viewstamp_proto::BatchView::parse(&rest)
      .expect("codec-built")
      .len(),
    3
  );
}

#[test]
fn a_group_packs_whole_or_defers_whole() {
  let mut b = BatchingClient::new(cfg(0));
  b.enqueue_unit(Bytes::from(vec![1u8; 700]));
  // The group needs 2 * (4 + 200) = 408 more bytes; 4 + 704 + 408 > 1024, so it defers whole.
  b.enqueue_group(vec![
    Bytes::from(vec![2u8; 200]),
    Bytes::from(vec![3u8; 200]),
  ]);
  let body1 = b.pack(1).expect("packs the lone unit");
  assert_eq!(
    viewstamp_proto::BatchView::parse(&body1)
      .expect("codec-built")
      .len(),
    1,
    "the body ships without the group"
  );
  let body2 = b.pack(2).expect("the group leads the next body");
  let view = viewstamp_proto::BatchView::parse(&body2).expect("codec-built");
  assert_eq!(view.len(), 2, "the group rides one body, whole");
  assert_eq!(b.groups_submitted(), 1);
  let groups: Vec<Option<u64>> = b.bodies()[1].units().iter().map(|u| u.group()).collect();
  assert_eq!(groups, vec![Some(0), Some(0)], "adjacent group bookkeeping");
}

#[test]
fn on_ack_demuxes_and_records_per_unit_replies() {
  let mut b = BatchingClient::new(cfg(0));
  b.enqueue_unit(Bytes::from_static(b"a"));
  b.enqueue_unit(Bytes::from_static(b"bb"));
  let body = b.pack(1).expect("packs");
  // Apply through the real BatchSm to produce the genuine reply body.
  let mut sm = crate::sm::BatchSm::default();
  let reply =
    viewstamp_proto::StateMachine::apply(&mut sm, viewstamp_proto::OpNumber::with(1), &body);
  b.on_ack(1, &reply);
  assert_eq!(b.units_acked(), 2);
  let units = b.bodies()[0].units();
  assert_eq!(
    units[0].reply().map(|r| r.as_ref()),
    Some(&1u64.to_be_bytes()[..])
  );
  assert_eq!(
    units[1].reply().map(|r| r.as_ref()),
    Some(&2u64.to_be_bytes()[..])
  );
  assert!(b.bodies()[0].acked());
}

#[test]
#[should_panic(expected = "reply unit count diverges")]
fn on_ack_panics_on_a_count_mismatch() {
  let mut b = BatchingClient::new(cfg(0));
  b.enqueue_unit(Bytes::from_static(b"a"));
  b.enqueue_unit(Bytes::from_static(b"bb"));
  b.pack(1).expect("packs");
  // A one-unit reply for a two-unit body.
  let mut reply = BatchBuilder::new(64);
  reply.push(&1u64.to_be_bytes()).expect("fits");
  b.on_ack(1, &reply.finish().expect("non-empty"));
}

#[test]
fn seeded_emission_is_deterministic_and_spends_the_budget() {
  let run = || {
    let mut b = BatchingClient::new(cfg(40));
    for _ in 0..200 {
      b.step_emission();
    }
    let mut shipped: Vec<Vec<u8>> = Vec::new();
    let mut request = 1;
    while let Some(body) = b.pack(request) {
      shipped.push(body.to_vec());
      request += 1;
    }
    (shipped, b.groups_submitted())
  };
  let (a, ga) = run();
  let (b, gb) = run();
  assert_eq!(a, b, "emission + packing is a pure function of the config");
  assert_eq!(ga, gb);
  assert!(!a.is_empty(), "the budget genuinely emitted units");
}

/// One fabricated apply-stream entry: op `op` committed `(client, request)`.
fn committed(op: u64, client: u128, request: u64) -> (u64, AppliedEvent) {
  use viewstamp_proto::{ClientId, Committed, OpNumber, RequestNumber};
  (
    0,
    AppliedEvent::Committed(Committed::new(
      OpNumber::with(op),
      ClientId::new(client),
      RequestNumber::with(request),
      Bytes::new(),
    )),
  )
}

/// One fabricated acked unit with the deterministic reply for global position `count`.
fn acked_unit(bytes: &'static [u8], group: Option<u64>, count: u64) -> SubmittedUnit {
  SubmittedUnit {
    bytes: Bytes::from_static(bytes),
    group,
    reply: Some(Bytes::copy_from_slice(&count.to_be_bytes())),
  }
}

/// One fabricated packed body.
fn body(request: u64, acked: bool, units: Vec<SubmittedUnit>) -> SubmittedBody {
  SubmittedBody {
    request,
    units,
    acked,
  }
}

#[test]
fn oracle_passes_a_consistent_fabrication() {
  let events = vec![committed(1, 7, 1)];
  let history: Vec<(u64, u32, Bytes)> = vec![
    (1, 0, Bytes::from_static(b"a")),
    (1, 1, Bytes::from_static(b"bb")),
  ];
  let bodies = vec![body(
    1,
    true,
    vec![acked_unit(b"a", None, 1), acked_unit(b"bb", None, 2)],
  )];
  assert!(check_units(&[&events], &[&history], &[(7, &bodies)]).is_ok());
}

#[test]
fn oracle_flags_an_acked_body_never_applied() {
  // No replica's apply stream carries (client 7, request 1): the ack references a lost op.
  let bodies = vec![body(1, true, vec![acked_unit(b"a", None, 1)])];
  assert!(
    check_units(&[&[]], &[&[]], &[(7, &bodies)]).is_violation(),
    "an acked-but-never-applied batched request must be flagged"
  );
}

#[test]
fn oracle_flags_an_op_with_no_unit_history() {
  // The request committed but no replica's unit history holds its op: the units vanished.
  let events = vec![committed(1, 7, 1)];
  let bodies = vec![body(1, true, vec![acked_unit(b"a", None, 1)])];
  assert!(
    check_units(&[&events], &[&[]], &[(7, &bodies)]).is_violation(),
    "an acked op missing from every unit history must be flagged"
  );
}

#[test]
fn oracle_flags_rewritten_unit_bytes() {
  let events = vec![committed(1, 7, 1)];
  let history: Vec<(u64, u32, Bytes)> = vec![(1, 0, Bytes::from_static(b"X"))];
  let bodies = vec![body(1, true, vec![acked_unit(b"a", None, 1)])];
  assert!(
    check_units(&[&events], &[&history], &[(7, &bodies)]).is_violation(),
    "recorded unit bytes diverging from the submitted bytes must be flagged"
  );
}

#[test]
fn oracle_flags_a_divergent_per_unit_reply() {
  let events = vec![committed(1, 7, 1)];
  let history: Vec<(u64, u32, Bytes)> = vec![(1, 0, Bytes::from_static(b"a"))];
  // The history position is 0, so the deterministic reply is 1 — an acked 5 diverges.
  let bodies = vec![body(1, true, vec![acked_unit(b"a", None, 5)])];
  assert!(
    check_units(&[&events], &[&history], &[(7, &bodies)]).is_violation(),
    "an acked reply diverging from the SM's deterministic per-unit reply must be flagged"
  );
}

#[test]
fn oracle_flags_a_missing_or_extra_unit_at_the_op() {
  let events = vec![committed(1, 7, 1)];
  // Missing: the body acked two units but the op's history holds one.
  let short: Vec<(u64, u32, Bytes)> = vec![(1, 0, Bytes::from_static(b"a"))];
  let two = vec![body(
    1,
    true,
    vec![acked_unit(b"a", None, 1), acked_unit(b"bb", None, 2)],
  )];
  assert!(
    check_units(&[&events], &[&short], &[(7, &two)]).is_violation(),
    "a unit missing from the op's history must be flagged"
  );
  // Extra: the op's history holds three units but the body submitted two.
  let long: Vec<(u64, u32, Bytes)> = vec![
    (1, 0, Bytes::from_static(b"a")),
    (1, 1, Bytes::from_static(b"bb")),
    (1, 2, Bytes::from_static(b"ghost")),
  ];
  assert!(
    check_units(&[&events], &[&long], &[(7, &two)]).is_violation(),
    "an op recording more units than were submitted must be flagged"
  );
}

#[test]
fn oracle_flags_a_request_committed_at_two_ops() {
  let events = vec![committed(1, 7, 1), committed(2, 7, 1)];
  let history: Vec<(u64, u32, Bytes)> = vec![(1, 0, Bytes::from_static(b"a"))];
  let bodies = vec![body(1, true, vec![acked_unit(b"a", None, 1)])];
  assert!(
    check_units(&[&events], &[&history], &[(7, &bodies)]).is_violation(),
    "a request applied at two ops must be flagged"
  );
}

#[test]
fn oracle_flags_a_duplicated_unit_in_a_history() {
  let events = vec![committed(1, 7, 1)];
  let history: Vec<(u64, u32, Bytes)> = vec![
    (1, 0, Bytes::from_static(b"a")),
    (1, 0, Bytes::from_static(b"a")),
  ];
  let bodies = vec![body(1, true, vec![acked_unit(b"a", None, 1)])];
  assert!(
    check_units(&[&events], &[&history], &[(7, &bodies)]).is_violation(),
    "a unit applied twice within one history must be flagged"
  );
}

#[test]
fn oracle_flags_a_group_split_within_a_body() {
  // Group 0's units sit at indices 0 and 2 with a lone unit between them: non-adjacent.
  let events = vec![committed(1, 7, 1)];
  let history: Vec<(u64, u32, Bytes)> = vec![
    (1, 0, Bytes::from_static(b"g")),
    (1, 1, Bytes::from_static(b"x")),
    (1, 2, Bytes::from_static(b"g")),
  ];
  let bodies = vec![body(
    1,
    true,
    vec![
      acked_unit(b"g", Some(0), 1),
      acked_unit(b"x", None, 2),
      acked_unit(b"g", Some(0), 3),
    ],
  )];
  assert!(
    check_units(&[&events], &[&history], &[(7, &bodies)]).is_violation(),
    "a group on non-adjacent indices must be flagged"
  );
}

#[test]
fn oracle_flags_a_group_split_across_bodies() {
  // Group 0 has one unit in request 1 and another in request 2: the atomic group was split.
  // Packing-level integrity is judged on unacked bodies too, so no events/history are needed.
  let bodies = vec![
    body(1, false, vec![acked_unit(b"g1", Some(0), 1)]),
    body(2, false, vec![acked_unit(b"g2", Some(0), 2)]),
  ];
  assert!(
    check_units(&[&[]], &[&[]], &[(7, &bodies)]).is_violation(),
    "a group riding two bodies must be flagged"
  );
}
