use super::Vopr;

// The causal stale-read witness fires ONLY on an observed probe-induced failover, never on a bare
// cut and never after a heal-before-failover — so the lane's non-vacuity cannot be satisfied
// without exercising a completed deposed-primary failover window.
#[test]
fn resolve_stale_probe_distinguishes_failover_from_heal() {
  // No probe in flight: nothing to resolve.
  assert_eq!(Vopr::resolve_stale_probe(None, false, None), (None, false));

  // A DIFFERENT serving primary in a strictly higher view while the target is still cut: the
  // probe-induced failover — the witness fires and the probe resolves.
  assert_eq!(
    Vopr::resolve_stale_probe(Some((0, 0)), true, Some((1, 1))),
    (None, true),
    "a higher-view serving primary while the target is cut is the failover witness"
  );

  // The regression: a heal BEFORE any failover (target no longer cut, no higher-view primary yet)
  // abandons the probe WITHOUT a witness — a cut undone before it forced a view change must not
  // count.
  assert_eq!(
    Vopr::resolve_stale_probe(Some((0, 0)), false, None),
    (None, false),
    "a heal before any failover abandons the probe with no witness"
  );

  // Still pending: the target is cut, but no higher-view serving primary has emerged yet (election
  // ongoing, or only the same/lower view present).
  assert_eq!(
    Vopr::resolve_stale_probe(Some((0, 0)), true, None),
    (Some((0, 0)), false),
    "an election window leaves the probe pending"
  );
  assert_eq!(
    Vopr::resolve_stale_probe(Some((0, 5)), true, Some((1, 5))),
    (Some((0, 5)), false),
    "a same-view primary is not the awaited higher-view failover"
  );

  // A target HEALED before the failover never counts, even if a higher-view serving primary now
  // exists — the cut was undone before it could cause the view change, so attributing the
  // failover to the probe would be non-causal (the calm-window-heal path the witness must
  // exclude).
  assert_eq!(
    Vopr::resolve_stale_probe(Some((0, 0)), false, Some((1, 2))),
    (None, false),
    "a higher-view primary after the cut was healed is not a probe-caused failover"
  );
}
