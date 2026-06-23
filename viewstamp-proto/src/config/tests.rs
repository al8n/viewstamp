use super::*;

#[test]
fn checkpoint_ops_is_validated_and_accessible() {
  let c = Config::try_new(0, MemberId::new(0)).unwrap();
  assert_eq!(c.checkpoint_ops(), DEFAULT_CHECKPOINT_OPS); // default interval
  let c2 = Config::with_checkpoint_ops(0, MemberId::new(0), 8).unwrap();
  assert_eq!(c2.checkpoint_ops(), 8);
  // zero interval is rejected (a checkpoint every 0 ops is meaningless / would loop)
  assert_eq!(
    Config::with_checkpoint_ops(0, MemberId::new(0), 0),
    Err(ConfigError::ZeroCheckpointOps)
  );
  // an interval beyond the pipeline-headroom cap is rejected
  assert_eq!(
    Config::with_checkpoint_ops(0, MemberId::new(0), MAX_CHECKPOINT_OPS + 1),
    Err(ConfigError::CheckpointOpsTooLarge {
      ops: MAX_CHECKPOINT_OPS + 1
    })
  );
}

#[test]
fn cluster_and_local_are_accessible() {
  let c = Config::try_new(42, MemberId::new(7)).unwrap();
  assert_eq!(c.cluster(), 42);
  assert_eq!(c.local(), MemberId::new(7));
  // forfeit lag is one checkpoint interval (the default here)
  assert_eq!(c.forfeit_checkpoint_lag(), DEFAULT_CHECKPOINT_OPS);
}

#[test]
fn max_client_sessions_is_validated_and_accessible() {
  let c = Config::try_new(0, MemberId::new(0)).unwrap();
  assert_eq!(c.max_client_sessions(), MAX_CLIENT_SESSIONS); // the default cap
  let c2 = c.with_max_client_sessions(8).unwrap();
  assert_eq!(c2.max_client_sessions(), 8);
  // the other fields are preserved by the chainable setter
  assert_eq!(c2.local(), MemberId::new(0));
  assert_eq!(c2.checkpoint_ops(), c.checkpoint_ops());
  // a zero cap is rejected (it would evict every session at first apply)
  assert_eq!(
    c.with_max_client_sessions(0),
    Err(ConfigError::ZeroMaxClientSessions)
  );
}

#[test]
fn max_sync_envelope_len_is_validated_and_accessible() {
  let c = Config::try_new(0, MemberId::new(0)).unwrap();
  assert_eq!(c.max_sync_envelope_len(), MAX_SYNC_ENVELOPE_LEN); // the default cap
  let c2 = c.with_max_sync_envelope_len(1 << 20).unwrap();
  assert_eq!(c2.max_sync_envelope_len(), 1 << 20);
  // the other fields are preserved by the chainable setter
  assert_eq!(c2.local(), MemberId::new(0));
  assert_eq!(c2.max_client_sessions(), c.max_client_sessions());
  // a zero cap is rejected (it would refuse every chunked transfer)
  assert_eq!(
    c.with_max_sync_envelope_len(0),
    Err(ConfigError::ZeroMaxSyncEnvelopeLen)
  );
}

#[test]
fn with_checkpoint_interval_chains_onto_the_default() {
  // A config built via `try_new` (the default interval) takes a non-default interval via the
  // chainable setter, preserving the other static params.
  let c = Config::try_new(7, MemberId::new(5))
    .unwrap()
    .with_checkpoint_interval(16)
    .unwrap();
  assert_eq!(c.checkpoint_ops(), 16);
  assert_eq!(c.cluster(), 7);
  assert_eq!(c.local(), MemberId::new(5));
  assert_eq!(
    Config::try_new(7, MemberId::new(5))
      .unwrap()
      .checkpoint_ops(),
    DEFAULT_CHECKPOINT_OPS
  ); // without the setter it is the default
  assert!(c.with_checkpoint_interval(0).is_err()); // zero rejected
  assert!(
    c.with_checkpoint_interval(MAX_CHECKPOINT_OPS + 1).is_err() // beyond the cap rejected
  );
}
