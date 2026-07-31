use std::cell::Cell;

use super::{ShutdownReport, StorageQuiescence, drain_storage};

/// Run a future to completion by polling it directly. Every future built here resolves without ever
/// parking (its `sleep` is `ready(())`), so no waker is ever needed; the bound only stops a broken
/// loop from hanging the test.
fn run<F: Future>(fut: F) -> F::Output {
  let mut fut = std::pin::pin!(fut);
  let mut cx = std::task::Context::from_waker(futures_util::task::noop_waker_ref());
  for _ in 0..1_000 {
    if let std::task::Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
      return out;
    }
  }
  panic!("the drain did not resolve");
}

/// The report is the shutdown's carrier of facts, and `storage_quiesced` reads exactly one of them:
/// it is `true` only for [`StorageQuiescence::Quiesced`], and expiry reports honestly rather than
/// being smoothed into success.
#[test]
fn the_report_reads_back_the_quiescence_it_was_built_with() {
  assert!(ShutdownReport::new(StorageQuiescence::Quiesced).storage_quiesced());
  assert!(!ShutdownReport::new(StorageQuiescence::DeadlineExpired).storage_quiesced());
}

/// An already-quiet store costs ONE pass and no wait: the drain pumps BEFORE it consults the
/// deadline or sleeps, so the common case (nothing in flight when the shutdown lands) adds no
/// latency to teardown.
#[test]
fn an_already_quiet_store_drains_in_one_pass_without_sleeping() {
  let pumps = Cell::new(0usize);
  let sleeps = Cell::new(0usize);
  let outcome = run(drain_storage(
    || {
      pumps.set(pumps.get() + 1);
      true
    },
    |_| {
      sleeps.set(sleeps.get() + 1);
      std::future::ready(())
    },
  ));
  assert_eq!(outcome, StorageQuiescence::Quiesced);
  assert_eq!(pumps.get(), 1, "one pass suffices for a quiet store");
  assert_eq!(sleeps.get(), 0, "and it never waits");
}

/// The drain keeps pumping until the ENDPOINT says it is quiet, not until some count of ops it
/// started with is exhausted — a pass can itself submit further durability work. Each pass that
/// finds work still in flight is followed by exactly one wait.
#[test]
fn the_drain_pumps_until_the_endpoint_reports_quiescence() {
  const PASSES_STILL_IN_FLIGHT: usize = 5;
  let pumps = Cell::new(0usize);
  let sleeps = Cell::new(0usize);
  let outcome = run(drain_storage(
    || {
      pumps.set(pumps.get() + 1);
      pumps.get() > PASSES_STILL_IN_FLIGHT
    },
    |_| {
      sleeps.set(sleeps.get() + 1);
      std::future::ready(())
    },
  ));
  assert_eq!(outcome, StorageQuiescence::Quiesced);
  assert_eq!(
    pumps.get(),
    PASSES_STILL_IN_FLIGHT + 1,
    "it pumps until the in-flight signal clears, not a fixed number of times"
  );
  assert_eq!(
    sleeps.get(),
    PASSES_STILL_IN_FLIGHT,
    "one wait per pass that found work still in flight, and none after the clearing pass"
  );
}
