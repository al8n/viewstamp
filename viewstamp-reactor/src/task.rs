use agnostic_lite::{AsyncSpawner, JoinHandle, RuntimeLite};

/// A spawned task handle whose drop ABORTS the task — on every runtime.
///
/// The runtimes behind [`RuntimeLite`] do not agree on what dropping a raw spawn handle means:
/// tokio's handle detaches (the task keeps running, now unsupervised), while smol's wrapper
/// cancels on drop. Driver state holding raw handles would therefore leak live tasks on one
/// runtime exactly where it tears them down on the other — and a test suite green on either
/// runtime could mask the opposite behavior on the other. This wrapper normalizes through the
/// trait's consuming [`JoinHandle::abort`] (tokio: a real abort; smol: the cancel-on-drop), so
/// dropping the OWNER of a task — a connection unit, a dial in flight — is the task's teardown as
/// a structural invariant, not a per-runtime accident.
///
/// This is the ONLY handle type driver state may hold: every `R::spawn` is wrapped at the spawn
/// site, and a task meant to outlive its spawner uses `R::spawn_detach` explicitly instead.
pub(crate) struct AbortOnDrop<R: RuntimeLite>(Option<<R::Spawner as AsyncSpawner>::JoinHandle<()>>);

impl<R: RuntimeLite> AbortOnDrop<R> {
  /// Wrap the handle returned by `R::spawn` for a `()`-output task.
  pub(crate) fn new(handle: <R::Spawner as AsyncSpawner>::JoinHandle<()>) -> Self {
    Self(Some(handle))
  }
}

impl<R: RuntimeLite> Drop for AbortOnDrop<R> {
  fn drop(&mut self) {
    if let Some(handle) = self.0.take() {
      handle.abort();
    }
  }
}
