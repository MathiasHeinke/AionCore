pub mod acp;
pub mod aionrs;
pub(crate) mod process_registry;

/// Drain the fail-closed owner for process trees whose durable registry and
/// emergency evidence could not initially be written.
pub async fn drain_unpersisted_process_supervisors() {
    process_registry::drain_unpersisted_process_supervisors().await;
}
