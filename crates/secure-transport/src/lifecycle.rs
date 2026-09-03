//! Pure, network-free transport state machine.
//!
//! This mirrors how `secure_core::AppLifecycle` separates lifecycle bookkeeping from I/O: the
//! state machine here has no dependency on Tor, Arti, or any network type, so its invariants
//! (strict mode refuses connections before readiness, failure is a real state rather than a
//! transient error, shutdown is terminal) can be tested directly without needing a live Tor
//! bootstrap - which this environment cannot exercise. [`TorTransport`](crate::TorTransport)
//! wraps this with the real Arti calls.

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportState {
    /// No bootstrap attempt has been made yet.
    NotStarted,
    /// A bootstrap attempt is in progress.
    Bootstrapping,
    /// Bootstrap succeeded; connections may be established.
    Ready,
    /// The most recent bootstrap attempt failed. A new `Start` may be applied to retry.
    Failed,
    /// Shut down. Terminal - a new transport must be constructed to use Tor again.
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportEvent {
    Start,
    BootstrapSucceeded,
    BootstrapFailed,
    Stop,
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error("invalid transport transition from {state:?} using {event:?}")]
pub struct TransportLifecycleError {
    pub state: TransportState,
    pub event: TransportEvent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportLifecycle(TransportState);

impl Default for TransportLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl TransportLifecycle {
    #[must_use]
    pub const fn new() -> Self {
        Self(TransportState::NotStarted)
    }

    #[must_use]
    pub const fn state(&self) -> TransportState {
        self.0
    }

    /// Whether it is currently safe to establish a new connection through this transport.
    ///
    /// This is the single enforcement point behind "strict mode refuses messaging before Tor
    /// readiness" and "no clearnet fallback": every connection attempt must check this (or go
    /// through [`TorTransport::connect`](crate::TorTransport::connect), which does) before any
    /// network I/O happens. There is deliberately no other way to open a connection through
    /// this crate.
    #[must_use]
    pub const fn can_connect(&self) -> bool {
        matches!(self.0, TransportState::Ready)
    }

    pub fn apply(&mut self, event: TransportEvent) -> Result<(), TransportLifecycleError> {
        use TransportEvent as E;
        use TransportState as S;

        let next = match (self.0, event) {
            (S::NotStarted, E::Start) => S::Bootstrapping,
            (S::Failed, E::Start) => S::Bootstrapping,
            (S::Bootstrapping, E::BootstrapSucceeded) => S::Ready,
            (S::Bootstrapping, E::BootstrapFailed) => S::Failed,
            (S::NotStarted | S::Bootstrapping | S::Ready | S::Failed, E::Stop) => S::Stopped,
            (state, event) => return Err(TransportLifecycleError { state, event }),
        };

        self.0 = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_not_started_and_refuses_connections() {
        let lifecycle = TransportLifecycle::new();
        assert_eq!(lifecycle.state(), TransportState::NotStarted);
        assert!(!lifecycle.can_connect());
    }

    #[test]
    fn happy_path_reaches_ready_and_allows_connections() {
        let mut lifecycle = TransportLifecycle::new();
        lifecycle.apply(TransportEvent::Start).expect("start");
        assert_eq!(lifecycle.state(), TransportState::Bootstrapping);
        assert!(!lifecycle.can_connect(), "must not connect mid-bootstrap");

        lifecycle
            .apply(TransportEvent::BootstrapSucceeded)
            .expect("bootstrap succeeded");
        assert_eq!(lifecycle.state(), TransportState::Ready);
        assert!(lifecycle.can_connect());
    }

    #[test]
    fn failed_bootstrap_refuses_connections_but_allows_retry() {
        let mut lifecycle = TransportLifecycle::new();
        lifecycle.apply(TransportEvent::Start).expect("start");
        lifecycle
            .apply(TransportEvent::BootstrapFailed)
            .expect("bootstrap failed");
        assert_eq!(lifecycle.state(), TransportState::Failed);
        assert!(!lifecycle.can_connect());

        lifecycle.apply(TransportEvent::Start).expect("retry");
        assert_eq!(lifecycle.state(), TransportState::Bootstrapping);
    }

    #[test]
    fn stop_is_reachable_from_every_non_terminal_state_and_refuses_connections() {
        for build in [
            (|| TransportLifecycle::new()) as fn() -> TransportLifecycle,
            || {
                let mut l = TransportLifecycle::new();
                l.apply(TransportEvent::Start).unwrap();
                l
            },
            || {
                let mut l = TransportLifecycle::new();
                l.apply(TransportEvent::Start).unwrap();
                l.apply(TransportEvent::BootstrapSucceeded).unwrap();
                l
            },
            || {
                let mut l = TransportLifecycle::new();
                l.apply(TransportEvent::Start).unwrap();
                l.apply(TransportEvent::BootstrapFailed).unwrap();
                l
            },
        ] {
            let mut lifecycle = build();
            lifecycle.apply(TransportEvent::Stop).expect("stop");
            assert_eq!(lifecycle.state(), TransportState::Stopped);
            assert!(!lifecycle.can_connect());
        }
    }

    #[test]
    fn stopped_is_terminal() {
        let mut lifecycle = TransportLifecycle::new();
        lifecycle.apply(TransportEvent::Stop).expect("stop");

        for event in [
            TransportEvent::Start,
            TransportEvent::BootstrapSucceeded,
            TransportEvent::BootstrapFailed,
            TransportEvent::Stop,
        ] {
            let error = lifecycle
                .apply(event)
                .expect_err("no event may leave Stopped");
            assert_eq!(error.state, TransportState::Stopped);
        }
    }

    #[test]
    fn ready_cannot_be_entered_without_bootstrapping_first() {
        let mut lifecycle = TransportLifecycle::new();
        let error = lifecycle
            .apply(TransportEvent::BootstrapSucceeded)
            .expect_err("cannot succeed a bootstrap that never started");
        assert_eq!(error.state, TransportState::NotStarted);
    }

    #[test]
    fn cannot_connect_in_any_state_other_than_ready() {
        for state in [
            TransportState::NotStarted,
            TransportState::Bootstrapping,
            TransportState::Failed,
            TransportState::Stopped,
        ] {
            assert!(!TransportLifecycle(state).can_connect());
        }
        assert!(TransportLifecycle(TransportState::Ready).can_connect());
    }
}
