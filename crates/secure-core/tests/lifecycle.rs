use secure_core::{AppEvent, AppLifecycle, AppState, DestructionEvent, DestructionStage};

#[test]
fn unlocked_application_can_lock_without_destroying_identity() {
    let mut lifecycle = AppLifecycle::new(AppState::Unlocked);

    lifecycle.apply(AppEvent::Lock).expect("lock transition");

    assert_eq!(lifecycle.state(), AppState::Locked);
}

#[test]
fn destroyed_state_is_terminal() {
    let mut lifecycle = AppLifecycle::new(AppState::Destroyed);

    assert!(lifecycle.apply(AppEvent::UnlockSucceeded).is_err());
    assert_eq!(lifecycle.state(), AppState::Destroyed);
}

#[test]
fn constructing_destroying_state_preserves_destruction_invariant() {
    let mut lifecycle = AppLifecycle::new(AppState::Destroying);

    assert_eq!(lifecycle.destruction_stage(), Some(DestructionStage::Armed));
    lifecycle
        .apply_destruction(DestructionEvent::UiSealed)
        .expect("destroying state must have an active stage");
}

#[test]
fn a_resumed_destruction_continues_forward_from_its_recovered_stage() {
    // Recovering a burn from durable storage must re-enter it where it stopped, not restart the
    // sequence at `Armed` - restarting would mean a caller had no way to distinguish "this burn
    // has not begun" from "this burn is nearly finished", and every recovery would replay the
    // whole sequence.
    let mut lifecycle = AppLifecycle::resuming_destruction(DestructionStage::NetworkStopped);

    assert_eq!(lifecycle.state(), AppState::Destroying);
    assert_eq!(
        lifecycle.destruction_stage(),
        Some(DestructionStage::NetworkStopped)
    );

    // Stages already completed before the crash must not be re-applicable - the sequence is
    // monotonic across a restart, not merely within one process.
    assert!(
        lifecycle
            .apply_destruction(DestructionEvent::UiSealed)
            .is_err()
    );

    lifecycle
        .apply_destruction(DestructionEvent::RuntimeSecretsRevoked)
        .expect("resume forward");
    lifecycle
        .apply_destruction(DestructionEvent::PersistentKeyAccessDestroyed)
        .expect("destroy key access");
    lifecycle
        .apply_destruction(DestructionEvent::DataCleanupFinished)
        .expect("finish cleanup");

    assert_eq!(lifecycle.state(), AppState::Destroyed);
}

#[test]
fn a_recovered_complete_stage_is_already_terminal() {
    // A journal recording `Complete` describes a burn that finished. Reconstructing it must
    // yield the terminal state directly, never a `Destroying` state that would accept further
    // destruction events or report the application as still mid-burn.
    let mut lifecycle = AppLifecycle::resuming_destruction(DestructionStage::Complete);

    assert_eq!(lifecycle.state(), AppState::Destroyed);
    assert!(
        lifecycle
            .apply_destruction(DestructionEvent::DataCleanupFinished)
            .is_err()
    );
    assert!(lifecycle.apply(AppEvent::UnlockSucceeded).is_err());
}

#[test]
fn identity_burn_cannot_clean_data_before_key_access_is_destroyed() {
    let mut lifecycle = AppLifecycle::new(AppState::Unlocked);
    lifecycle
        .apply(AppEvent::BeginIdentityBurn)
        .expect("begin destruction");

    lifecycle
        .apply_destruction(DestructionEvent::UiSealed)
        .expect("seal UI");
    lifecycle
        .apply_destruction(DestructionEvent::NetworkStopped)
        .expect("stop network");
    lifecycle
        .apply_destruction(DestructionEvent::RuntimeSecretsRevoked)
        .expect("revoke runtime secrets");

    assert!(
        lifecycle
            .apply_destruction(DestructionEvent::DataCleanupFinished)
            .is_err()
    );
    assert_eq!(
        lifecycle.destruction_stage(),
        Some(DestructionStage::RuntimeSecretsRevoked)
    );

    lifecycle
        .apply_destruction(DestructionEvent::PersistentKeyAccessDestroyed)
        .expect("destroy persistent key access");
    lifecycle
        .apply_destruction(DestructionEvent::DataCleanupFinished)
        .expect("cleanup only after key destruction");

    assert_eq!(lifecycle.state(), AppState::Destroyed);
}
