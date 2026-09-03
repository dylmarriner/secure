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
