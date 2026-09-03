//! Application lifecycle and destruction-state invariants for Secure.

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppState {
    Starting,
    Onboarding,
    Locked,
    Unlocked,
    Ghost,
    Destroying,
    Destroyed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppEvent {
    NeedsOnboarding,
    ExistingVault,
    OnboardingComplete,
    UnlockSucceeded,
    Lock,
    StartGhost,
    EndGhost,
    BeginIdentityBurn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestructionStage {
    Armed,
    UiSealed,
    NetworkStopped,
    RuntimeSecretsRevoked,
    PersistentKeyAccessDestroyed,
    Complete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestructionEvent {
    UiSealed,
    NetworkStopped,
    RuntimeSecretsRevoked,
    PersistentKeyAccessDestroyed,
    DataCleanupFinished,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LifecycleError {
    #[error("invalid application transition from {state:?} using {event:?}")]
    InvalidTransition { state: AppState, event: AppEvent },
    #[error("destruction event {event:?} received while application is not destroying")]
    DestructionNotActive { event: DestructionEvent },
    #[error("destroying application state is missing its destruction stage")]
    MissingDestructionStage,
    #[error("invalid destruction transition from {stage:?} using {event:?}")]
    InvalidDestructionTransition {
        stage: DestructionStage,
        event: DestructionEvent,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppLifecycle {
    state: AppState,
    destruction_stage: Option<DestructionStage>,
}

impl AppLifecycle {
    #[must_use]
    pub const fn new(state: AppState) -> Self {
        let destruction_stage = if matches!(state, AppState::Destroying) {
            Some(DestructionStage::Armed)
        } else {
            None
        };

        Self {
            state,
            destruction_stage,
        }
    }

    #[must_use]
    pub const fn state(&self) -> AppState {
        self.state
    }

    #[must_use]
    pub const fn destruction_stage(&self) -> Option<DestructionStage> {
        self.destruction_stage
    }

    pub fn apply(&mut self, event: AppEvent) -> Result<(), LifecycleError> {
        let next = match (self.state, event) {
            (AppState::Starting, AppEvent::NeedsOnboarding) => AppState::Onboarding,
            (AppState::Starting, AppEvent::ExistingVault) => AppState::Locked,
            (AppState::Onboarding, AppEvent::OnboardingComplete) => AppState::Locked,
            (AppState::Locked, AppEvent::UnlockSucceeded) => AppState::Unlocked,
            (AppState::Unlocked, AppEvent::Lock) => AppState::Locked,
            (AppState::Locked, AppEvent::StartGhost) => AppState::Ghost,
            (AppState::Ghost, AppEvent::EndGhost) => AppState::Locked,
            (
                AppState::Locked | AppState::Unlocked | AppState::Ghost,
                AppEvent::BeginIdentityBurn,
            ) => {
                self.destruction_stage = Some(DestructionStage::Armed);
                AppState::Destroying
            }
            (state, event) => return Err(LifecycleError::InvalidTransition { state, event }),
        };

        self.state = next;
        Ok(())
    }

    pub fn apply_destruction(&mut self, event: DestructionEvent) -> Result<(), LifecycleError> {
        if self.state != AppState::Destroying {
            return Err(LifecycleError::DestructionNotActive { event });
        }

        let stage = self
            .destruction_stage
            .ok_or(LifecycleError::MissingDestructionStage)?;

        let next = match (stage, event) {
            (DestructionStage::Armed, DestructionEvent::UiSealed) => DestructionStage::UiSealed,
            (DestructionStage::UiSealed, DestructionEvent::NetworkStopped) => {
                DestructionStage::NetworkStopped
            }
            (DestructionStage::NetworkStopped, DestructionEvent::RuntimeSecretsRevoked) => {
                DestructionStage::RuntimeSecretsRevoked
            }
            (
                DestructionStage::RuntimeSecretsRevoked,
                DestructionEvent::PersistentKeyAccessDestroyed,
            ) => DestructionStage::PersistentKeyAccessDestroyed,
            (
                DestructionStage::PersistentKeyAccessDestroyed,
                DestructionEvent::DataCleanupFinished,
            ) => DestructionStage::Complete,
            (stage, event) => {
                return Err(LifecycleError::InvalidDestructionTransition { stage, event });
            }
        };

        self.destruction_stage = Some(next);
        if next == DestructionStage::Complete {
            self.state = AppState::Destroyed;
        }

        Ok(())
    }
}
