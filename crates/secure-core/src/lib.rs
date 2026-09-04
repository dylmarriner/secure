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

impl DestructionStage {
    /// Position of this stage in the destruction sequence. Exists so a caller persisting stage
    /// progress across a crash can prove a resumed burn only ever moves *forward*: a recorded
    /// stage may be advanced, never lowered. The numbers themselves are not a persistence
    /// format - a caller that writes stages to disk owns its own versioned encoding, the same
    /// way `secure_storage::burn::BurnStage` owns its own database strings.
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::Armed => 0,
            Self::UiSealed => 1,
            Self::NetworkStopped => 2,
            Self::RuntimeSecretsRevoked => 3,
            Self::PersistentKeyAccessDestroyed => 4,
            Self::Complete => 5,
        }
    }

    /// The event that advances *out of* this stage, or `None` once terminal. Lets a resuming
    /// caller drive the remaining sequence without hard-coding which events it already applied
    /// before the crash.
    #[must_use]
    pub const fn advancing_event(self) -> Option<DestructionEvent> {
        match self {
            Self::Armed => Some(DestructionEvent::UiSealed),
            Self::UiSealed => Some(DestructionEvent::NetworkStopped),
            Self::NetworkStopped => Some(DestructionEvent::RuntimeSecretsRevoked),
            Self::RuntimeSecretsRevoked => Some(DestructionEvent::PersistentKeyAccessDestroyed),
            Self::PersistentKeyAccessDestroyed => Some(DestructionEvent::DataCleanupFinished),
            Self::Complete => None,
        }
    }
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

    /// Reconstruct a lifecycle that is part-way through an identity burn, from a stage a caller
    /// recovered from durable storage after a crash or forced termination.
    ///
    /// This is the counterpart to persisting destruction progress: [`Self::new`] can only ever
    /// re-enter a burn at [`DestructionStage::Armed`], which would mean a restart silently
    /// restarts the sequence from the beginning and loses the record of how far it had actually
    /// got. Callers that persist their stage use this instead so a resumed burn continues
    /// forward from exactly where it stopped.
    ///
    /// A recovered [`DestructionStage::Complete`] yields the terminal [`AppState::Destroyed`],
    /// not a `Destroying` state that could accept further destruction events - the same
    /// end-state [`Self::apply_destruction`] reaches when it completes the sequence live.
    #[must_use]
    pub const fn resuming_destruction(stage: DestructionStage) -> Self {
        let state = if matches!(stage, DestructionStage::Complete) {
            AppState::Destroyed
        } else {
            AppState::Destroying
        };

        Self {
            state,
            destruction_stage: Some(stage),
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
