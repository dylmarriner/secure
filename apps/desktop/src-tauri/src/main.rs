//! Secure desktop Tauri host.
//!
//! This binary is deliberately the only place in the application allowed to hold the vault
//! master key and an open vault handle. The WebView only ever receives an [`AppStatus`] over
//! IPC; it never receives passphrases back, key material, or a database handle.
//!
//! Runtime state and lifecycle command logic live in [`runtime`]; the functions below are thin
//! IPC adapters over it. The feature-gated messaging commands are also thin adapters; the
//! native core remains behind `secure-messaging`'s production boundary.

mod destruction_journal;
mod messaging;
mod runtime;

use std::fs;

use tauri::{Manager, State};

#[cfg(not(feature = "simplex-native"))]
use runtime::unlock_application_impl;
use runtime::{
    AppRuntime, AppStatus, TorStatus, VaultPaths, app_status_impl, burn_identity_impl,
    complete_onboarding_impl, end_ghost_impl, lock_application_impl, start_ghost_impl,
    start_tor_impl, stop_tor_impl, tor_status_impl,
};
#[cfg(feature = "simplex-native")]
use runtime::{
    accept_invitation_impl, create_invitation_impl, messaging_status_impl, send_text_message_impl,
    start_messaging_impl, stop_messaging_impl, unlock_application_with_messaging,
};

const TOR_STATE_DIR_NAME: &str = "tor/state";
const TOR_CACHE_DIR_NAME: &str = "tor/cache";

#[tauri::command]
fn app_status(runtime: State<'_, AppRuntime>) -> Result<AppStatus, String> {
    app_status_impl(&runtime)
}

#[tauri::command]
fn tor_status(runtime: State<'_, AppRuntime>) -> TorStatus {
    tor_status_impl(&runtime)
}

#[tauri::command]
async fn start_tor(runtime: State<'_, AppRuntime>) -> Result<TorStatus, String> {
    start_tor_impl(&runtime).await
}

#[cfg(not(feature = "simplex-native"))]
#[tauri::command]
fn stop_tor(runtime: State<'_, AppRuntime>) -> Result<TorStatus, String> {
    stop_tor_impl(&runtime)
}

#[cfg(feature = "simplex-native")]
#[tauri::command]
async fn stop_tor(runtime: State<'_, AppRuntime>) -> Result<TorStatus, String> {
    if messaging_status_impl(&runtime).state == "ready" {
        stop_messaging_impl(&runtime).await;
    }
    stop_tor_impl(&runtime)
}

#[cfg(feature = "simplex-native")]
#[tauri::command]
async fn start_messaging(
    runtime: State<'_, AppRuntime>,
) -> Result<runtime::MessagingStatus, String> {
    start_messaging_impl(&runtime).await
}

#[cfg(feature = "simplex-native")]
#[tauri::command]
fn messaging_status(runtime: State<'_, AppRuntime>) -> runtime::MessagingStatus {
    messaging_status_impl(&runtime)
}

#[cfg(feature = "simplex-native")]
#[tauri::command]
async fn create_invitation(runtime: State<'_, AppRuntime>) -> Result<String, String> {
    create_invitation_impl(&runtime).await
}

#[cfg(feature = "simplex-native")]
#[tauri::command]
async fn accept_invitation(link: String, runtime: State<'_, AppRuntime>) -> Result<(), String> {
    accept_invitation_impl(&runtime, &link).await
}

#[cfg(feature = "simplex-native")]
#[tauri::command]
async fn send_text_message(
    chat_id: i64,
    message: String,
    runtime: State<'_, AppRuntime>,
) -> Result<(), String> {
    send_text_message_impl(&runtime, chat_id, &message).await
}

#[tauri::command]
fn complete_onboarding(
    passphrase: String,
    runtime: State<'_, AppRuntime>,
) -> Result<AppStatus, String> {
    complete_onboarding_impl(passphrase, &runtime)
}

#[cfg(not(feature = "simplex-native"))]
#[tauri::command]
fn unlock_application(
    passphrase: String,
    runtime: State<'_, AppRuntime>,
) -> Result<AppStatus, String> {
    unlock_application_impl(passphrase, &runtime)
}

#[cfg(feature = "simplex-native")]
#[tauri::command]
async fn unlock_application(
    passphrase: String,
    runtime: State<'_, AppRuntime>,
) -> Result<AppStatus, String> {
    unlock_application_with_messaging(passphrase, &runtime).await
}

#[cfg(not(feature = "simplex-native"))]
#[tauri::command]
fn lock_application(runtime: State<'_, AppRuntime>) -> Result<AppStatus, String> {
    lock_application_impl(&runtime)
}

#[cfg(feature = "simplex-native")]
#[tauri::command]
async fn lock_application(runtime: State<'_, AppRuntime>) -> Result<AppStatus, String> {
    // Required shutdown order (docs/security-remediation-plan.md Phase R5): messaging -> SOCKS
    // active streams/listener (both inside `stop_messaging_impl`) -> Tor transport -> vault/key
    // state (`lock_application_impl`, awaited after both complete).
    stop_messaging_impl(&runtime).await;
    let _ = stop_tor_impl(&runtime);
    lock_application_impl(&runtime)
}

#[cfg(not(feature = "simplex-native"))]
#[tauri::command]
fn burn_identity(
    replacement_passphrase: Option<String>,
    runtime: State<'_, AppRuntime>,
) -> Result<AppStatus, String> {
    burn_identity_impl(replacement_passphrase, &runtime)
}

#[cfg(feature = "simplex-native")]
#[tauri::command]
async fn burn_identity(
    replacement_passphrase: Option<String>,
    runtime: State<'_, AppRuntime>,
) -> Result<AppStatus, String> {
    // Same shutdown primitive and order as `lock_application` above, ahead of
    // `PersistentKeyAccessDestroyed` inside `burn_identity_impl`.
    stop_messaging_impl(&runtime).await;
    let _ = stop_tor_impl(&runtime);
    burn_identity_impl(replacement_passphrase, &runtime)
}

#[tauri::command]
fn start_ghost(runtime: State<'_, AppRuntime>) -> Result<AppStatus, String> {
    start_ghost_impl(&runtime)
}

#[cfg(not(feature = "simplex-native"))]
#[tauri::command]
fn end_ghost(runtime: State<'_, AppRuntime>) -> Result<AppStatus, String> {
    end_ghost_impl(&runtime)
}

#[cfg(feature = "simplex-native")]
#[tauri::command]
async fn end_ghost(runtime: State<'_, AppRuntime>) -> Result<AppStatus, String> {
    // Same reasoning as `lock_application`: stop any active Ghost messaging (and its own
    // ephemeral store cleanup, inside `end_ghost_impl`) before the session's key is dropped.
    stop_messaging_impl(&runtime).await;
    end_ghost_impl(&runtime)
}

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            let app_data_dir = app
                .path()
                .app_data_dir()
                .expect("application data directory must be resolvable");
            fs::create_dir_all(&app_data_dir)
                .expect("failed to create the application data directory");

            let tor_state_dir = app_data_dir.join(TOR_STATE_DIR_NAME);
            let tor_cache_dir = app_data_dir.join(TOR_CACHE_DIR_NAME);
            fs::create_dir_all(&tor_state_dir).expect("failed to create the Tor state directory");
            fs::create_dir_all(&tor_cache_dir).expect("failed to create the Tor cache directory");

            let runtime = AppRuntime::new(
                VaultPaths::new(app_data_dir),
                tor_state_dir,
                tor_cache_dir,
                // TPM 2.0 where supported; otherwise a store that refuses every operation, so
                // no production identity is ever created without device-bound protection.
                std::sync::Arc::from(secure_device::platform_store()),
            )
            .expect("failed to construct application runtime");
            app.manage(runtime);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            app_status,
            complete_onboarding,
            unlock_application,
            lock_application,
            burn_identity,
            start_ghost,
            end_ghost,
            tor_status,
            start_tor,
            stop_tor,
            #[cfg(feature = "simplex-native")]
            start_messaging,
            #[cfg(feature = "simplex-native")]
            messaging_status,
            #[cfg(feature = "simplex-native")]
            create_invitation,
            #[cfg(feature = "simplex-native")]
            accept_invitation,
            #[cfg(feature = "simplex-native")]
            send_text_message
        ])
        .run(tauri::generate_context!())
        .expect("failed to run Secure desktop application");
}
