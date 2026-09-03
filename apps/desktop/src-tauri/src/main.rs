use secure_core::{AppEvent, AppLifecycle, AppState};
use serde::Serialize;
use std::sync::Mutex;
use tauri::State;

struct AppRuntime {
    lifecycle: Mutex<AppLifecycle>,
}

impl AppRuntime {
    fn new() -> Self {
        Self {
            lifecycle: Mutex::new(AppLifecycle::new(AppState::Locked)),
        }
    }
}

#[derive(Debug, Serialize)]
struct AppStatus {
    state: &'static str,
}

#[tauri::command]
fn app_status(runtime: State<'_, AppRuntime>) -> Result<AppStatus, String> {
    let lifecycle = runtime
        .lifecycle
        .lock()
        .map_err(|_| "application lifecycle lock poisoned".to_owned())?;
    Ok(status_for(lifecycle.state()))
}

#[tauri::command]
fn lock_application(runtime: State<'_, AppRuntime>) -> Result<AppStatus, String> {
    let mut lifecycle = runtime
        .lifecycle
        .lock()
        .map_err(|_| "application lifecycle lock poisoned".to_owned())?;

    match lifecycle.state() {
        AppState::Unlocked => lifecycle
            .apply(AppEvent::Lock)
            .map_err(|error| error.to_string())?,
        AppState::Locked => {}
        state => return Err(format!("cannot lock application from {state:?}")),
    }

    Ok(status_for(lifecycle.state()))
}

fn status_for(state: AppState) -> AppStatus {
    AppStatus {
        state: match state {
            AppState::Starting => "starting",
            AppState::Onboarding => "onboarding",
            AppState::Locked => "locked",
            AppState::Unlocked => "unlocked",
            AppState::Ghost => "ghost",
            AppState::Destroying => "destroying",
            AppState::Destroyed => "destroyed",
        },
    }
}

fn main() {
    tauri::Builder::default()
        .manage(AppRuntime::new())
        .invoke_handler(tauri::generate_handler![app_status, lock_application])
        .run(tauri::generate_context!())
        .expect("failed to run Secure desktop application");
}
