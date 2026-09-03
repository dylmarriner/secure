const stateBadge = document.querySelector("#stateBadge");
const message = document.querySelector("#message");
const refreshButton = document.querySelector("#refreshButton");
const lockButton = document.querySelector("#lockButton");

function tauriInvoke() {
  const invoke = window.__TAURI__?.core?.invoke;
  if (!invoke) {
    throw new Error("Tauri IPC is unavailable");
  }
  return invoke;
}

function renderStatus(status) {
  stateBadge.textContent = status.state;
  lockButton.disabled = status.state !== "unlocked";
}

async function refreshStatus() {
  try {
    const status = await tauriInvoke()("app_status");
    renderStatus(status);
    message.textContent = "";
  } catch (error) {
    message.textContent = String(error);
  }
}

async function lockApplication() {
  try {
    const status = await tauriInvoke()("lock_application");
    renderStatus(status);
    message.textContent = "Application locked.";
  } catch (error) {
    message.textContent = String(error);
  }
}

refreshButton.addEventListener("click", refreshStatus);
lockButton.addEventListener("click", lockApplication);
void refreshStatus();
