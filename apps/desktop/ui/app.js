const stateBadge = document.querySelector("#stateBadge");
const message = document.querySelector("#message");

const onboardingPanel = document.querySelector("#onboardingPanel");
const onboardingForm = document.querySelector("#onboardingForm");
const onboardingPassphrase = document.querySelector("#onboardingPassphrase");

const lockedPanel = document.querySelector("#lockedPanel");
const unlockForm = document.querySelector("#unlockForm");
const unlockPassphrase = document.querySelector("#unlockPassphrase");

const unlockedPanel = document.querySelector("#unlockedPanel");
const lockButton = document.querySelector("#lockButton");

function tauriInvoke() {
  const invoke = window.__TAURI__?.core?.invoke;
  if (!invoke) {
    throw new Error("Tauri IPC is unavailable");
  }
  return invoke;
}

const PANELS_BY_STATE = {
  onboarding: onboardingPanel,
  locked: lockedPanel,
  unlocked: unlockedPanel,
};

function renderStatus(status) {
  stateBadge.textContent = status.state;

  for (const panel of [onboardingPanel, lockedPanel, unlockedPanel]) {
    panel.hidden = true;
  }

  const activePanel = PANELS_BY_STATE[status.state];
  if (activePanel) {
    activePanel.hidden = false;
  }
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

async function completeOnboarding(event) {
  event.preventDefault();
  try {
    const status = await tauriInvoke()("complete_onboarding", {
      passphrase: onboardingPassphrase.value,
    });
    onboardingPassphrase.value = "";
    renderStatus(status);
    message.textContent = "Vault created. Enter your passphrase to unlock it.";
  } catch (error) {
    message.textContent = String(error);
  }
}

async function unlockApplication(event) {
  event.preventDefault();
  try {
    const status = await tauriInvoke()("unlock_application", {
      passphrase: unlockPassphrase.value,
    });
    unlockPassphrase.value = "";
    renderStatus(status);
    message.textContent = "";
  } catch (error) {
    unlockPassphrase.value = "";
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

onboardingForm.addEventListener("submit", completeOnboarding);
unlockForm.addEventListener("submit", unlockApplication);
lockButton.addEventListener("click", lockApplication);
void refreshStatus();
