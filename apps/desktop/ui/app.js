const stateBadge = document.querySelector("#stateBadge");
const message = document.querySelector("#message");

const onboardingPanel = document.querySelector("#onboardingPanel");
const onboardingForm = document.querySelector("#onboardingForm");
const onboardingPassphrase = document.querySelector("#onboardingPassphrase");

const lockedPanel = document.querySelector("#lockedPanel");
const unlockForm = document.querySelector("#unlockForm");
const unlockPassphrase = document.querySelector("#unlockPassphrase");
const startGhostButton = document.querySelector("#startGhostButton");

const ghostPanel = document.querySelector("#ghostPanel");
const endGhostButton = document.querySelector("#endGhostButton");

const unlockedPanel = document.querySelector("#unlockedPanel");
const lockButton = document.querySelector("#lockButton");

const destroyedPanel = document.querySelector("#destroyedPanel");

const burnPanel = document.querySelector("#burnPanel");
const burnRevealButton = document.querySelector("#burnRevealButton");
const burnForm = document.querySelector("#burnForm");
const burnConfirm = document.querySelector("#burnConfirm");
const burnReplacement = document.querySelector("#burnReplacement");
const burnCancelButton = document.querySelector("#burnCancelButton");

/// Typed confirmation for an irreversible action. A second click is too easy to make by
/// accident or muscle memory for something with no undo; typing the word forces the user to
/// read what they are agreeing to.
const BURN_CONFIRMATION = "DESTROY";

const torStateBadge = document.querySelector("#torStateBadge");
const startTorButton = document.querySelector("#startTorButton");
const stopTorButton = document.querySelector("#stopTorButton");
const torMessage = document.querySelector("#torMessage");

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
  ghost: ghostPanel,
  destroyed: destroyedPanel,
};

// States in which an identity exists to be destroyed. Mirrors the backend's own accepted
// states for `burn_identity`; the backend refuses anything else regardless of what is shown.
const BURNABLE_STATES = new Set(["locked", "unlocked", "ghost"]);

function resetBurnConfirmation() {
  burnForm.hidden = true;
  burnRevealButton.hidden = false;
  burnConfirm.value = "";
  burnReplacement.value = "";
}

function renderStatus(status) {
  stateBadge.textContent = status.state;

  for (const panel of [onboardingPanel, lockedPanel, unlockedPanel, ghostPanel, destroyedPanel]) {
    panel.hidden = true;
  }

  const activePanel = PANELS_BY_STATE[status.state];
  if (activePanel) {
    activePanel.hidden = false;
  }

  burnPanel.hidden = !BURNABLE_STATES.has(status.state);
  // Never leave a primed confirmation form behind across a state change - locking, unlocking or
  // completing a burn must all return this to its safe, collapsed default.
  resetBurnConfirmation();
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

async function startGhost() {
  try {
    const status = await tauriInvoke()("start_ghost");
    renderStatus(status);
    message.textContent = "";
  } catch (error) {
    message.textContent = String(error);
  }
}

async function endGhost() {
  try {
    const status = await tauriInvoke()("end_ghost");
    renderStatus(status);
    message.textContent = "Ghost session ended. Its key no longer exists.";
  } catch (error) {
    message.textContent = String(error);
  }
}

function revealBurnConfirmation() {
  burnRevealButton.hidden = true;
  burnForm.hidden = false;
  burnConfirm.focus();
}

async function burnIdentity(event) {
  event.preventDefault();

  if (burnConfirm.value.trim() !== BURN_CONFIRMATION) {
    message.textContent = `Type ${BURN_CONFIRMATION} exactly to confirm. Nothing has been destroyed.`;
    return;
  }

  // An empty field means "leave nothing behind"; the backend distinguishes null from a string
  // and validates the length itself before destroying anything.
  const replacement = burnReplacement.value.length > 0 ? burnReplacement.value : null;

  try {
    const status = await tauriInvoke()("burn_identity", {
      replacementPassphrase: replacement,
    });
    renderStatus(status);
    message.textContent = replacement
      ? "Previous identity destroyed. A new, unrelated vault is now in its place - unlock it with its own passphrase."
      : "Identity destroyed. The vault key no longer exists.";
  } catch (error) {
    resetBurnConfirmation();
    message.textContent = String(error);
  }
}

function renderTorStatus(status) {
  torStateBadge.textContent = status.state;
  const busy = status.state === "bootstrapping";
  startTorButton.disabled = busy || status.state === "ready";
  stopTorButton.disabled = busy || status.state === "stopped";
  if (typeof status.bootstrap_fraction === "number") {
    torMessage.textContent = `Bootstrap progress: ${Math.round(status.bootstrap_fraction * 100)}%`;
  }
}

async function refreshTorStatus() {
  try {
    const status = await tauriInvoke()("tor_status");
    renderTorStatus(status);
  } catch (error) {
    torMessage.textContent = String(error);
  }
}

async function startTor() {
  torMessage.textContent = "Bootstrapping - this can take a while...";
  startTorButton.disabled = true;
  try {
    const status = await tauriInvoke()("start_tor");
    renderTorStatus(status);
    torMessage.textContent = "";
  } catch (error) {
    torMessage.textContent = String(error);
    await refreshTorStatus();
  }
}

async function stopTor() {
  try {
    const status = await tauriInvoke()("stop_tor");
    renderTorStatus(status);
    torMessage.textContent = "";
  } catch (error) {
    torMessage.textContent = String(error);
  }
}

onboardingForm.addEventListener("submit", completeOnboarding);
unlockForm.addEventListener("submit", unlockApplication);
lockButton.addEventListener("click", lockApplication);
startGhostButton.addEventListener("click", startGhost);
endGhostButton.addEventListener("click", endGhost);
burnRevealButton.addEventListener("click", revealBurnConfirmation);
burnCancelButton.addEventListener("click", () => {
  resetBurnConfirmation();
  message.textContent = "";
});
burnForm.addEventListener("submit", burnIdentity);
startTorButton.addEventListener("click", startTor);
stopTorButton.addEventListener("click", stopTor);
void refreshStatus();
void refreshTorStatus();
