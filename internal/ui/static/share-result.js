const shareBreakpoint = window.matchMedia("(max-width: 720px)");

function getShareButtonLabel(button) {
  return shareBreakpoint.matches
    ? button.getAttribute("data-label-compact") || "Share"
    : button.getAttribute("data-label-full") || "Share this result";
}

function syncShareButtonLabel(button) {
  button.textContent = getShareButtonLabel(button);
}

function syncAllShareButtonLabels() {
  document.querySelectorAll("[data-share-button]").forEach(syncShareButtonLabel);
}

function syncShareLabelsAfterHtmx(event) {
  const target = event.detail && event.detail.target;
  if (target) {
    target.querySelectorAll("[data-share-button]").forEach(syncShareButtonLabel);
    return;
  }
  syncAllShareButtonLabels();
}

document.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-share-button]");
  if (!button) {
    return;
  }

  const shareUrl = button.getAttribute("data-share-url");
  if (!shareUrl) {
    return;
  }

  try {
    await navigator.clipboard.writeText(new URL(shareUrl, window.location.origin).toString());
    button.textContent = "Copied";
    window.setTimeout(() => {
      syncShareButtonLabel(button);
    }, 1400);
  } catch (_error) {
    button.textContent = "Copy failed";
    window.setTimeout(() => {
      syncShareButtonLabel(button);
    }, 1400);
  }
});

syncAllShareButtonLabels();
shareBreakpoint.addEventListener("change", syncAllShareButtonLabels);
document.body.addEventListener("htmx:afterSwap", syncShareLabelsAfterHtmx);
