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
    const previousText = button.textContent;
    button.textContent = "Copied";
    window.setTimeout(() => {
      button.textContent = previousText;
    }, 1400);
  } catch (_error) {
    button.textContent = "Copy failed";
    window.setTimeout(() => {
      button.textContent = "Share this result";
    }, 1400);
  }
});
