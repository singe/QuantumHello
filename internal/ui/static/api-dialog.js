document.addEventListener("DOMContentLoaded", () => {
  const dialog = document.getElementById("api-dialog");
  const openButton = document.querySelector("[data-api-dialog-open]");

  if (!dialog || !openButton) {
    return;
  }

  openButton.addEventListener("click", () => {
    if (typeof dialog.showModal === "function") {
      dialog.showModal();
    }
  });

  dialog.addEventListener("click", (event) => {
    const rect = dialog.getBoundingClientRect();
    const clickedOutside =
      event.clientX < rect.left ||
      event.clientX > rect.right ||
      event.clientY < rect.top ||
      event.clientY > rect.bottom;
    if (clickedOutside) {
      dialog.close();
    }
  });
});
