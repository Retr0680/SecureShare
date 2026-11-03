document.addEventListener("DOMContentLoaded", () => {
  const fileInput = document.getElementById("file-input");
  if (fileInput) {
    fileInput.addEventListener("change", () => {
      const label = document.getElementById("file-label");
      if (label && fileInput.files.length) label.textContent = fileInput.files[0].name;
    });
  }
  document.querySelectorAll("[data-copy]").forEach(button => {
    button.addEventListener("click", async () => {
      const input = document.querySelector(button.dataset.copy);
      if (!input) return;
      try {
        await navigator.clipboard.writeText(input.value);
        button.textContent = "Copied";
        setTimeout(() => button.textContent = "Copy", 1600);
      } catch {
        input.select();
        document.execCommand("copy");
      }
    });
  });
  document.querySelectorAll("form[data-confirm]").forEach(form => {
    form.addEventListener("submit", event => {
      if (!confirm(form.dataset.confirm)) event.preventDefault();
    });
  });
});
