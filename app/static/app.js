// Small progressive enhancements; the page works without this file.
document.addEventListener("click", async (event) => {
  const btn = event.target.closest("[data-copy]");
  if (!btn) return;
  const input = document.querySelector(btn.dataset.copy);
  if (!input) return;
  try {
    await navigator.clipboard.writeText(input.value);
    btn.textContent = "Copied";
    setTimeout(() => { btn.textContent = "Copy"; }, 1400);
  } catch {
    input.select();
  }
});

// "Share this link onward" mints an attributed pass-along URL.
document.addEventListener("click", async (event) => {
  const btn = event.target.closest("[data-share]");
  if (!btn) return;
  const res = await fetch(btn.dataset.share, { method: "POST", credentials: "same-origin" });
  const data = await res.json().catch(() => ({ ok: false }));
  const out = document.querySelector("#shareout");
  if (!out) return;
  if (data.ok) {
    out.value = data.url;
    out.hidden = false;
    btn.textContent = "Pass-along link ready";
  } else {
    out.value = data.error || "Could not create a pass-along link.";
    out.hidden = false;
  }
});
