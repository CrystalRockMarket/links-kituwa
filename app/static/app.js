// Progressive enhancement only; every page works without this file.

// Mobile navigation drawer
(() => {
  const btn = document.getElementById("menu-btn");
  const bar = document.getElementById("sidebar");
  const scrim = document.getElementById("scrim");
  if (!btn || !bar || !scrim) return;

  const setOpen = (open) => {
    bar.classList.toggle("is-open", open);
    scrim.hidden = !open;
    btn.setAttribute("aria-expanded", String(open));
    btn.setAttribute("aria-label", open ? "Close navigation" : "Open navigation");
  };

  btn.addEventListener("click", () => setOpen(!bar.classList.contains("is-open")));
  scrim.addEventListener("click", () => setOpen(false));
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") setOpen(false);
  });
  bar.addEventListener("click", (e) => {
    if (e.target.closest("a")) setOpen(false);
  });
})();

// Copy a short URL
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

// Mint an attributed pass-along link
document.addEventListener("click", async (event) => {
  const btn = event.target.closest("[data-share]");
  if (!btn) return;
  const res = await fetch(btn.dataset.share, { method: "POST", credentials: "same-origin" });
  const data = await res.json().catch(() => ({ ok: false }));
  const out = document.querySelector("#shareout");
  if (!out) return;
  out.hidden = false;
  if (data.ok) {
    out.value = data.url;
    btn.textContent = "Pass-along link ready";
  } else {
    out.value = data.error || "Could not create a pass-along link.";
  }
});
