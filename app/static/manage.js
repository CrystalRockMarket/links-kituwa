/* Manage page: the token in the fragment authorises changes; the server stores
 * only its SHA-256 and cannot read the link content. */
(function () {
  "use strict";

  const id = document.body.dataset.linkId;
  const token = location.hash.slice(1);
  if (token) history.replaceState(null, "", location.pathname);

  if (!token) { document.getElementById("step-loading").hidden = true;
                document.getElementById("step-nokey").hidden = false; return; }

  const steps = ["step-loading", "step-nokey", "step-main"];
  function show(name) {
    steps.forEach(function (s) { document.getElementById(s).hidden = (s !== name); });
  }

  function render(state) {
    document.getElementById("state").textContent = state.state || "—";
    document.getElementById("uses").textContent = state.uses == null ? "—" : state.uses;
    document.getElementById("left").textContent =
      state.max_uses == null ? "unlimited" : (state.uses_left == null ? "—" : state.uses_left);
    document.getElementById("expires").textContent =
      state.expires_at ? state.expires_at.replace("T", " ").slice(0, 16) + " UTC" : "never";
    show("step-main");
  }

  async function call(action, seconds) {
    const res = await fetch("/api/manage/" + encodeURIComponent(id), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: token, action: action, seconds: seconds || null })
    });
    const data = await res.json().catch(function () { return {}; });
    if (!res.ok || !data.ok) {
      document.getElementById("msg").textContent = data.error || "That did not work.";
      return;
    }
    render(data);
  }

  call("state").then(function () {
    if (document.getElementById("step-main").hidden) {
      document.getElementById("step-loading").hidden = true;
      document.getElementById("step-nokey").hidden = false;
    }
  });

  document.querySelectorAll("[data-act]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      const act = btn.getAttribute("data-act");
      if (act === "delete" && !confirm("Delete this link now? The content is wiped immediately.")) return;
      document.getElementById("msg").textContent = "Working…";
      call(act, parseInt(btn.getAttribute("data-seconds"), 10)).then(function () {
        document.getElementById("msg").textContent = act === "delete"
          ? "Deleted. The content is gone." : "Updated.";
      });
    });
  });
})();
