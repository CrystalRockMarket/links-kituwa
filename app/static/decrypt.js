/* Decrypt page. The key lives in the fragment; it is cleared before any network
 * call, and the destination is only revealed after the server has spent a use. */
(function () {
  "use strict";

  const id = document.body.dataset.linkId;
  const steps = ["step-loading", "step-nokey", "step-intro", "step-password",
                 "step-done", "step-gone", "step-report"];
  let linkKey = null;
  let sealed = null;
  let password = "";
  let payload = null;
  let timer = null;

  function show(name) {
    steps.forEach(function (s) {
      document.getElementById(s).hidden = (s !== name);
    });
  }
  function gone(text) {
    document.getElementById("gone-reason").textContent = text;
    show("step-gone");
  }

  // 1. Read the key, then erase it from the address bar and from history.
  const hash = location.hash.slice(1);
  if (hash) {
    try {
      const raw = window.LK.unb64u(hash);
      if (raw.length === 32) linkKey = raw;
    } catch (e) { linkKey = null; }
    history.replaceState(null, "", location.pathname + location.search);
  }

  if (!linkKey) { show("step-nokey"); return; }

  // 2. Ask the server only for public state. This spends nothing.
  fetch("/api/links/" + encodeURIComponent(id), { cache: "no-store" })
    .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); })
    .then(function (out) {
      const d = out.d || {};
      if (!out.ok || !d.exists) return gone("No such link.");
      if (d.state === "spent") return gone("It has been used the allowed number of times.");
      if (d.state === "expired") return gone("It has expired.");
      if (d.state === "disabled") return gone("It was disabled by the operator.");
      if (d.state === "scheduled") {
        return gone("It is not active yet. Try again later.");
      }
      if (d.max_uses) {
        document.getElementById("uses-line").textContent =
          "Opening it uses one of " + d.uses_left + " remaining open" +
          (d.uses_left === 1 ? "" : "s") + ".";
      } else {
        document.getElementById("uses-line").textContent =
          "This link allows unlimited opens.";
      }
      if (d.kdf && d.kdf !== "none") {
        document.getElementById("step-password").hidden = false;
        show("step-password");
        document.getElementById("password").focus();
      } else {
        show("step-intro");
      }
    })
    .catch(function () { gone("The server did not answer. Try again in a moment."); });

  async function consume() {
    const res = await fetch("/api/links/" + encodeURIComponent(id) + "/consume",
                            { method: "POST", headers: { "Content-Type": "application/json" },
                              body: "{}" });
    const data = await res.json().catch(function () { return {}; });
    if (res.status === 410) { gone("It has been used the allowed number of times, or expired."); return null; }
    if (!res.ok) { gone(data.error || "This link cannot be opened."); return null; }
    return data;
  }

  async function decrypt() {
    try {
      payload = await window.LK.open(sealed, linkKey, password);
      return true;
    } catch (e) {
      return false;
    }
  }

  function render() {
    const urls = (payload.urls && payload.urls.length) ? payload.urls : [payload.url];
    const clean = [];
    urls.forEach(function (u) {
      const parsed = window.LK.parseUrl(u);
      if (parsed) clean.push(parsed);
    });
    if (!clean.length) {
      gone("The payload did not contain a usable http(s) address.");
      return;
    }
    const first = clean[0];
    const info = window.LK.hostInfo(first);
    document.getElementById("domain").textContent = info.host;
    document.getElementById("full-url").textContent = first.href;

    const warns = [];
    if (info.puny) warns.push("This address uses punycode (xn--). It can imitate a " +
                              "look-alike of a real site. Check the domain carefully.");
    if (info.nonAscii) warns.push("This address contains non-ASCII characters and may " +
                                  "imitate another domain.");
    if (info.ip) warns.push("This address is a raw IP address, not a named site.");
    if (warns.length) {
      const w = document.getElementById("warn");
      w.textContent = warns.join(" ");
      w.hidden = false;
    }

    if (payload.note) {
      const n = document.getElementById("note");
      n.textContent = payload.note;
      n.hidden = false;
    }

    if (clean.length > 1) {
      const list = document.getElementById("bundle");
      list.innerHTML = "";
      clean.forEach(function (u) {
        const li = document.createElement("li");
        const a = document.createElement("a");
        a.href = u.href;
        a.rel = "noopener noreferrer";
        a.textContent = window.LK.hostInfo(u).host + u.pathname;
        li.appendChild(a);
        list.appendChild(li);
      });
      list.hidden = false;
      document.getElementById("go").textContent = "Go to " + info.host;
      document.getElementById("go").href = first.href;
    } else {
      document.getElementById("go").href = first.href;
      document.getElementById("go").textContent = "Go to " + info.host;
    }

    document.title = info.host + " · links.kituwa.com";
    show("step-done");

    if (sealed.redirect_mode === "auto") {
      let left = 3;
      const line = document.getElementById("countdown");
      line.hidden = false;
      line.textContent = "Opening " + info.host + " in " + left +
        (left === 1 ? " second…" : " seconds…");
      timer = setInterval(function () {
        left -= 1;
        if (left <= 0) {
          clearInterval(timer);
          const target = window.LK.parseUrl(first.href);
          if (target) location.replace(target.href);
          return;
        }
        line.textContent = "Opening " + info.host + " in " + left +
          (left === 1 ? " second…" : " seconds…");
      }, 1000);
    }
  }

  async function reveal() {
    document.getElementById("reveal").disabled = true;
    const data = await consume();
    document.getElementById("reveal").disabled = false;
    if (!data) return;
    sealed = data;
    if (data.kdf && data.kdf !== "none" && !password) {
      show("step-password");
      document.getElementById("password").focus();
      return;
    }
    if (await decrypt()) render();
    else {
      document.getElementById("pw-error").textContent = "That password did not work.";
      document.getElementById("pw-error").hidden = false;
      show("step-password");
    }
  }

  document.getElementById("reveal").addEventListener("click", reveal);

  document.getElementById("unlock").addEventListener("click", async function () {
    password = document.getElementById("password").value;
    if (!password) return;
    document.getElementById("pw-error").hidden = true;
    if (!sealed) { await reveal(); return; }
    if (await decrypt()) render();
    else {
      document.getElementById("pw-error").textContent =
        "That password did not work. You can try again — the link is already open.";
      document.getElementById("pw-error").hidden = false;
    }
  });

  document.getElementById("password").addEventListener("keydown", function (ev) {
    if (ev.key === "Enter") document.getElementById("unlock").click();
  });

  document.getElementById("copy").addEventListener("click", function () {
    const text = document.getElementById("full-url").textContent;
    navigator.clipboard.writeText(text).then(function () {
      const b = document.getElementById("copy");
      b.textContent = "Copied";
      setTimeout(function () { b.textContent = "Copy address"; }, 1400);
    });
  });

  // --- reporting -------------------------------------------------------
  function openReport() {
    if (timer) { clearInterval(timer); timer = null; }
    document.getElementById("report-open").hidden = true;
    show("step-report");
  }
  document.getElementById("report-open").addEventListener("click", openReport);
  document.getElementById("report-cancel").addEventListener("click", function () {
    show(payload ? "step-done" : "step-gone");
    document.getElementById("report-open").hidden = false;
  });
  document.getElementById("report-send").addEventListener("click", async function () {
    const body = {
      reason: document.getElementById("report-reason").value,
      url: document.getElementById("report-url").value || null
    };
    const res = await fetch("/api/links/" + encodeURIComponent(id) + "/report",
                            { method: "POST", headers: { "Content-Type": "application/json" },
                              body: JSON.stringify(body) });
    if (res.ok) {
      document.getElementById("report-done").hidden = false;
      document.getElementById("report-send").disabled = true;
    }
  });
})();
