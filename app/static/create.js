/* Create page: validate, encrypt in the browser, then post only the sealed blob. */
(function () {
  "use strict";

  const form = document.getElementById("create-form");
  if (!form) return;

  const rows = document.getElementById("url-rows");
  const statusEl = document.getElementById("status");
  const errorEl = document.getElementById("error");
  const result = document.getElementById("result");
  const btn = document.getElementById("create-btn");
  const hint = document.getElementById("mode-hint");
  const MODE_KEY = "links.mode";

  function advInUse() {
    const found = [];
    if ((form.querySelector("input[name=note]").value || "").trim()) found.push("a note");
    if (form.querySelector("input[name=password]").value) found.push("a password");
    if (document.getElementById("not-before").value !== "0") found.push("a start time");
    if (form.querySelector("select[name=redirect_mode]").value !== "auto") found.push("manual redirect");
    if (rows.querySelectorAll("input[name=url]").length > 1) found.push("more than one URL");
    return found;
  }

  function applyMode(mode, remember) {
    const simple = mode !== "complex";
    form.classList.toggle("mode-simple", simple);
    document.querySelectorAll("[data-mode-set]").forEach(function (b) {
      b.setAttribute("aria-pressed",
        String((b.getAttribute("data-mode-set") === "complex") === !simple));
    });
    if (simple) {
      const used = advInUse();
      hint.textContent = used.length
        ? "Simple view — the advanced options you set will still be used: " + used.join(", ") + "."
        : "A URL, how many opens and how long. That is all most links need.";
    } else {
      hint.textContent = "Every option: a note, a password, a start time, redirect behaviour and bundles.";
    }
    if (remember) {
      try { localStorage.setItem(MODE_KEY, simple ? "simple" : "complex"); } catch (e) {}
    }
  }

  let stored = "simple";
  try { stored = localStorage.getItem(MODE_KEY) || "simple"; } catch (e) {}
  applyMode(stored, false);

  document.querySelectorAll("[data-mode-set]").forEach(function (b) {
    b.addEventListener("click", function () {
      applyMode(b.getAttribute("data-mode-set"), true);
      if (b.getAttribute("data-mode-set") === "simple") {
        form.querySelector("input[name=url]").focus();
      }
    });
  });

  form.addEventListener("input", function () {
    if (form.classList.contains("mode-simple")) applyMode("simple", false);
  });

  function say(text) { statusEl.textContent = text || ""; }
  function fail(text) {
    errorEl.textContent = text;
    errorEl.hidden = !text;
  }

  document.getElementById("add-url").addEventListener("click", function () {
    const count = rows.querySelectorAll("input[name=url]").length;
    if (count >= 10) { fail("Ten URLs is the maximum for one link."); return; }
    const wrap = document.createElement("div");
    wrap.className = "url-row adv";
    const label = document.createElement("label");
    label.textContent = "Another URL";
    const input = document.createElement("input");
    input.type = "url";
    input.name = "url";
    input.placeholder = "https://example.com/second";
    input.inputMode = "url";
    input.spellcheck = false;
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "btn btn-ghost btn-sm";
    remove.textContent = "Remove";
    remove.addEventListener("click", function () { wrap.remove(); });
    label.appendChild(input);
    wrap.appendChild(label);
    wrap.appendChild(remove);
    rows.appendChild(wrap);
  });

  function toggle(id, select) {
    const el = document.getElementById(id);
    el.hidden = select.value !== "custom";
  }
  document.getElementById("max-uses").addEventListener("change", function () {
    toggle("custom-uses-wrap", this);
  });
  document.getElementById("expires").addEventListener("change", function () {
    toggle("custom-expiry-wrap", this);
  });
  document.getElementById("not-before").addEventListener("change", function () {
    toggle("custom-notbefore-wrap", this);
  });

  function intValue(select, customId, fallback) {
    if (select.value === "custom") {
      const n = parseInt(document.getElementById(customId).value, 10);
      return Number.isFinite(n) ? n : fallback;
    }
    return parseInt(select.value, 10);
  }

  async function post(body) {
    const res = await fetch("/api/links", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    const data = await res.json().catch(function () { return {}; });
    return { res: res, data: data };
  }

  form.addEventListener("submit", async function (ev) {
    ev.preventDefault();
    fail("");
    if (!window.crypto || !crypto.subtle) {
      fail("This browser does not expose Web Crypto. Use a current browser over HTTPS.");
      return;
    }

    const urls = [];
    let badUrl = false;
    form.querySelectorAll("input[name=url]").forEach(function (input) {
      const u = window.LK.parseUrl(input.value);
      if (u) urls.push(u.href);
      else if (input.value.trim()) badUrl = true;
    });
    if (badUrl) { fail("Only http:// and https:// addresses are allowed."); return; }
    if (!urls.length) { fail("Enter at least one http(s) URL."); return; }

    const note = (form.querySelector("input[name=note]").value || "").trim();
    const password = form.querySelector("input[name=password]").value || "";
    if (password && password.length < 8) {
      fail("Use at least 8 characters for the password."); return;
    }

    const maxUses = intValue(document.getElementById("max-uses"), "custom_uses", 1);
    const expiresIn = intValue(document.getElementById("expires"), "custom_expiry", 86400);
    const notBefore = intValue(document.getElementById("not-before"), "custom_not_before", 0);
    const usesIsCustom = document.getElementById("max-uses").value === "custom";
    if (usesIsCustom && (!maxUses || maxUses < 1)) { fail("Custom uses must be 1 or more."); return; }
    if (maxUses !== 0 && (!maxUses || maxUses < 1)) { fail("Uses must be 1 or more."); return; }
    if (expiresIn !== 0 && expiresIn < 60) { fail("Expiry must be at least one minute."); return; }
    if (expiresIn !== 0 && notBefore >= expiresIn) {
      fail("The link would activate after it expires. Pick a later expiry."); return;
    }

    const payload = { v: 1, urls: urls, createdAt: new Date().toISOString() };
    if (note) payload.note = note;

    btn.disabled = true;
    try {
      say(password ? "Deriving the key (600,000 rounds)…" : "Encrypting in your browser…");
      const key = window.LK.newKey();
      const sealed = await window.LK.seal(payload, key, password);
      const options = {
        max_uses: maxUses === 0 ? null : maxUses,
        expires_in: expiresIn === 0 ? null : expiresIn,
        not_before_in: notBefore || 0,
        redirect_mode: form.querySelector("select[name=redirect_mode]").value,
        has_note: !!note
      };
      say("Sending the sealed blob…");
      let out = await post({
        ciphertext: sealed.ciphertext, iv: sealed.iv, salt: sealed.salt,
        kdf: sealed.kdf, options: options
      });

      if (out.res.status === 428 && out.data.pow) {
        say("Proving you are a person (a few seconds)…");
        const chal = await (await fetch("/api/pow")).json();
        const solution = await window.LK.solve(chal.challenge, chal.bits);
        out = await post({
          ciphertext: sealed.ciphertext, iv: sealed.iv, salt: sealed.salt,
          kdf: sealed.kdf, options: options,
          pow: { challenge: chal.challenge, solution: String(solution) }
        });
      }

      if (!out.res.ok) {
        fail(out.data.error || "The server refused the link (" + out.res.status + ").");
        say("");
        return;
      }

      const share = out.data.url + "#" + window.LK.b64u(key);
      const manage = location.origin + "/m/" + out.data.id + "#" + out.data.manage_token;
      document.getElementById("share-url").value = share;
      document.getElementById("manage-url").value = manage;
      document.getElementById("open-preview").href = share;
      form.hidden = true;
      result.hidden = false;
      say("");
      result.scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (err) {
      fail("Could not create the link: " + (err && err.message ? err.message : err));
      say("");
    } finally {
      btn.disabled = false;
    }
  });

  document.getElementById("another").addEventListener("click", function () {
    result.hidden = true;
    form.hidden = false;
    form.reset();
    form.querySelectorAll(".url-row").forEach(function (r) { r.remove(); });
    document.getElementById("share-url").value = "";
    document.getElementById("manage-url").value = "";
    applyMode(form.classList.contains("mode-simple") ? "simple" : "complex", false);
    form.scrollIntoView({ behavior: "smooth", block: "start" });
  });

  document.addEventListener("click", function (ev) {
    const target = ev.target.closest("[data-copy]");
    if (!target) return;
    const input = document.querySelector(target.getAttribute("data-copy"));
    if (!input) return;
    input.select();
    navigator.clipboard.writeText(input.value).then(function () {
      const old = target.textContent;
      target.textContent = "Copied";
      setTimeout(function () { target.textContent = old; }, 1400);
    }).catch(function () { document.execCommand("copy"); });
  });
})();
