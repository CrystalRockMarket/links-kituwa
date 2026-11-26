/* Links — client-side crypto. Web Crypto only, no third-party code.
 * A link key is 32 random bytes, base64url, carried in the URL fragment.
 * The server receives ciphertext + iv (+ salt when a password is used). */
(function () {
  "use strict";

  const enc = new TextEncoder();
  const dec = new TextDecoder();

  function b64u(bytes) {
    let s = "";
    const view = new Uint8Array(bytes);
    for (let i = 0; i < view.length; i += 0x8000) {
      s += String.fromCharCode.apply(null, view.subarray(i, i + 0x8000));
    }
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function unb64u(text) {
    const s = String(text).replace(/-/g, "+").replace(/_/g, "/");
    const pad = "=".repeat((4 - (s.length % 4)) % 4);
    const bin = atob(s + pad);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function random(n) {
    return crypto.getRandomValues(new Uint8Array(n));
  }

  async function deriveKey(linkKey, password, salt) {
    if (!password) return linkKey;
    const base = await crypto.subtle.importKey(
      "raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt: salt, iterations: 600000, hash: "SHA-256" }, base, 256);
    const hkdf = await crypto.subtle.importKey(
      "raw", new Uint8Array(bits), "HKDF", false, ["deriveBits"]);
    const out = await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: linkKey,
        info: enc.encode("links-kituwa-v1") }, hkdf, 256);
    return new Uint8Array(out);
  }

  async function seal(payload, linkKey, password) {
    const salt = password ? random(16) : null;
    const key = await deriveKey(linkKey, password, salt);
    const iv = random(12);
    const k = await crypto.subtle.importKey("raw", key, "AES-GCM", false, ["encrypt"]);
    const ct = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv }, k, enc.encode(JSON.stringify(payload)));
    return {
      ciphertext: b64u(ct),
      iv: b64u(iv),
      salt: salt ? b64u(salt) : null,
      kdf: password ? "pbkdf2-sha256-600k" : "none"
    };
  }

  async function open(sealed, linkKey, password) {
    const salt = sealed.salt ? unb64u(sealed.salt) : null;
    const key = await deriveKey(linkKey, password || "", salt);
    const k = await crypto.subtle.importKey("raw", key, "AES-GCM", false, ["decrypt"]);
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: unb64u(sealed.iv) }, k, unb64u(sealed.ciphertext));
    return JSON.parse(dec.decode(pt));
  }

  function parseUrl(raw) {
    try {
      const u = new URL(String(raw).trim());
      if (u.protocol !== "http:" && u.protocol !== "https:") return null;
      if (u.username || u.password) return null;
      return u;
    } catch (e) {
      return null;
    }
  }

  function hostInfo(u) {
    const host = u.hostname;
    const puny = host.indexOf("xn--") !== -1;
    const ascii = /^[a-z0-9.-]+$/i.test(host);
    const ip = /^[\d.]+$/.test(host) || host.indexOf(":") !== -1;
    return { host: host, puny: puny, nonAscii: !ascii, ip: ip };
  }

  /* Proof of work: find a nonce whose SHA-256 has `bits` leading zero bits. */
  async function solve(challenge, bits) {
    const target = Math.ceil(bits / 8);
    for (let n = 0; n < 4000000; n++) {
      const digest = new Uint8Array(
        await crypto.subtle.digest("SHA-256", enc.encode(challenge + ":" + n)));
      let ok = true;
      for (let i = 0; i < target; i++) {
        const need = Math.min(8, bits - i * 8);
        if (need <= 0) break;
        if (i === target - 1) {
          if ((digest[i] >> (8 - need)) !== 0) { ok = false; break; }
        } else if (digest[i] !== 0) { ok = false; break; }
      }
      if (ok) return n;
    }
    throw new Error("proof of work did not converge");
  }

  window.LK = {
    b64u: b64u, unb64u: unb64u, random: random,
    seal: seal, open: open, parseUrl: parseUrl, hostInfo: hostInfo, solve: solve,
    newKey: function () { return random(32); }
  };
})();
