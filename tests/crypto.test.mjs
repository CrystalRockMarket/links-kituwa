/* Round-trip test for the browser crypto, run under Node's Web Crypto. */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
globalThis.window = {};
eval(readFileSync(join(here, "..", "app", "static", "crypto.js"), "utf8"));
const LK = globalThis.window.LK;

let failed = 0;
function check(name, cond) {
  if (cond) { console.log("ok   " + name); }
  else { console.log("FAIL " + name); failed += 1; }
}
async function rejects(name, fn) {
  try { await fn(); check(name, false); } catch (e) { check(name, true); }
}

const key = LK.newKey();
const payload = { v: 1, urls: ["https://example.com/a?b=c#d"], note: "hi", createdAt: "now" };

const sealed = await LK.seal(payload, key, "");
check("ciphertext is not the plaintext",
      !atob(sealed.ciphertext.replace(/-/g, "+").replace(/_/g, "/"))
        .includes("example.com"));
check("iv is 12 bytes", LK.unb64u(sealed.iv).length === 12);
check("kdf none without a password", sealed.kdf === "none" && sealed.salt === null);

const opened = await LK.open(sealed, key, "");
check("round trip", JSON.stringify(opened) === JSON.stringify(payload));

await rejects("wrong key fails", () => LK.open(sealed, LK.newKey(), ""));

const pwSealed = await LK.seal(payload, key, "correct horse battery");
check("salt present with a password", pwSealed.salt && LK.unb64u(pwSealed.salt).length === 16);
check("kdf is pbkdf2", pwSealed.kdf === "pbkdf2-sha256-600k");
check("password round trip",
      JSON.stringify(await LK.open(pwSealed, key, "correct horse battery"))
      === JSON.stringify(payload));
await rejects("wrong password fails", () => LK.open(pwSealed, key, "wrong password"));
await rejects("password link needs the link key too",
              () => LK.open(pwSealed, LK.newKey(), "correct horse battery"));

const tampered = { ...sealed, ciphertext: sealed.ciphertext.slice(0, -4) + "AAAA" };
await rejects("tampered ciphertext fails", () => LK.open(tampered, key, ""));

check("https accepted", LK.parseUrl("https://example.com/x") !== null);
check("http accepted", LK.parseUrl("http://example.com/x") !== null);
check("javascript: rejected", LK.parseUrl("javascript:alert(1)") === null);
check("data: rejected", LK.parseUrl("data:text/html,x") === null);
check("file: rejected", LK.parseUrl("file:///etc/passwd") === null);
check("credentials rejected", LK.parseUrl("https://user:pw@example.com/") === null);

check("punycode detected", LK.hostInfo(new URL("https://xn--pple-43d.com/")).puny);
check("plain host is clean", !LK.hostInfo(new URL("https://example.com/")).puny);

const chal = "abc.def.18.mac";
const n = await LK.solve(chal, 18);
const digest = new Uint8Array(await crypto.subtle.digest("SHA-256",
  new TextEncoder().encode(chal + ":" + n)));
check("proof of work has 18 leading zero bits", digest[0] === 0 && digest[1] === 0
      && (digest[2] >> 6) === 0);

process.exit(failed ? 1 : 0);
