/* Shell behaviour: mobile menu and copy-to-clipboard. No tracking, no analytics. */
(function () {
  "use strict";
  var sidebar = document.getElementById("sidebar");
  var scrim = document.getElementById("scrim");
  var btn = document.getElementById("menu-btn");

  function close() {
    if (!sidebar) return;
    sidebar.classList.remove("is-open");
    if (scrim) scrim.hidden = true;
    if (btn) btn.setAttribute("aria-expanded", "false");
  }
  if (btn && sidebar) {
    btn.addEventListener("click", function () {
      var open = sidebar.classList.toggle("is-open");
      if (scrim) scrim.hidden = !open;
      btn.setAttribute("aria-expanded", open ? "true" : "false");
    });
  }
  if (scrim) scrim.addEventListener("click", close);

  document.addEventListener("click", function (ev) {
    var target = ev.target.closest("[data-copy]");
    if (!target) return;
    var input = document.querySelector(target.getAttribute("data-copy"));
    if (!input) return;
    input.select();
    var done = function () {
      var old = target.textContent;
      target.textContent = "Copied";
      setTimeout(function () { target.textContent = old; }, 1400);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(input.value).then(done).catch(function () {
        document.execCommand("copy"); done();
      });
    } else {
      document.execCommand("copy"); done();
    }
  });
})();
