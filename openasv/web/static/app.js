(function () {
  "use strict";
  var $ = function (s, el) { return (el || document).querySelector(s); };
  var $$ = function (s, el) { return Array.prototype.slice.call((el || document).querySelectorAll(s)); };

  $$("[data-print]").forEach(function (b) { b.addEventListener("click", function () { window.print(); }); });
  $$("[data-autosubmit]").forEach(function (i) { i.addEventListener("change", function () { i.form.submit(); }); });
  $$("form[data-confirm]").forEach(function (f) {
    f.addEventListener("submit", function (e) { if (!window.confirm(f.getAttribute("data-confirm"))) e.preventDefault(); });
  });
  $$("[data-cvss-toggle]").forEach(function (sel) {
    var field = $("[data-cvss-field]", sel.form);
    var sync = function () { if (field) field.hidden = sel.value !== "cvss"; };
    sel.addEventListener("change", sync); sync();
  });

  var live = $("#scan-live");
  if (!live) return;
  var logEl = $("#log"), list = $("#stages"), timer = null;
  function render(j) {
    var st = $("#scan-status");
    if (st) { st.textContent = j.status_text || j.status; st.className = "chip " + j.status; }
    list.innerHTML = "";
    j.stages.forEach(function (s) {
      var li = document.createElement("li");
      li.className = "stage " + s.status;
      li.innerHTML = '<span class="dot"></span><span class="what"><b></b><span class="mono"></span></span>' +
        '<span class="small muted"></span><progress max="100"></progress><span class="msg"></span>';
      $("b", li).textContent = s.label;
      $(".mono", li).textContent = s.target || "";
      $(".small", li).textContent = s.status_text || s.status;
      $("progress", li).value = s.progress || 0;
      $(".msg", li).textContent = s.message || "";
      list.appendChild(li);
    });
    (j.upcoming || []).forEach(function (s) {
      var li = document.createElement("li");
      li.className = "stage pending";
      li.innerHTML = '<span class="dot"></span><span class="what"><b></b></span><span class="small muted"></span>';
      $("b", li).textContent = s.label;
      $(".small", li).textContent = j.pending_text || "pending";
      list.appendChild(li);
    });
    var atBottom = logEl.scrollHeight - logEl.scrollTop - logEl.clientHeight < 40;
    logEl.textContent = j.log.length ? j.log.join("\n") : (j.waiting_text || "Waiting for output…");
    if (atBottom) logEl.scrollTop = logEl.scrollHeight;
    if (["completed", "failed", "cancelled"].indexOf(j.status) >= 0) {
      clearInterval(timer);
      if (live.getAttribute("data-done") !== "1") window.location.reload();
    }
  }
  function tick() {
    fetch(live.getAttribute("data-api"), { credentials: "same-origin", cache: "no-store" })
      .then(function (r) { return r.json(); }).then(render).catch(function () {});
  }
  tick();
  timer = setInterval(tick, 2000);
})();
