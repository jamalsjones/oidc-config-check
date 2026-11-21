(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var sourceUrl = null;

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }

  function run() {
    var r = OidcConfigCheck.check($("doc").value, { sourceUrl: sourceUrl });
    var out = $("results");
    out.textContent = "";
    out.appendChild(el("p", "label", "Findings"));
    if (r.config && r.config.issuer) {
      var who = el("p", null);
      who.style.margin = "0 0 12px";
      who.appendChild(document.createTextNode("Issuer "));
      who.appendChild(el("code", null, String(r.config.issuer)));
      out.appendChild(who);
    }
    var sum = el("div", "summary");
    if (r.summary.error === 0) sum.appendChild(el("span", "count ok", "No errors"));
    else sum.appendChild(el("span", "count error", r.summary.error + (r.summary.error === 1 ? " error" : " errors")));
    if (r.summary.warn) sum.appendChild(el("span", "count warn", r.summary.warn + (r.summary.warn === 1 ? " warning" : " warnings")));
    if (r.summary.info) sum.appendChild(el("span", "count info", r.summary.info + (r.summary.info === 1 ? " note" : " notes")));
    out.appendChild(sum);
    var ul = el("ul", "findings");
    r.findings.forEach(function (f) {
      var li = el("li", "finding " + f.level);
      var head = el("div", "head");
      head.appendChild(el("span", "lvl", f.level === "warn" ? "warning" : f.level === "info" ? "note" : "error"));
      if (f.field) head.appendChild(el("code", null, f.field));
      li.appendChild(head);
      li.appendChild(el("p", null, f.message));
      if (f.ref) li.appendChild(el("div", "ref", f.ref));
      ul.appendChild(li);
    });
    out.appendChild(ul);
  }

  function loadSample(name) {
    sourceUrl = null;
    fetch("examples/" + name + ".json")
      .then(function (r) { return r.text(); })
      .then(function (t) { $("doc").value = t; run(); });
  }

  $("fetch").addEventListener("click", function () {
    var url = OidcConfigCheck.wellKnownUrl($("url").value);
    if (!url) return;
    var note = $("fetch-note");
    note.textContent = "Fetching " + url + " ...";
    fetch(url, { headers: { accept: "application/json" } })
      .then(function (res) {
        if (!res.ok) throw new Error("HTTP " + res.status);
        return res.text();
      })
      .then(function (text) {
        sourceUrl = url;
        $("doc").value = text;
        note.textContent = "Fetched " + url + ".";
        run();
      })
      .catch(function () {
        note.textContent = "Couldn't fetch " + url + ". The provider may block requests from other sites (CORS). Open that URL in a new tab, copy the JSON and paste it below.";
      });
  });
  $("url").addEventListener("keydown", function (e) { if (e.key === "Enter") $("fetch").click(); });
  $("check").addEventListener("click", function () { run(); });
  $("doc").addEventListener("input", function () { sourceUrl = null; });
  $("sample-legacy").addEventListener("click", function () { loadSample("legacy"); });
  $("sample-modern").addEventListener("click", function () { loadSample("modern"); });
})();
