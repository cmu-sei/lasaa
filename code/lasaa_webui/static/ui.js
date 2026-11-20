// <legal>
// LASAA tool
//
// Copyright 2026 Carnegie Mellon University.
//
// NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
// INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
// UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS
// TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE
// OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE
// MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND
// WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
//
// Licensed under a MIT (SEI)-style license, please see License.txt or contact
// permission@sei.cmu.edu for full terms.
//
// [DISTRIBUTION STATEMENT A] This material has been approved for public
// release and unlimited distribution.  Please see Copyright notice for
// non-US Government use and distribution.
//
// This Software includes and/or makes use of Third-Party Software each subject
// to its own license.
//
// DM26-0426
// </legal>

// Keyboard shortcuts for the alert list and alert pages (the "Keys" help
// in base.html lists them).  Loaded as a file: the CSP forbids inline scripts.
(function () {
  "use strict";

  function $(sel) { return document.querySelector(sel); }
  function typing(el) {
    return el && (el.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName));
  }
  function follow(sel) {
    var a = $(sel);
    if (a && a.href) { window.location.href = a.href; return true; }
    return false;
  }
  function press(sel) {
    var el = $(sel);
    if (el) { el.click(); return true; }
    return false;
  }
  function toggleKeys(show) {
    var k = $("#keys");
    if (k) { k.hidden = (show === undefined) ? !k.hidden : !show; }
  }

  // Alert list: j/k move a selection over the rows; Enter or o opens it.
  var sel = -1;
  function rows() { return document.querySelectorAll("#alerts tr[data-href]"); }
  function select(i) {
    var rs = rows();
    if (!rs.length) { return; }
    sel = Math.max(0, Math.min(rs.length - 1, i));
    rs.forEach(function (r, j) { r.classList.toggle("sel", j === sel); });
    rs[sel].scrollIntoView({block: "nearest"});
  }

  // The "Run LASAA on the checked alerts" button: the count, and disabled
  // while nothing is checked.
  function updatePick() {
    var b = $("#pick-btn");
    if (!b) { return; }
    var n = document.querySelectorAll("#alerts input[name=pick]:checked").length;
    b.disabled = n === 0;
    b.textContent = n ? "Run LASAA on the " + n + " checked alert" + (n === 1 ? "" : "s") + "\u2026"
                      : "Run LASAA on the checked alerts\u2026";
  }

  // Alert page: [ and ] step through the trace markers.
  var step = -1;
  function goStep(delta) {
    var steps = document.querySelectorAll("table.code tr.step");
    if (!steps.length) { return; }
    step = Math.max(0, Math.min(steps.length - 1, step + delta));
    steps.forEach(function (r, j) { r.classList.toggle("step-current", j === step); });
    steps[step].scrollIntoView({block: "center"});
  }

  function chooseVerdict(v) {
    var radio = document.getElementById("v-" + v);
    if (!radio) { return false; }
    radio.checked = true;
    var note = $("#note");
    if (note) { note.focus(); }
    return true;
  }

  document.addEventListener("keydown", function (e) {
    var page = document.body.dataset.page;
    var t = e.target;
    if (e.key === "Enter" && (e.ctrlKey || e.metaKey) && t.form && t.form.id === "review-form") {
      e.preventDefault();
      press("#save-next-btn");
      return;
    }
    // Ctrl+Enter in an "Ask an LLM" question sends it (htmx handles the submit).
    if (e.key === "Enter" && (e.ctrlKey || e.metaKey) && t.form && t.form.hasAttribute("data-chat")) {
      e.preventDefault();
      t.form.requestSubmit();
      return;
    }
    // Enter in a saved config's name or a test prompt presses its own
    // button (Save config, Send), not the form's "Prepare the run".
    var own = e.key === "Enter" && t.tagName === "INPUT" && t.closest("[data-no-estimate]");
    if (own) {
      e.preventDefault();
      var b = own.querySelector("button");
      if (b) { b.click(); }
      return;
    }
    if (e.key === "Escape") {
      if (typing(t)) { t.blur(); }
      toggleKeys(false);
      return;
    }
    if (typing(t) || e.ctrlKey || e.metaKey || e.altKey) { return; }

    var done = false;
    switch (e.key) {
      case "?": toggleKeys(); done = true; break;
      case "b": done = press("#blind-btn"); break;
      case "/":
        var q = $("#filters input[name=q]");
        var back = $("#list-link");
        if (q) { q.focus(); q.select(); done = true; }
        else if (back) { window.location.href = back.href + "#search"; done = true; }
        break;
    }
    if (!done && page === "list") {
      if (e.key === "j") { select(sel + 1); done = true; }
      else if (e.key === "k") { select(sel - 1); done = true; }
      else if (e.key === "x" && sel >= 0 && rows()[sel]) {
        var box = rows()[sel].querySelector("input[type=checkbox]");
        if (box) { box.checked = !box.checked; updatePick(); }
        done = true;
      }
      else if ((e.key === "Enter" || e.key === "o") && sel >= 0 && rows()[sel]) {
        window.location.href = rows()[sel].dataset.href;
        done = true;
      }
    }
    if (!done && page === "alert") {
      switch (e.key) {
        case "j": done = follow("a[rel=next]"); break;
        case "k": done = follow("a[rel=prev]"); break;
        case "c": done = press("#confirm-btn"); break;
        case "t": done = chooseVerdict("true"); break;
        case "f": done = chooseVerdict("false"); break;
        case "d": done = chooseVerdict("dependent"); break;
        case "u": done = chooseVerdict("uncertain"); break;
        case "n": var n = $("#note"); if (n) { n.focus(); done = true; } break;
        case "a": var ask = $("#chat-question"); if (ask) { ask.focus(); done = true; } break;
        case "e": done = follow("#editor-link"); break;
        case "[": goStep(-1); done = true; break;
        case "]": goStep(1); done = true; break;
      }
    }
    if (done) { e.preventDefault(); }
  });

  document.addEventListener("click", function (e) {
    if (e.target && e.target.id === "keys-btn") { toggleKeys(); }
    // "Use it" buttons (the build-command hint) fill in a field.
    var fill = e.target && e.target.getAttribute && e.target.getAttribute("data-fill");
    if (fill) {
      var f = $(fill);
      if (f) { f.value = e.target.getAttribute("data-value"); f.focus(); }
      var check = $(e.target.getAttribute("data-check") || "#none");
      if (check) { check.checked = true; }
    }
    // An example button (the new-snapshot form) fills in several fields of
    // its form: {field name: value}; a radio group's value checks that radio.
    var preset = e.target && e.target.closest && e.target.closest("[data-preset]");
    if (preset) {
      var form = preset.closest("form");
      var values = JSON.parse(preset.getAttribute("data-preset"));
      Object.keys(values).forEach(function (name) {
        var el = form && form.elements[name];
        if (el) { el.value = values[name]; }
      });
      // So that the build hint for the directory follows (htmx, on change).
      var origin = form && form.elements.origin;
      if (origin) { origin.dispatchEvent(new Event("change", {bubbles: true})); }
    }
  });
  // A plain (non-htmx) form with data-confirm asks before it is sent.
  document.addEventListener("submit", function (e) {
    var msg = e.target && e.target.getAttribute && e.target.getAttribute("data-confirm");
    if (msg && !window.confirm(msg)) { e.preventDefault(); }
  });
  // Typing a build command chooses "Build with command".
  document.addEventListener("input", function (e) {
    if (e.target && e.target.id === "build-command" && $("#build-yes")) {
      $("#build-yes").checked = true;
    }
  });
  document.addEventListener("change", function (e) {
    if (e.target && e.target.name === "pick") { updatePick(); }
    if (e.target && e.target.name === "model_key") { fillSaved(); }
    if (e.target && /^(model_key|provider|region|prefix)$/.test(e.target.name)) { modelPanel(); }
  });

  // The run form's Model panel: show the fields that go with the chosen
  // model and provider (data-show-custom, data-providers="A|B",
  // data-custom-of="select name", data-show-saved).
  function modelPanel() {
    var key = $("select[name=model_key]");
    if (!key) { return; }
    var opt = key.options[key.selectedIndex];
    var custom = key.value === "custom";
    var provider = custom ? $("select[name=provider]").value : opt.getAttribute("data-provider");
    var each = function (sel, fn) { Array.prototype.forEach.call(document.querySelectorAll(sel), fn); };
    each("[data-show-custom]", function (el) { el.hidden = !custom; });
    each("[data-show-saved]", function (el) { el.hidden = key.value.indexOf("saved:") !== 0; });
    each("[data-providers]", function (el) {
      el.hidden = el.getAttribute("data-providers").split("|").indexOf(provider) < 0;
    });
    each("[data-custom-of]", function (el) {
      var s = $("select[name=" + el.getAttribute("data-custom-of") + "]");
      el.hidden = !s || s.value !== "custom";
    });
  }
  // Choosing a saved config fills in its run settings, which stay editable.
  function fillSaved() {
    var key = $("select[name=model_key]");
    var opt = key && key.options[key.selectedIndex];
    var json = opt && opt.getAttribute("data-spec");
    if (!json) { return; }
    var spec = JSON.parse(json);
    var choose = function (name, value, customName) {
      var s = $("select[name=" + name + "]");
      if (!s) { return; }
      var known = Array.prototype.some.call(s.options, function (o) { return o.value === value; });
      s.value = known ? value : "custom";
      if (!known && customName) { $("input[name=" + customName + "]").value = value; }
    };
    choose("effort", spec.effort || "");
    choose("region", spec.region, "region_custom");
    choose("prefix", spec.prefix || "auto", "prefix_custom");
    $("input[name=flex]").checked = !!spec.flex;
    $("input[name=concurrency]").value = spec.concurrency;
  }
  // Typing a saved config's name or a test prompt isn't a change to the
  // run, so it mustn't refresh the estimate (or take back a prepared run).
  ["input", "change"].forEach(function (type) {
    document.addEventListener(type, function (e) {
      if (e.target && e.target.closest && e.target.closest("[data-no-estimate]")) {
        e.stopPropagation();
      }
    }, true);
  });
  // A job's log is replaced every few seconds while it runs.  Keep its
  // scroll position, and follow the end of the log if it was at the end.
  var logState = null;
  function restoreLog() {
    var l = $("pre.log");
    if (!l) { return; }
    l.scrollTop = (!logState || logState.atEnd) ? l.scrollHeight : logState.top;
  }
  document.addEventListener("htmx:beforeSwap", function () {
    var l = $("pre.log");
    logState = l ? {top: l.scrollTop,
                    atEnd: l.scrollHeight - l.scrollTop - l.clientHeight < 8} : null;
  });
  // The list is replaced when the filters change; start the selection over.
  document.addEventListener("htmx:afterSwap", function (e) {
    sel = -1; updatePick(); restoreLog();
    if (e.detail && e.detail.target && e.detail.target.id === "model-choice") {
      // A saved config was saved or deleted: the model list was replaced.
      fillSaved();
      modelPanel();
      var key = $("select[name=model_key]");
      if (key) { key.dispatchEvent(new Event("input", {bubbles: true})); }
    }
  });
  updatePick();
  restoreLog();
  modelPanel();
  // "/" on an alert page comes back to the list at #search.
  if (window.location.hash === "#search") {
    var q = $("#filters input[name=q]");
    if (q) { q.focus(); q.select(); }
  }
})();
