/* ============================================================
   AIHarness — live demo, Matrix-terminal edition.
   Calls the real /api/* contract.

   API CONTRACT:
   - POST /api/scans  { language, files:[{path,content}] }
       apiKey is OMITTED by default (server uses a configured
       demo key). Only included if the user opens the "advanced"
       disclosure and types one. -> 202 { id }
   - GET  /api/scans/:id        -> { scan:{status}, findings:[] }
   - GET  /api/scans/:id/sarif  -> SARIF download

   SECURITY: finding fields derive from UNTRUSTED scanned code.
   They are rendered with createTextNode / textContent ONLY.
   No finding field is ever interpolated into innerHTML.
   severity/confidence/verdict are validated against allowlists
   before being used in className tokens.
   ============================================================ */
(function () {
  "use strict";

  var $ = function (id) { return document.getElementById(id); };

  var form        = $("scan-form");
  var scanBtn     = $("scan");
  var loadBtn     = $("load-sample");
  var langSel     = $("language");
  var keyInput    = $("apiKey");        // inside the optional <details>
  var codeArea    = $("code");

  /* ---------- input mode: "Paste code" vs "GitHub repo URL" ---------- */
  var modePasteBtn = $("mode-paste");
  var modeRepoBtn  = $("mode-repo");
  var panelPaste   = $("panel-paste");
  var panelRepo    = $("panel-repo");
  var repoUrlInput = $("repo-url");

  var inputMode = "paste"; // "paste" | "repo"

  function setMode(mode) {
    inputMode = mode;
    var isPaste = mode === "paste";
    if (modePasteBtn) {
      modePasteBtn.classList.toggle("mode-btn-active", isPaste);
      modePasteBtn.setAttribute("aria-pressed", isPaste ? "true" : "false");
    }
    if (modeRepoBtn) {
      modeRepoBtn.classList.toggle("mode-btn-active", !isPaste);
      modeRepoBtn.setAttribute("aria-pressed", isPaste ? "false" : "true");
    }
    if (panelPaste) panelPaste.hidden = !isPaste;
    if (panelRepo)  panelRepo.hidden  = isPaste;
    if (loadBtn)    loadBtn.hidden    = !isPaste;
  }

  if (modePasteBtn) modePasteBtn.addEventListener("click", function () { setMode("paste"); });
  if (modeRepoBtn)  modeRepoBtn.addEventListener("click", function () { setMode("repo"); });

  var termBody    = $("term-body");
  var termLines   = $("term-lines");
  var termCursor  = $("term-cursor");

  var findingsHead  = $("findings-head");
  var findingsCount = $("findings-count");
  var sarifLink     = $("sarif");

  var reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ---------- allowlists (validate untrusted values before className use) ---------- */
  var CONF    = ["low", "medium", "high"];
  var SEV     = ["info", "low", "medium", "high", "critical"];
  var VERDICT = ["confirmed", "refuted", "uncertain"];

  /* ---------- planted-vulnerability sample (Python) ---------- */
  var SAMPLE = [
    "import subprocess",
    "import sqlite3",
    "from flask import Flask, request",
    "",
    "app = Flask(__name__)",
    "",
    "@app.route('/ping')",
    "def ping():",
    "    host = request.args.get('host')",
    "    # CWE-78: OS command injection via shell=True with untrusted input",
    "    return subprocess.check_output('ping -c 1 ' + host, shell=True)",
    "",
    "@app.route('/user')",
    "def get_user():",
    "    uid = request.args.get('id')",
    "    conn = sqlite3.connect('app.db')",
    "    cur = conn.cursor()",
    "    # CWE-89: SQL injection via string concatenation",
    "    cur.execute(\"SELECT * FROM users WHERE id = '\" + uid + \"'\")",
    "    return str(cur.fetchall())",
    ""
  ].join("\n");

  // Default the textarea to the planted-vuln sample so the demo just works.
  if (codeArea && !codeArea.value.trim()) codeArea.value = SAMPLE;

  if (loadBtn && codeArea) {
    loadBtn.addEventListener("click", function () {
      if (langSel) langSel.value = "python";
      codeArea.value = SAMPLE;
      codeArea.focus();
    });
  }

  /* ============================================================
     TERMINAL OUTPUT — streamed lines + blinking cursor.
     Each line is a styled <span class="term-line ...">. All
     dynamic/untrusted text goes through textContent only.
     ============================================================ */
  function scrollTerm() { if (termBody) termBody.scrollTop = termBody.scrollHeight; }

  function moveCursorToEnd() {
    if (termCursor && termLines && termLines.parentNode) {
      termLines.parentNode.appendChild(termCursor); // keep cursor after the lines
    }
  }

  // Append a plain line (string parts only -> textContent). Returns the element.
  function line(cls, text) {
    var el = document.createElement("span");
    el.className = "term-line" + (cls ? " " + cls : "");
    if (text != null) el.textContent = text;
    termLines.appendChild(el);
    moveCursorToEnd();
    scrollTerm();
    return el;
  }

  // Append a finding line built from tokens. tokens = array of
  // { text, cls } — text is textContent only; cls is from an allowlist.
  function tokenLine(rootCls, tokens) {
    var el = document.createElement("span");
    el.className = "term-line" + (rootCls ? " " + rootCls : "");
    tokens.forEach(function (t) {
      if (t.cls) {
        var s = document.createElement("span");
        s.className = "tok " + t.cls;
        s.textContent = t.text;
        el.appendChild(s);
      } else {
        el.appendChild(document.createTextNode(t.text));
      }
    });
    termLines.appendChild(el);
    moveCursorToEnd();
    scrollTerm();
    return el;
  }

  function clearTerm() {
    if (termLines) termLines.replaceChildren();
    moveCursorToEnd();
  }

  /* ---------- typewriter for the command line (decorative) ---------- */
  function typeCommand(text, done) {
    var el = document.createElement("span");
    el.className = "term-line t-cmd";
    var prompt = document.createElement("span");
    prompt.className = "prompt";
    prompt.textContent = "$ ";
    el.appendChild(prompt);
    var rest = document.createTextNode("");
    el.appendChild(rest);
    termLines.appendChild(el);
    moveCursorToEnd();

    if (reduceMotion) { rest.textContent = text; scrollTerm(); if (done) done(); return; }

    var i = 0;
    (function step() {
      rest.textContent = text.slice(0, i);
      scrollTerm();
      if (i < text.length) { i++; setTimeout(step, 22); }
      else if (done) done();
    })();
  }

  /* ---------- status -> terminal mapping ---------- */
  var STATUS_LABEL = {
    queued:    "queued",
    scanning:  "scanning (semgrep)",
    triaging:  "triaging (model-agnostic)",
    completed: "completed",
    failed:    "failed"
  };

  /* ============================================================
     CODE RAIN — performant requestAnimationFrame canvas behind
     the terminal text. Dimmed via CSS opacity so text stays
     readable. Paused / static under prefers-reduced-motion.
     ============================================================ */
  (function codeRain() {
    var canvas = $("rain");
    var term = $("terminal");
    if (!canvas || !term) return;
    var ctx = canvas.getContext("2d");
    if (!ctx) return;

    var GLYPHS = "ｱｲｳｴｵｶｷｸ01<>=/{}[]#$*+-".split("");
    var fontSize = 14;
    var cols = 0, drops = [], dpr = 1;

    function resize() {
      var w = term.clientWidth, h = term.clientHeight;
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = w * dpr; canvas.height = h * dpr;
      canvas.style.width = w + "px"; canvas.style.height = h + "px";
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      cols = Math.max(1, Math.floor(w / fontSize));
      drops = new Array(cols);
      for (var i = 0; i < cols; i++) drops[i] = Math.random() * (h / fontSize);
    }

    function frame() {
      var w = term.clientWidth, h = term.clientHeight;
      // translucent fade for trails
      ctx.fillStyle = "rgba(10,15,10,0.10)";
      ctx.fillRect(0, 0, w, h);
      ctx.font = fontSize + "px monospace";
      for (var i = 0; i < cols; i++) {
        var ch = GLYPHS[(Math.random() * GLYPHS.length) | 0];
        var x = i * fontSize;
        var y = drops[i] * fontSize;
        // brighter head, dim trail
        ctx.fillStyle = Math.random() > 0.975 ? "#aaffcc" : "#1f8f4a";
        ctx.fillText(ch, x, y);
        if (y > h && Math.random() > 0.975) drops[i] = 0;
        drops[i] += 0.5 + Math.random() * 0.35;
      }
    }

    var rafId = null;
    function start() { if (rafId === null) loop(); }
    function stop() { if (rafId !== null) { cancelAnimationFrame(rafId); rafId = null; } }
    function loop() { frame(); rafId = requestAnimationFrame(loop); }

    resize();
    window.addEventListener("resize", function () { resize(); });

    if (reduceMotion) {
      // static, dim single pass — no animation
      ctx.fillStyle = "rgba(10,15,10,1)"; ctx.fillRect(0, 0, term.clientWidth, term.clientHeight);
      ctx.font = fontSize + "px monospace"; ctx.fillStyle = "#185f33";
      for (var i = 0; i < cols; i++) {
        ctx.fillText(GLYPHS[(Math.random() * GLYPHS.length) | 0], i * fontSize, (Math.random() * term.clientHeight));
      }
      return;
    }

    // run only while the terminal is on-screen
    if ("IntersectionObserver" in window) {
      var io = new IntersectionObserver(function (entries) {
        entries.forEach(function (e) { if (e.isIntersecting) start(); else stop(); });
      }, { threshold: 0.02 });
      io.observe(term);
    } else {
      start();
    }
  })();

  /* ============================================================
     FINDINGS — stream each finding as terminal lines (XSS-safe).
     ============================================================ */
  function streamFindings(findings) {
    var count = Array.isArray(findings) ? findings.length : 0;

    line("t-rule", "── findings ──────────────────────────────");

    if (!count) {
      line("t-ok", "> no findings. scanner + triage found nothing to report.");
      return;
    }

    findings.forEach(function (f) {
      var sev     = SEV.indexOf(f && f.severity) !== -1 ? f.severity : null;
      var conf    = CONF.indexOf(f && f.confidence) !== -1 ? f.confidence : null;
      var verdict = VERDICT.indexOf(f && f.verdict) !== -1 ? f.verdict : null;

      var verdictText = verdict ? verdict.toUpperCase() : "UNVERIFIED";
      var verdictCls  = verdict === "confirmed" ? "tok-confirmed"
                      : verdict === "refuted"   ? "tok-refuted"
                      : verdict === "uncertain" ? "tok-uncertain"
                      : "tok-needsreview";

      var cwe  = (f && f.cwe != null) ? String(f.cwe) : "CWE:n/a";
      var file = (f && f.file != null) ? String(f.file) : "(unknown)";
      var ln   = (f && f.startLine != null) ? String(f.startLine) : "?";

      // [VERDICT] CWE-78  high   conf=high   app.py:3  message
      tokenLine(null, [
        { text: "> [" },
        { text: verdictText, cls: verdictCls },
        { text: "] " },
        { text: pad(cwe, 8) },
        { text: " " },
        { text: pad(sev || "n/a", 8), cls: sev ? ("tok-" + sev) : "tok-needsreview" },
        { text: " conf=" },
        { text: pad(conf || "n/a", 6), cls: conf === "high" ? "tok-confirmed" : conf === "medium" ? "tok-uncertain" : "tok-needsreview" },
        { text: " " },
        { text: file + ":" + ln + "  " },
        { text: (f && f.message) ? String(f.message) : (f && f.explanation ? String(f.explanation) : "") }
      ]);

      // honest "needs review" tag for LLM-only / non-confirmed low-confidence
      if (conf !== "high" && verdict !== "confirmed") {
        tokenLine("t-dim", [
          { text: "    └ " },
          { text: "needs review", cls: "tok-needsreview" },
          { text: " — not independently confirmed" }
        ]);
      }

      if (f && f.remediation) {
        line("t-fix", "    └ fix: " + String(f.remediation));
      } else if (f && f.explanation && f.message) {
        line("t-dim", "    └ " + String(f.explanation));
      }
    });
  }

  function pad(s, n) { s = String(s); while (s.length < n) s += " "; return s; }

  /* ============================================================
     SCAN FLOW
     ============================================================ */
  var polling = false;

  function setBusy(busy) {
    if (!scanBtn) return;
    scanBtn.disabled = busy;
    scanBtn.textContent = busy ? "Scanning…" : "Run scan";
  }

  if (form) {
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      if (polling) return;
      startScan();
    });
  }

  function startScan() {
    clearTerm();
    if (findingsHead) findingsHead.hidden = true;
    if (sarifLink) sarifLink.hidden = true;

    var lang = langSel ? langSel.value : "python";
    var userKey = keyInput && keyInput.value ? keyInput.value.trim() : "";
    var body, cmdLabel;

    if (inputMode === "repo") {
      // GitHub repo URL mode
      var repoUrl = repoUrlInput ? repoUrlInput.value.trim() : "";
      if (!repoUrl) {
        line("t-err", "$ error: enter a GitHub repository URL (e.g. https://github.com/owner/repo).");
        return;
      }
      body = { language: lang, repoUrl: repoUrl };
      if (userKey) body.apiKey = userKey;
      cmdLabel = "aiharness scan --repo " + repoUrl;
    } else {
      // Paste code mode (existing behaviour)
      var code = codeArea ? codeArea.value.trim() : "";
      if (!code) {
        line("t-err", "$ error: add some source code to scan (or click \"Load sample\").");
        return;
      }
      var ext = { python: "py", javascript: "js", java: "java", go: "go" }[lang] || "txt";
      var fileName = "app." + ext;
      body = { language: lang, files: [{ path: fileName, content: code }] };
      if (userKey) body.apiKey = userKey;
      cmdLabel = "aiharness scan " + fileName;
    }

    setBusy(true);
    polling = true;

    // Build request body. apiKey OMITTED by default; only include it if the
    // user opened the advanced disclosure and typed a non-empty key.

    typeCommand(cmdLabel, function () {
      if (userKey) line("t-dim", "> using your Anthropic key (envelope-encrypted · shredded after scan)");
      else         line("t-dim", "> using configured demo key (no key required)");

      fetch("/api/scans", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body)
      })
        .then(function (res) {
          if (!res.ok) {
            return res.text().then(function (t) {
              throw new Error("POST /api/scans .......... " + res.status + (t ? "  " + t : ""));
            });
          }
          return res.json();
        })
        .then(function (data) {
          if (!data || !data.id) throw new Error("unexpected response: missing scan id.");
          line("t-info", "> POST /api/scans ............ 202 queued");
          poll(data.id);
        })
        .catch(function (err) {
          line("t-err", "> " + (err && err.message ? err.message : "failed to submit scan."));
          setBusy(false);
          polling = false;
        });
    });
  }

  function poll(id) {
    var attempts = 0;
    var MAX = 75;        // ~150s at 2s interval (cold container boot can be 30-60s+)
    var INTERVAL = 2000;
    var lastStatus = null;

    function tick() {
      attempts++;
      fetch("/api/scans/" + encodeURIComponent(id))
        .then(function (res) {
          if (!res.ok) {
            return res.text().then(function (t) {
              throw new Error("GET /api/scans/:id ......... " + res.status + (t ? "  " + t : ""));
            });
          }
          return res.json();
        })
        .then(function (data) {
          var scan = data && data.scan ? data.scan : {};
          var status = scan.status || "unknown";
          var findings = data && data.findings ? data.findings : [];

          // stream each status CHANGE as a terminal line
          if (status !== lastStatus) {
            lastStatus = status;
            var label = STATUS_LABEL[status] || status;
            if (status === "completed") {
              line("t-ok", "> status: completed ...");
            } else if (status === "failed") {
              line("t-err", "> status: failed ...");
            } else {
              line("t-info", "> status: " + label + " ...");
            }
          }

          if (status === "completed") {
            streamFindings(findings);
            var url = "/api/scans/" + encodeURIComponent(id) + "/sarif";
            var n = Array.isArray(findings) ? findings.length : 0;
            tokenLine("t-link", [
              { text: "> SARIF 2.1.0 written · " + n + " result" + (n === 1 ? "" : "s") + " · [ download ]" }
            ]);
            if (sarifLink) {
              sarifLink.href = url;
              sarifLink.hidden = false;
            }
            if (findingsHead) {
              findingsHead.hidden = false;
              if (findingsCount) findingsCount.textContent = n === 1 ? "1 finding" : n + " findings";
            }
            setBusy(false);
            polling = false;
            return;
          }

          if (status === "failed") {
            line("t-err", "> scan failed. " + (scan.error ? String(scan.error) : "the job did not complete."));
            if (Array.isArray(findings) && findings.length) streamFindings(findings);
            setBusy(false);
            polling = false;
            return;
          }

          if (attempts >= MAX) {
            line("t-err", "> timed out after ~" + (MAX * 2) + "s. the job may still be running — try again shortly.");
            setBusy(false);
            polling = false;
            return;
          }
          setTimeout(tick, INTERVAL);
        })
        .catch(function (err) {
          // transient network error: retry until MAX before giving up
          if (attempts < MAX) {
            setTimeout(tick, INTERVAL);
            return;
          }
          line("t-err", "> " + (err && err.message ? err.message : "lost connection while polling."));
          setBusy(false);
          polling = false;
        });
    }

    setTimeout(tick, INTERVAL);
  }
})();
