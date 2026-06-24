/* ============================================================
   AIHarness — architecture pipeline animation + nav + reveal
   Vanilla JS, no dependencies. Respects prefers-reduced-motion.

   RENDERING GUARANTEE:
   - The diagram is built inside init(), which runs on
     DOMContentLoaded (or immediately if the DOM is already
     parsed). It is NOT gated behind an IntersectionObserver,
     so nodes/edges/detail render reliably on load.
   - Scroll-reveal is progressive enhancement only: a load
     event + a setTimeout fallback force every .reveal element
     visible, so nothing can stay hidden if the observer fails.
   ============================================================ */
(function () {
  "use strict";

  var reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ---------- pipeline data ---------- */
  var STAGES = [
    {
      stage: "Inputs",
      sub: "Paste · Git URL · CI/CD API · PR webhook",
      detail: "A scan starts from anywhere it's needed: pasted source, a Git repository URL, a call from your CI/CD pipeline, or a pull-request webhook that gates a merge.",
      standards: ["SSDF SP 800-218", "CI/PR gate"]
    },
    {
      stage: "Orchestrator",
      sub: "Hono Worker · validate · envelope-encrypt key · enqueue",
      detail: "A Cloudflare Worker running Hono validates the request, envelope-encrypts your BYO model key, and enqueues the job. It never persists the plaintext key.",
      standards: ["ASVS 5.0", "ISO/IEC 27001"]
    },
    {
      stage: "Queue",
      sub: "Cloudflare Queue · durable, fail-fast hand-off",
      detail: "The job is handed to a Cloudflare Queue for durable, decoupled processing. Configuration fails fast and honestly rather than silently degrading.",
      standards: ["NIST CSF 2.0"]
    },
    {
      stage: "ScanRunner",
      sub: "Durable Object + Container · Semgrep deterministic SAST",
      detail: "A Durable Object drives a Container running Semgrep: deterministic static analysis with stable, pinnable rule IDs. Same code in, same findings out — fully reproducible and auditable.",
      standards: ["CWE", "CWE Top 25", "SARIF 2.1.0"]
    },
    {
      stage: "AI Triage",
      sub: "Model-agnostic adapter · Claude / OpenAI / Gemini · evidence-based confidence",
      detail: "A model-agnostic adapter triages findings: CWE-grounded, code-as-data (prompt-injection defense), evidence-based confidence, and a never-hard-fail posture. The model fills a strict JSON schema only.",
      standards: ["OWASP LLM Top 10", "NIST AI RMF", "ISO/IEC 42001"]
    },
    {
      stage: "Output",
      sub: "SARIF 2.1.0 · findings · immutable audit log",
      detail: "Results emit as SARIF 2.1.0 plus structured findings and an immutable audit log (model id, version, prompt hash, ruleset versions) — reproducible and defensible.",
      standards: ["SARIF 2.1.0 (OASIS)", "Immutable audit log"]
    }
  ];

  function buildArchitecture() {
    var track = document.getElementById("arch-track");
    if (!track) return;

    // Guard against double-build if init somehow runs twice.
    if (track.dataset.built === "1") return;
    track.dataset.built = "1";

    var nodes = [];

    STAGES.forEach(function (s, i) {
      var stage = document.createElement("div");
      stage.className = "arch-stage";
      stage.setAttribute("role", "listitem");

      // 3D connector that links this stage to the next (energy travels along it)
      if (i < STAGES.length - 1) {
        var link = document.createElement("span");
        link.className = "arch-link";
        link.setAttribute("aria-hidden", "true");
        var packet = document.createElement("span");
        packet.className = "arch-link-packet";
        link.appendChild(packet);
        stage.appendChild(link);
      }

      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "arch-node";
      btn.setAttribute("aria-label", "0" + (i + 1) + " " + s.stage + " — " + s.sub);

      // extruded 3D faces (top edge-light + side walls give real depth)
      var faceTop = document.createElement("span");
      faceTop.className = "node-face node-face-top";
      faceTop.setAttribute("aria-hidden", "true");
      btn.appendChild(faceTop);

      var faceSide = document.createElement("span");
      faceSide.className = "node-face node-face-side";
      faceSide.setAttribute("aria-hidden", "true");
      btn.appendChild(faceSide);

      var faceBottom = document.createElement("span");
      faceBottom.className = "node-face node-face-bottom";
      faceBottom.setAttribute("aria-hidden", "true");
      btn.appendChild(faceBottom);

      var content = document.createElement("span");
      content.className = "node-content";

      var dot = document.createElement("span");
      dot.className = "node-dot";
      dot.setAttribute("aria-hidden", "true");
      content.appendChild(dot);

      var stageLabel = document.createElement("span");
      stageLabel.className = "node-stage";
      stageLabel.textContent = "0" + (i + 1) + " · " + s.stage;
      content.appendChild(stageLabel);

      var sub = document.createElement("span");
      sub.className = "node-sub";
      sub.textContent = s.sub;
      content.appendChild(sub);

      btn.appendChild(content);

      // per-node hover/focus OVERLAY tooltip (detail + standards) — does not
      // take layout space, so the default (no-hover) state still fits one screen
      var tip = document.createElement("span");
      tip.className = "node-tip";
      tip.setAttribute("role", "tooltip");

      var tipP = document.createElement("span");
      tipP.className = "node-tip-detail";
      tipP.textContent = s.detail;
      tip.appendChild(tipP);

      var tipUl = document.createElement("span");
      tipUl.className = "node-tip-standards";
      s.standards.forEach(function (label) {
        var chip = document.createElement("span");
        chip.className = "node-tip-chip";
        chip.textContent = label;
        tipUl.appendChild(chip);
      });
      tip.appendChild(tipUl);
      btn.appendChild(tip);

      function activate() {
        nodes.forEach(function (n, idx) { n.classList.toggle("active", idx === i); });
      }
      btn.addEventListener("click", activate);
      btn.addEventListener("mouseenter", activate);
      btn.addEventListener("focus", activate);
      btn.addEventListener("mouseleave", function () { btn.classList.remove("active"); });
      btn.addEventListener("blur", function () { btn.classList.remove("active"); });

      stage.appendChild(btn);
      track.appendChild(stage);
      nodes.push(btn);
    });

    /* ---------- looping pulse animation ---------- */
    if (!reduceMotion) {
      var STEP_MS = 1150;     // dwell per stage
      var rafId = null;
      var startTs = null;
      var lit = -1;

      function loop(ts) {
        if (startTs === null) { startTs = ts; }
        var elapsed = ts - startTs;
        var cycle = nodes.length * STEP_MS;
        var phase = (elapsed % cycle) / STEP_MS;   // 0 .. nodes.length
        var cur = Math.floor(phase) % nodes.length;
        var frac = phase - Math.floor(phase);      // 0..1 within current stage

        if (cur !== lit) {
          nodes.forEach(function (n, idx) { n.classList.toggle("lit", idx === cur); });
          // light the connector leaving the previous node as the packet arrives
          var links = track.querySelectorAll(".arch-link");
          links.forEach(function (l, idx) { l.classList.toggle("flowing", idx === cur); });
          lit = cur;
        }
        // drive the packet position along the active connector via CSS var
        track.style.setProperty("--flow", frac.toFixed(3));

        rafId = requestAnimationFrame(loop);
      }
      rafId = requestAnimationFrame(loop);

      // pause loop when section off-screen to save cycles (build already done)
      if ("IntersectionObserver" in window) {
        var archSection = document.getElementById("architecture");
        if (archSection) {
          var io = new IntersectionObserver(function (entries) {
            entries.forEach(function (e) {
              if (e.isIntersecting && rafId === null) { startTs = null; rafId = requestAnimationFrame(loop); }
              else if (!e.isIntersecting && rafId !== null) { cancelAnimationFrame(rafId); rafId = null; }
            });
          }, { threshold: 0.02 });
          io.observe(archSection);
        }
      }
    } else {
      // reduced motion: show the final lit state, all connectors complete
      nodes.forEach(function (n) { n.classList.add("lit"); });
      track.querySelectorAll(".arch-link").forEach(function (l) { l.classList.add("flowing"); });
      track.style.setProperty("--flow", "1");
    }
  }

  /* ---------- mobile nav toggle ---------- */
  function wireNav() {
    var navToggle = document.getElementById("nav-toggle");
    var navLinks = document.getElementById("nav-links");
    if (navToggle && navLinks) {
      navToggle.addEventListener("click", function () {
        var open = navLinks.classList.toggle("open");
        navToggle.setAttribute("aria-expanded", open ? "true" : "false");
      });
      navLinks.addEventListener("click", function (e) {
        if (e.target.tagName === "A") {
          navLinks.classList.remove("open");
          navToggle.setAttribute("aria-expanded", "false");
        }
      });
    }
  }

  /* ---------- scroll reveal (progressive enhancement) ---------- */
  function revealAll(reveals) {
    reveals.forEach(function (el) { el.classList.add("in"); });
  }

  function wireReveal() {
    var reveals = Array.prototype.slice.call(document.querySelectorAll(".reveal"));

    if (reduceMotion || !("IntersectionObserver" in window)) {
      revealAll(reveals);
      return;
    }

    var ro = new IntersectionObserver(function (entries, obs) {
      entries.forEach(function (e) {
        if (e.isIntersecting) { e.target.classList.add("in"); obs.unobserve(e.target); }
      });
    }, { threshold: 0.08, rootMargin: "0px 0px -6% 0px" });
    reveals.forEach(function (el) { ro.observe(el); });

    // SAFETY NET 1: once everything has loaded, force-reveal anything
    // still hidden (e.g. if the observer never fired).
    window.addEventListener("load", function () {
      setTimeout(function () { revealAll(reveals); }, 600);
    });
    // SAFETY NET 2: hard timeout regardless of load event, so nothing
    // can ever stay invisible.
    setTimeout(function () { revealAll(reveals); }, 2500);
  }

  /* ---------- init ---------- */
  function init() {
    buildArchitecture();
    wireNav();
    wireReveal();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
