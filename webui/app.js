/* recon-one console — no framework, no build step.
   Every value that reaches the DOM goes through textContent; the only innerHTML use is
   for elements created from static template strings with no interpolated data. */

(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);

  const api = async (path, opts = {}) => {
    const res = await fetch(path, {
      credentials: "same-origin",
      headers: Object.assign({ "X-Recon-Request": "1" }, opts.body ? { "Content-Type": "application/json" } : {}),
      ...opts,
      body: opts.body ? JSON.stringify(opts.body) : undefined,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const err = new Error(data.error || `HTTP ${res.status}`);
      err.status = res.status;
      throw err;
    }
    return data;
  };

  const state = {
    configured: false,
    authed: false,
    rememberDays: 30,
    job: null,
    since: 0,
    timer: null,
    report: null,
    runs: [],
    selected: "",
    view: "scan",
    lastTargets: "",
    lastJobState: "",
    booted: false,
    compareLoading: false,
  };

  const el = (tag, cls, text) => {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) node.textContent = text;
    return node;
  };

  /* ───────────────────────────── toast ───────────────────────────── */

  let toastTimer = null;
  const toast = (message, kind = "info") => {
    const node = $("toast");
    node.textContent = message;
    node.dataset.kind = kind;
    node.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { node.hidden = true; }, 2600);
  };

  /* ───────────────────────────── theme & preset ───────────────────────────── */

  const THEMES = ["auto", "dark", "light"];
  const THEME_LABEL = { auto: "跟随系统", dark: "深色", light: "浅色" };
  const PRESETS = ["tangerine", "soft-pop", "brutalist"];

  const applyTheme = (name, persist) => {
    document.documentElement.setAttribute("data-theme", name);
    const btn = $("themeBtn");
    if (btn) btn.textContent = THEME_LABEL[name];
    if (persist) {
      try { localStorage.setItem("recon-theme", name); } catch (_) { /* private mode */ }
    }
  };

  const applyPreset = (name, persist) => {
    document.documentElement.setAttribute("data-preset", name);
    document.querySelectorAll(".preset").forEach((b) => {
      b.classList.toggle("is-on", b.dataset.preset === name);
      b.setAttribute("aria-pressed", String(b.dataset.preset === name));
    });
    const swatch = document.querySelector(`.preset[data-preset="${name}"] > i`);
    const probe = $("presetRadius");
    if (swatch && probe) probe.style.borderColor = getComputedStyle(swatch).backgroundColor;
    if (persist) {
      try { localStorage.setItem("recon-preset", name); } catch (_) { /* ignore */ }
    }
  };

  const bootLook = () => {
    let t = null, pr = null;
    try {
      t = localStorage.getItem("recon-theme");
      pr = localStorage.getItem("recon-preset");
    } catch (_) { /* ignore */ }
    applyTheme(THEMES.includes(t) ? t : "auto", false);
    applyPreset(PRESETS.includes(pr) ? pr : "tangerine", false);
    window.matchMedia("(prefers-color-scheme: dark)")
      .addEventListener("change", () => {
        if (document.documentElement.getAttribute("data-theme") === "auto") {
          applyTheme("auto", false);
        }
      });
  };

  const cycleTheme = () => {
    const now = document.documentElement.getAttribute("data-theme") || "auto";
    applyTheme(THEMES[(THEMES.indexOf(now) + 1) % THEMES.length], true);
  };

  /* ───────────────────────────── routing ───────────────────────────── */

  const VIEW_TITLE = {
    scan: "扫描", runs: "产物", overview: "概览", compare: "对比", checks: "评分明细",
    endpoints: "端点", params: "参数与请求体", log: "运行日志",
  };
  const VIEWS = Object.keys(VIEW_TITLE);

  const viewFromHash = () => {
    const raw = (window.location.hash || "").replace(/^#\/?/, "");
    return VIEWS.includes(raw) ? raw : "";
  };

  const showView = (name, opts = {}) => {
    const view = VIEWS.includes(name) ? name : "scan";
    state.view = view;
    document.querySelectorAll(".view").forEach((v) => {
      v.hidden = v.dataset.view !== view;
    });
    document.querySelectorAll(".navitem").forEach((b) => {
      const on = b.dataset.view === view;
      b.classList.toggle("is-on", on);
      if (on) b.setAttribute("aria-current", "page");
      else b.removeAttribute("aria-current");
    });
    $("viewTitle").textContent = VIEW_TITLE[view] || view;
    $("side").classList.remove("is-open");
    if (!opts.silent) {
      try { localStorage.setItem("recon-view", view); } catch (_) { /* ignore */ }
      if (viewFromHash() !== view) window.location.hash = `#/${view}`;
    }
    if (view === "runs") loadRuns();
    if (view === "compare") loadCompare();
    if (!opts.keepScroll) window.scrollTo({ top: 0 });
  };

  // 空态与内容互斥：任何视图都能进，只是没数据时给出「去扫描」的引导，而不是把导航禁用。
  const refreshDataFlags = () => {
    const loaded = !!state.report;
    document.querySelectorAll("[data-needs-report]").forEach((n) => { n.hidden = loaded; });
    document.querySelectorAll("[data-has-report]").forEach((n) => { n.hidden = !loaded; });
    $("badgeRuns").textContent = state.runs.length ? String(state.runs.length) : "";
  };

  /* ───────────────────────────── progress ───────────────────────────── */

  const fmtElapsed = (s) => {
    const m = Math.floor(s / 60);
    return m ? `${m}分${String(Math.round(s % 60)).padStart(2, "0")}秒` : `${Math.round(s)}秒`;
  };

  const setProgress = (pct, stage) => {
    const box = $("progress");
    const job = state.job || {};
    const running = job.state === "running";
    const value = Number.isFinite(pct) ? pct : 0;
    box.hidden = !running && value <= 0;
    $("progressPct").textContent = `${value}%`;
    $("progressStage").textContent = stage || "";
    $("progressFill").style.width = `${value}%`;
  };

  const setStatus = (jobState) => {
    const map = {
      idle: "空闲", running: "扫描中", done: "已完成",
      partial: "部分完成", error: "出错", cancelled: "已停止",
    };
    const label = map[jobState] || jobState || "空闲";
    const pill = $("liveBar");
    pill.dataset.state = jobState || "idle";
    $("liveText").textContent = label;
    const status = $("connStatus");
    status.textContent = label;
    status.dataset.state = jobState || "idle";
  };

  /* ───────────────────────────── target rows ───────────────────────────── */

  const TARGET_STATE = {
    queued: "排队", running: "探测中", done: "完成",
    partial: "部分", error: "失败", cancelled: "已停止",
  };

  const renderTargets = (job) => {
    const list = $("targetList");
    const targets = (job && job.targets) || [];
    $("parallelHint").textContent = job && job.parallel && targets.length
      ? `${targets.length} 个目标 · 并行 ${job.parallel}` : "";
    if (!targets.length) {
      if (state.lastTargets !== "") {
        list.replaceChildren(el("li", "targets__empty", "还没有运行中的批次。"));
        state.lastTargets = "";
      }
      return;
    }
    const signature = JSON.stringify(targets.map((t) => [t.target, t.state, t.progress, t.stage, t.error]));
    if (signature === state.lastTargets) return;
    state.lastTargets = signature;

    list.replaceChildren();
    for (const t of targets) {
      const li = el("li", "targets__row");
      li.dataset.state = t.state || "queued";

      const head = el("div", "targets__head");
      head.appendChild(el("span", "targets__name mono", t.target || "—"));
      head.appendChild(el("span", "targets__state", TARGET_STATE[t.state] || t.state || ""));
      li.appendChild(head);

      const bar = el("div", "targets__bar");
      const fill = el("i");
      fill.style.width = `${Number.isFinite(t.progress) ? t.progress : 0}%`;
      bar.appendChild(fill);
      li.appendChild(bar);

      const meta = el("div", "targets__meta");
      const bits = [];
      if (t.progress != null) bits.push(`${t.progress}%`);
      if (t.stage) bits.push(t.stage);
      if (t.verdict) bits.push(t.verdict);
      if (t.error) bits.push(t.error);
      meta.textContent = bits.join(" · ");
      if (t.error) meta.dataset.kind = "error";
      li.appendChild(meta);

      list.appendChild(li);
    }
  };

  /* ───────────────────────────── events ───────────────────────────── */

  const appendEvents = (events) => {
    if (!events || !events.length) return;
    const box = $("liveLog");
    if (box.textContent === "尚未开始扫描。") box.textContent = "";
    const stick = box.scrollTop + box.clientHeight >= box.scrollHeight - 24;
    for (const ev of events) {
      const line = document.createElement("div");
      const stage = ev.stage || ev.type || "·";
      const who = ev.target ? `${ev.target} ` : "";
      line.textContent = `${who}[${stage}] ${ev.message || ev.msg || ""}`;
      box.appendChild(line);
    }
    // 保留最近 400 行：控制台要能看，但不能无限膨胀
    while (box.childElementCount > 400) box.removeChild(box.firstChild);
    $("liveCount").textContent = `${box.childElementCount} 行`;
    if (stick) box.scrollTop = box.scrollHeight;
  };

  /* ───────────────────────────── polling (live, no refresh) ───────────────────────────── */

  const schedule = (ms) => {
    clearTimeout(state.timer);
    state.timer = setTimeout(tick, ms);
  };

  const tick = async () => {
    if (!state.authed) return;
    let next = 3000;
    try {
      const [stateRes, eventsRes] = await Promise.all([
        fetch("/api/state", { credentials: "same-origin" }),
        fetch(`/api/events?since=${state.since}`, { credentials: "same-origin" }),
      ]);
      if (stateRes.status === 401 || eventsRes.status === 401) {
        state.authed = false;
        renderGate(true);
        return;
      }
      const data = await stateRes.json();
      const events = await eventsRes.json();
      $("ver").textContent = data.version || "";
      if (!data.authed) {
        state.authed = false;
        renderGate(data.configured);
        return;
      }
      applyJob(data.job || {});
      appendEvents(events.events || []);
      state.since = events.since ?? state.since;
      const running = (data.job || {}).state === "running";
      next = running ? 600 : 3000;
    } catch (_) {
      next = 2000;      // transient; retry quickly
    }
    schedule(next);
  };

  const applyJob = (job) => {
    const previous = state.lastJobState;
    state.job = job;
    setStatus(job.state);
    $("sideTarget").textContent = job.target || "—";
    setProgress(job.progress, job.stage);
    renderTargets(job);

    const running = job.state === "running";
    $("runBtn").disabled = running;
    $("stopBtn").disabled = !running;
    if (running) {
      const count = (job.targets || []).length;
      $("runMeta").textContent = count > 1
        ? `${count} 个目标并行中 · ${fmtElapsed(job.elapsed || 0)}`
        : `${job.target || ""} · 运行中 ${fmtElapsed(job.elapsed || 0)}`;
    } else if (job.target) {
      $("runMeta").textContent = `${job.target} · ${TARGET_STATE[job.state] || job.state}`;
    }
    if (previous === "running" && !running) {
      // 批次刚结束：把新报告与产物列表拉一次，不必刷新页面
      loadReport();
      loadRuns();
      if (!state.report && job.state !== "done") {
        toast(job.state === "cancelled" ? "扫描已停止" : "扫描结束，但没有可用的报告", "warn");
      }
    }
    state.lastJobState = job.state;
  };

  const startPolling = () => {
    if (!state.authed) return;
    clearTimeout(state.timer);
    tick();
  };

  /* ───────────────────────────── gate ───────────────────────────── */

  const showError = (node, message) => {
    node.textContent = message;
    node.hidden = !message;
  };

  /* 授权声明：服务端是唯一来源（config.AUTHORIZED_USE_*），前端只负责显示。
     登录页与扫描页都显示，因为「能不能对这个目标做」在点扫描之前就要回答。 */
  const applyAuthorization = (authz) => {
    if (!authz) return;
    const short = authz.summary || "";
    const full = authz.notice || "";
    const gate = $("gateAuthz");
    if (gate && short) gate.textContent = short;
    const hint = $("authHint");
    if (hint) {
      hint.textContent = full || short;
      hint.title = authz.notice_version ? `声明版本 ${authz.notice_version}` : "";
    }
  };

  const renderGate = (configured) => {
    clearTimeout(state.timer);
    state.timer = null;
    state.authed = false;
    $("gate").hidden = false;
    $("app").hidden = true;
    $("pairForm").hidden = configured;
    $("loginForm").hidden = !configured;
    $("gateLabel").textContent = configured ? "已初始化" : "首次运行";
    $("gateSub").textContent = configured
      ? "输入密码以进入控制台（登录后本浏览器保持登录）"
      : "首次运行：输入控制台打印的令牌，并设置一次密码";
    $("rememberHint").textContent = `登录后本浏览器 ${state.rememberDays} 天内免登录。`;
    if (configured) setTimeout(() => $("loginPass").focus(), 60);
  };

  const enterApp = async () => {
    state.authed = true;
    $("gate").hidden = true;
    $("app").hidden = false;
    let last = null;
    try { last = localStorage.getItem("recon-view"); } catch (_) { /* ignore */ }
    showView(viewFromHash() || (VIEWS.includes(last) ? last : "scan"), { silent: true });
    await loadRuns();
    await loadReport();
    startPolling();
    state.booted = true;
  };

  $("pairForm").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const pass = $("pairPass").value;
    if (pass !== $("pairPass2").value) return showError($("pairErr"), "两次输入的密码不一致");
    try {
      await api("/api/claim", {
        method: "POST",
        body: { token: $("pairToken").value.trim(), password: pass },
      });
      enterApp();
    } catch (err) {
      showError($("pairErr"), err.message);
    }
  });

  $("loginForm").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    try {
      await api("/api/login", { method: "POST", body: { password: $("loginPass").value } });
      enterApp();
    } catch (err) {
      showError($("loginErr"), err.message);
    }
  });

  $("logoutBtn").addEventListener("click", async () => {
    await api("/api/logout", { method: "POST" }).catch(() => {});
    clearTimeout(state.timer);
    state.timer = null;
    state.report = null;
    state.runs = [];
    state.authed = false;
    renderGate(true);
  });

  $("themeBtn").addEventListener("click", cycleTheme);
  document.querySelectorAll(".preset").forEach((b) => {
    b.addEventListener("click", () => applyPreset(b.dataset.preset, true));
  });
  document.querySelectorAll(".navitem").forEach((b) => {
    b.addEventListener("click", () => showView(b.dataset.view));
  });
  document.querySelectorAll("[data-goto]").forEach((b) => {
    b.addEventListener("click", () => showView(b.dataset.goto));
  });
  window.addEventListener("hashchange", () => {
    const target = viewFromHash();
    if (target && target !== state.view) showView(target, { silent: true });
  });
  $("sideToggle").addEventListener("click", () => {
    const side = $("side");
    if (window.matchMedia("(max-width: 900px)").matches) side.classList.remove("is-open");
    else side.classList.toggle("is-collapsed");
  });
  $("burger").addEventListener("click", () => $("side").classList.toggle("is-open"));

  /* ───────────────────────────── scan form ───────────────────────────── */

  $("swExt").addEventListener("change", (ev) => {
    $("extHint").hidden = !ev.target.checked;
  });

  const parseTargets = () => $("targets").value
    .split(/[\s,;]+/)
    .map((v) => v.trim())
    .filter(Boolean)
    .filter((v, i, arr) => arr.indexOf(v) === i);

  $("runBtn").addEventListener("click", async () => {
    const targets = parseTargets();
    showError($("runMeta"), "");
    if (!targets.length) { $("runMeta").textContent = "请填写至少一个域名"; return; }
    const allowExternal = $("swExt").checked;
    try {
      const res = await api("/api/scan", {
        method: "POST",
        body: {
          targets,
          profile: $("profile").value,
          verify_tls: $("swTls").checked,
          use_dns: $("swDns").checked,
          use_graphql: $("swGql").checked,
          allow_external: allowExternal,
          confirm_external: allowExternal,
          use_js: $("swJs").checked,
          use_intel: $("swIntel").checked,
          geo: $("swGeo").checked,
          cve: $("swCve").checked,
          use_discovery: $("swDiscovery").checked,
          authorized_by: $("authorizedBy").value.trim(),
        },
      });
      $("liveLog").textContent = "";
      $("liveCount").textContent = "";
      state.since = 0;
      state.lastTargets = "";
      toast(`已启动 ${res.targets.length} 个目标（并行 ${res.parallel}）`, "ok");
      // 立刻开始实时刷新：不等下一次轮询，也不需要刷新页面
      schedule(120);
    } catch (err) {
      $("runMeta").textContent = err.message;
      toast(err.message, "error");
    }
  });

  $("stopBtn").addEventListener("click", async () => {
    await api("/api/stop", { method: "POST" })
      .then(() => toast("已请求停止，等待当前阶段收尾", "warn"))
      .catch((err) => toast(err.message, "error"));
  });

  /* ───────────────────────────── runs (artifact management) ───────────────────────────── */

  const fmtBytes = (n) => {
    const v = Number(n) || 0;
    if (v >= 1024 * 1024) return `${(v / 1024 / 1024).toFixed(1)} MB`;
    if (v >= 1024) return `${(v / 1024).toFixed(0)} KB`;
    return `${v} B`;
  };

  const fmtWhen = (iso, mtime) => {
    if (iso) return iso.replace("T", " ").replace("Z", "");
    if (!mtime) return "—";
    const d = new Date(mtime * 1000);
    return d.toLocaleString();
  };

  const renderRuns = (runs, selected) => {
    state.runs = runs;
    const body = $("runsBody");
    body.replaceChildren();
    $("runsEmpty").hidden = runs.length > 0;
    $("runsMeta").textContent = runs.length
      ? `${runs.length} 份产物 · ${fmtBytes(runs.reduce((n, r) => n + (r.bytes || 0), 0))}`
      : "";
    const selectedName = selected ? String(selected).split(/[\\/]/).pop() : "";

    for (const r of runs) {
      const tr = el("tr");
      if (r.run === selectedName) tr.classList.add("is-current");

      const nameCell = el("td", "mono");
      nameCell.appendChild(el("span", "runs__name", r.run));
      if (r.run === selectedName) nameCell.appendChild(el("span", "tag tag--on", "当前"));
      if (!r.has_report) nameCell.appendChild(el("span", "tag tag--warn", "无报告"));
      tr.appendChild(nameCell);

      tr.appendChild(el("td", "mono", r.domain || "—"));
      tr.appendChild(el("td", "dim col-s", fmtWhen(r.generated_at, r.mtime)));
      tr.appendChild(el("td", "al-r col-n num", String((r.counts || {}).endpoints ?? "—")));
      tr.appendChild(el("td", "al-r col-n num", String((r.counts || {}).findings ?? "—")));
      const verdictCell = el("td", "dim col-s", r.verdict || "—");
      if (r.score_verdict) verdictCell.title = `评分层结论：${r.score_verdict}`;
      tr.appendChild(verdictCell);
      tr.appendChild(el("td", "al-r col-w num", fmtBytes(r.bytes)));

      const act = el("td", "al-r col-act");
      const open = el("button", "btn btn--sm", "查看");
      open.type = "button";
      open.disabled = !r.has_report;
      open.addEventListener("click", async () => {
        try {
          await api("/api/runs/select", { method: "POST", body: { run: r.run } });
          await loadReport();
          showView("overview");
          toast(`已切换到 ${r.run}`, "ok");
        } catch (err) { toast(err.message, "error"); }
      });
      act.appendChild(open);

      const del = el("button", "btn btn--sm btn--danger", "删除");
      del.type = "button";
      del.addEventListener("click", async () => {
        const ok = window.confirm(
          `删除产物目录 runs/${r.run}/？\n报告与 raw/ 原始 bundle 会一起移除，不可恢复。`);
        if (!ok) return;
        try {
          await api("/api/runs/delete", { method: "POST", body: { run: r.run, confirm: true } });
          await loadRuns();
          if (r.run === selectedName) {
            state.report = null;
            refreshDataFlags();
          }
          toast(`已删除 ${r.run}`, "ok");
        } catch (err) { toast(err.message, "error"); }
      });
      act.appendChild(del);

      tr.appendChild(act);
      body.appendChild(tr);
    }
    refreshDataFlags();
  };

  const loadRuns = async () => {
    try {
      const data = await api("/api/runs");
      renderRuns(data.runs || [], data.selected || "");
    } catch (err) {
      if (err.status === 401) { state.authed = false; renderGate(true); return; }
      toast(err.message, "error");
    }
  };

  $("runsRefresh").addEventListener("click", () => {
    loadRuns().then(() => toast("产物列表已刷新", "ok"));
  });

  /* ───────────────────────────── compare ───────────────────────────── */

  const BAND_LABEL = { high: "高", elevated: "偏高", moderate: "中", low: "低", unknown: "未定" };
  const BET_LABEL = { worth: "值得打", not_worth: "不值", withheld: "证据不足" };
  const BET_STATUS = { hit: "命中", miss: "未命中", unknown: "未判定" };

  const compareNumber = (value, width) => {
    const td = el("td", `al-r ${width} num`);
    td.textContent = value == null || value === "" ? "—" : String(value);
    return td;
  };

  /* 对比表：所有列由 /api/compare 提供（服务端按当前模型重算）。缺失一律显示 —，不显示 0。 */
  const renderCompare = (rows, selected) => {
    const body = $("compareBody");
    body.replaceChildren();
    const wrap = $("compareWrap");
    const empty = $("compareEmpty");
    $("compareCount").textContent = rows.length ? `${rows.length} 份带报告的产物` : "";
    wrap.hidden = rows.length === 0;
    empty.hidden = rows.length > 0;
    if (!rows.length) return;

    const selectedName = selected ? String(selected).split(/[\\/]/).pop() : "";
    for (const r of rows) {
      const isCurrent = !!r.selected || (!!selectedName && r.run === selectedName);
      const tr = el("tr");
      if (isCurrent) tr.classList.add("is-current");

      const tdName = el("td");
      tdName.appendChild(el("span", "runs__name mono", r.domain || r.run || "—"));
      if (isCurrent) tdName.appendChild(el("span", "tag tag--on", "当前"));
      tr.appendChild(tdName);

      tr.appendChild(el("td", "dim mono col-time", r.generated_at
        ? String(r.generated_at).slice(0, 16).replace("T", " ") : "—"));

      const tdVerdict = el("td", "col-verdict");
      if (r.error) tdVerdict.appendChild(el("span", "cmp__err", r.error));
      else {
        const verdictText = el("span", "dim", r.verdict || "未评估");
        if (r.score_verdict) verdictText.title = `评分层结论：${r.score_verdict}`;
        tdVerdict.appendChild(verdictText);
      }
      tr.appendChild(tdVerdict);

      const tdUnknown = compareNumber(r.unknowns, "col-n");
      if (r.next_action) tdUnknown.title = `下一步：${r.next_action}`;
      tr.appendChild(tdUnknown);

      tr.appendChild(compareNumber(r.worth, "col-w"));
      tr.appendChild(compareNumber(r.ease, "col-w"));

      const tdIdx = el("td", "al-r col-idx");
      const idx = el("div", "cmp__idx");
      idx.appendChild(el("span", r.index == null ? "num dim" : "num", r.index == null ? "—" : String(r.index)));
      const band = r.band || "unknown";
      const pill = el("span", "profile__band", BAND_LABEL[band] || band);
      pill.dataset.band = band;
      if (r.band_label) pill.title = r.band_label;
      idx.appendChild(pill);
      tdIdx.appendChild(idx);
      tr.appendChild(tdIdx);

      const counts = r.counts || {};
      tr.appendChild(compareNumber(counts.subdomains, "col-n"));
      tr.appendChild(compareNumber(counts.endpoints, "col-n"));
      tr.appendChild(compareNumber(counts.findings, "col-n"));
      tr.appendChild(compareNumber(r.observed_share_pct == null ? null : `${r.observed_share_pct}%`, "col-w"));

      const tdAct = el("td", "al-r col-act");
      const open = el("button", "btn btn--sm", "查看");
      open.type = "button";
      open.disabled = /unreadable/i.test(r.error || "");
      open.addEventListener("click", async () => {
        open.disabled = true;
        open.textContent = "切换中";
        try {
          await api("/api/runs/select", { method: "POST", body: { run: r.run } });
          await loadRuns();
          await loadReport();
          showView("overview");
          toast(`已切换到 ${r.domain || r.run}`, "ok");
        } catch (err) {
          open.disabled = false;
          open.textContent = "查看";
          toast(err.message, "error");
        }
      });
      tdAct.appendChild(open);
      tr.appendChild(tdAct);
      body.appendChild(tr);
    }
  };

  /* 只在进入对比视图时取一次，不做轮询。 */
  const loadCompare = async () => {
    if (state.compareLoading) return;
    state.compareLoading = true;
    const loading = $("compareLoading");
    const err = $("compareErr");
    loading.hidden = false;
    $("compareWrap").hidden = true;
    $("compareEmpty").hidden = true;
    err.hidden = true;
    $("compareCount").textContent = "";
    try {
      const data = await api("/api/compare");
      $("compareNote").textContent = data.note ||
        "列均按当前模型重算（score / profile / bet）。index 为机会指数（非概率）。";
      renderCompare(data.runs || [], data.selected || "");
    } catch (e) {
      if (e.status === 401) { state.authed = false; renderGate(true); return; }
      err.textContent = `读取对比失败：${e.message}`;
      err.hidden = false;
    } finally {
      loading.hidden = true;
      state.compareLoading = false;
    }
  };

  $("compareRefresh").addEventListener("click", async () => {
    await loadCompare();
    if ($("compareErr").hidden) {
      const count = $("compareCount").textContent;
      toast(count ? `对比已刷新：${count}` : "没有可对比的产物", count ? "ok" : "warn");
    }
  });

  /* ───────────────────────────── report rendering ───────────────────────────── */

  const STATUS_LABEL = { pass: "通过", warn: "警告", fail: "未通过", unknown: "未判定" };
  const AXIS_LABEL = { hygiene: "维护", opportunity: "机会" };
  const COUNT_LABEL = [
    ["pages", "页面"], ["scripts", "脚本"], ["endpoints", "端点"],
    ["endpoints_write", "写方法端点"], ["endpoints_testable", "可变异端点"],
    ["parameters", "参数"], ["sourcemaps", "source map"], ["secrets", "密钥"],
    ["specs", "API 规范"], ["graphql", "GraphQL"], ["discovered", "内容发现"],
  ];
  const ORDER = { fail: 0, warn: 1, unknown: 2, pass: 3 };

  const fmt = (v) => {
    if (v == null || v === "") return "—";
    const n = Number(v);
    if (!Number.isFinite(n)) return String(v);
    return String(n);
  };

  const statusTag = (status) => {
    const node = el("span", "st", STATUS_LABEL[status] || status);
    node.dataset.s = status;
    return node;
  };

  /* 结论正文用 **强调**。只认 `**`，全程 textNode，不引入任何标记注入面。 */
  const renderRichText = (node, text) => {
    node.replaceChildren();
    for (const part of String(text).split(/(\*\*[^*]+\*\*)/)) {
      if (!part) continue;
      if (part.startsWith("**") && part.endsWith("**") && part.length > 4) {
        node.appendChild(el("strong", null, part.slice(2, -2)));
      } else {
        node.appendChild(document.createTextNode(part));
      }
    }
  };

  /* ───────────────────── 图形基础：SVG 节点 + 极坐标，无框架 ───────────────────── */

  const SVGNS = "http://www.w3.org/2000/svg";

  const svgNode = (tag, attrs) => {
    const node = document.createElementNS(SVGNS, tag);
    if (attrs) {
      for (const key of Object.keys(attrs)) node.setAttribute(key, String(attrs[key]));
    }
    return node;
  };

  const svgText = (x, y, text, cls, anchor) => {
    const node = svgNode("text", { x, y, class: cls });
    if (anchor) node.setAttribute("text-anchor", anchor);
    node.textContent = text;
    return node;
  };

  const px = (v) => Math.round(v * 10) / 10;

  /* 0–100 的分数；null/空串保持 null —— 缺失绝不画成 0。 */
  const scoreOf = (v) => {
    if (v == null || v === "") return null;
    const n = Number(v);
    return Number.isFinite(n) ? Math.round(n * 10) / 10 : null;
  };

  const polar = (cx, cy, r, deg) => {
    const rad = (deg * Math.PI) / 180;
    return [cx + Math.cos(rad) * r, cy + Math.sin(rad) * r];
  };

  const RADAR_AXES = [
    { key: "worth", label: "价值", angle: -90 },
    { key: "ease", label: "易度", angle: 30 },
    { key: "index", label: "机会指数", angle: 150 },
  ];

  const axisWord = (axis, values) => {
    const v = values[axis.key];
    if (v != null) return `${axis.label} ${v}`;
    return axis.key === "index" ? "机会指数 withheld" : `${axis.label} 未采集`;
  };

  /* 三轴雷达：价值 / 易度（100 − 难度）/ 机会指数。
     缺值的轴画成虚线 + 空心点，而不是把 0 当成数据——「没读到」和「读到 0」在图上必须是两种东西。 */
  const renderRadar = (rep) => {
    const prof = rep.profile || {};
    const axes = prof.axes || {};
    const worth = axes.worth || {};
    const hard = axes.hardness || {};
    const succ = prof.success || {};
    const hardScore = scoreOf(hard.score);
    const values = {
      worth: scoreOf(worth.score),
      ease: hardScore == null ? null : Math.round((100 - hardScore) * 10) / 10,
      index: scoreOf(succ.index),
    };

    $("radarBox").setAttribute("aria-label",
      `三轴画像（0–100）：${RADAR_AXES.map((a) => axisWord(a, values)).join("，")}`);

    const W = 260, H = 240, cx = 130, cy = 120, R = 76;
    const svg = svgNode("svg", {
      class: "radar__svg", viewBox: `0 0 ${W} ${H}`, width: W, height: H,
      "aria-hidden": "true", focusable: "false",
    });

    for (const pct of [25, 50, 75, 100]) {
      svg.appendChild(svgNode("circle", {
        cx, cy, r: px((R * pct) / 100),
        class: pct === 100 ? "radar__ring radar__ring--outer" : "radar__ring",
      }));
    }

    for (const axis of RADAR_AXES) {
      const [x, y] = polar(cx, cy, R, axis.angle);
      svg.appendChild(svgNode("line", { x1: cx, y1: cy, x2: px(x), y2: px(y), class: "radar__axis" }));
    }

    const known = RADAR_AXES.filter((axis) => values[axis.key] != null);
    if (known.length >= 2) {
      const pts = known.map((axis) => {
        const [x, y] = polar(cx, cy, (R * values[axis.key]) / 100, axis.angle);
        return `${px(x)},${px(y)}`;
      });
      svg.appendChild(svgNode(known.length === 3 ? "polygon" : "polyline",
        { points: pts.join(" "), class: "radar__area" }));
    }

    for (const axis of RADAR_AXES) {
      const v = values[axis.key];
      const [x, y] = polar(cx, cy, v == null ? R : (R * v) / 100, axis.angle);
      if (v == null) {
        svg.appendChild(svgNode("line", { x1: cx, y1: cy, x2: px(x), y2: px(y), class: "radar__stub" }));
        svg.appendChild(svgNode("circle", { cx: px(x), cy: px(y), r: 3.2, class: "radar__dot radar__dot--open" }));
      } else {
        svg.appendChild(svgNode("circle", { cx: px(x), cy: px(y), r: 3, class: "radar__dot" }));
      }
    }

    for (const axis of RADAR_AXES) {
      const [vx, vy] = polar(cx, cy, R, axis.angle);
      let x = vx, nameY = vy + 14, valY = vy + 29, anchor = "middle";
      if (axis.angle === -90) { nameY = vy - 24; valY = vy - 9; }
      if (axis.angle === 30) { x = vx + 12; nameY = vy + 2; valY = vy + 17; anchor = "start"; }
      if (axis.angle === 150) { x = vx - 12; nameY = vy + 2; valY = vy + 17; anchor = "end"; }
      svg.appendChild(svgText(px(x), px(nameY), axis.label, "radar__lab", anchor));
      const v = values[axis.key];
      svg.appendChild(svgText(px(x), px(valY), v == null ? "—" : String(v),
        v == null ? "radar__val radar__val--none" : "radar__val", anchor));
    }

    $("radarFig").replaceChildren(svg);

    const legend = $("radarLegend");
    legend.replaceChildren();
    const rows = [
      ["价值", values.worth, worth.coverage_pct == null ? "未采集"
        : `覆盖 ${worth.coverage_pct}% · ${worth.checks_evaluated ?? "?"}/${worth.checks_total ?? "?"} 项判定`],
      ["易度", values.ease, hardScore == null ? "未采集"
        : `100 − 难度 ${hardScore} · 覆盖 ${hard.coverage_pct ?? "?"}%`],
      ["机会指数", values.index, values.index == null
        ? "withheld · 覆盖率不足，不按 0 计" : (succ.label || "非概率")],
    ];
    for (const [label, value, hint] of rows) {
      const row = el("div", "radar__row");
      row.appendChild(el("span", "radar__name", label));
      row.appendChild(el("span", value == null ? "radar__num num radar__num--none" : "radar__num num",
        value == null ? "—" : String(value)));
      row.appendChild(el("span", "radar__hint", hint));
      legend.appendChild(row);
    }
  };

  const PRIORITY_KEYS = [
    { key: "primary", label: "首要 primary" },
    { key: "secondary", label: "次要 secondary" },
    { key: "inventory", label: "清单 inventory" },
  ];

  const arcPath = (cx, cy, rOut, rIn, a0, a1) => {
    const p = (r, a) => {
      const [x, y] = polar(cx, cy, r, (a * 180) / Math.PI);
      return `${x.toFixed(2)} ${y.toFixed(2)}`;
    };
    const large = a1 - a0 > Math.PI ? 1 : 0;
    return `M${p(rOut, a0)}A${rOut} ${rOut} 0 ${large} 1 ${p(rOut, a1)}`
      + `L${p(rIn, a1)}A${rIn} ${rIn} 0 ${large} 0 ${p(rIn, a0)}Z`;
  };

  /* 端点风险分布：环形图 + 图例。三段之和恒等于 endpoints.length。 */
  const renderEndpointMix = (rep) => {
    const eps = rep.endpoints || [];
    const counts = { primary: 0, secondary: 0, inventory: 0 };
    for (const e of eps) {
      const key = String(e.priority || "inventory").toLowerCase();
      if (key in counts) counts[key] += 1;
      else counts.inventory += 1;
    }
    const total = eps.length;

    $("epMixMeta").textContent = total ? `${total} 个端点` : "";
    $("epMix").hidden = total === 0;
    $("epMixEmpty").hidden = total > 0;
    const fig = $("epMixFig");
    const legend = $("epMixLegend");
    fig.replaceChildren();
    legend.replaceChildren();
    if (!total) return;

    const S = 168, c = S / 2, rOut = 74, rIn = 52;
    const svg = svgNode("svg", {
      class: "donut__svg", viewBox: `0 0 ${S} ${S}`, width: S, height: S,
      "aria-hidden": "true", focusable: "false",
    });
    const segs = PRIORITY_KEYS.filter((k) => counts[k.key] > 0);
    const start = -Math.PI / 2;
    if (segs.length === 1) {
      // 单一分类占满整圈：拆成两段半圆，避开起终点重合的退化弧
      for (let i = 0; i < 2; i += 1) {
        svg.appendChild(svgNode("path", {
          d: arcPath(c, c, rOut, rIn, start + i * Math.PI, start + (i + 1) * Math.PI),
          class: `donut__seg donut__seg--${segs[0].key}`,
        }));
      }
    } else {
      let angle = start;
      segs.forEach((k, i) => {
        const end = i === segs.length - 1
          ? start + Math.PI * 2
          : angle + (counts[k.key] / total) * Math.PI * 2;
        svg.appendChild(svgNode("path", {
          d: arcPath(c, c, rOut, rIn, angle, end),
          class: `donut__seg donut__seg--${k.key}`,
        }));
        angle = end;
      });
    }

    const center = el("div", "donut__center");
    center.appendChild(el("span", "donut__total num", String(total)));
    center.appendChild(el("span", "donut__cap", "端点"));
    fig.appendChild(svg);
    fig.appendChild(center);

    for (const k of PRIORITY_KEYS) {
      const n = counts[k.key];
      const row = el("li", "donut__key");
      if (!n) row.dataset.zero = "1";
      const sw = el("i", "donut__sw");
      sw.dataset.k = k.key;
      sw.setAttribute("aria-hidden", "true");
      row.appendChild(sw);
      row.appendChild(el("span", "donut__name", k.label));
      row.appendChild(el("span", "donut__n num", String(n)));
      row.appendChild(el("span", "donut__p", `${Math.round((n / total) * 1000) / 10}%`));
      legend.appendChild(row);
    }
  };

  /* 情报落地：子域 / 主动探测强度 / 依赖版本。紧凑成三行，不给每项一张卡。 */
  const renderIntel = (rep) => {
    const meta = rep.meta || {};
    const prof = rep.profile || {};
    const dims = (prof.dimensions || {}).subdomains || {};
    const weights = prof.weights || {};
    const subs = Array.isArray((rep.assets || {}).subdomains) ? rep.assets.subdomains : [];

    const list = $("intelSubs");
    list.replaceChildren();
    const LIMIT = 8;
    for (const s of subs.slice(0, LIMIT)) {
      const li = el("li", "intel__sub");
      li.appendChild(el("span", "intel__host mono", s.host || s.url || "—"));
      if (s.source) li.appendChild(el("span", "tag tag--ghost", s.source));
      li.appendChild(el("span", s.probed ? "tag tag--on" : "tag tag--warn",
        s.probed ? "已探测" : "未探测"));
      if (s.last_cert) li.appendChild(el("span", "intel__cert", `证书 ${String(s.last_cert).slice(0, 10)}`));
      list.appendChild(li);
    }
    if (!subs.length) {
      const status = dims.status || "unknown";
      const reason = dims.reason ? ` · ${dims.reason}` : "";
      list.appendChild(el("li", "intel__empty", `未采集 · ${status}${reason}`));
      $("intelMeta").textContent = dims.status || "未采集";
    } else {
      if (subs.length > LIMIT) {
        list.appendChild(el("li", "intel__more", `另有 ${subs.length - LIMIT} 个未列出`));
      }
      $("intelMeta").textContent = `${subs.length} 个 · ${dims.source || "ct"}`;
    }

    const ps = meta.probe_stats || {};
    const stats = $("intelStats");
    stats.replaceChildren();
    const stat = (value, label, warn) => {
      const node = el("span", "intel__stat");
      node.appendChild(el("span", "num", value == null ? "—" : String(value)));
      node.appendChild(document.createTextNode(` ${label}`));
      if (warn) node.dataset.kind = "warn";
      return node;
    };
    stats.appendChild(stat(ps.requests, "次请求"));
    stats.appendChild(stat(ps.blocked, "次拦截", ps.blocked > 0));
    stats.appendChild(stat(ps.blocked_pct == null ? null : `${ps.blocked_pct}%`, "拦截率", ps.blocked_pct > 0));
    stats.appendChild(stat(ps.throttled, "次限速", ps.throttled > 0));
    stats.appendChild(stat(ps.scope_blocks, "次越界拦截", ps.scope_blocks > 0));

    const share = scoreOf(weights.observed_share_pct);
    $("intelShare").textContent = share == null
      ? "结论中来自主动实测的权重：未采集"
      : `结论中来自主动实测的权重 ${share}% · 主动权重 ${fmt(weights.active)} / 被动 ${fmt(weights.passive)}`;
    $("intelShareBar").style.width = `${share == null ? 0 : share}%`;

    const deps = meta.deps || {};
    const parts = ["python", "httpx", "anyio", "ssl"]
      .filter((k) => deps[k])
      .map((k) => `${k} ${deps[k]}`);
    $("intelDeps").textContent = parts.length ? `运行时 ${parts.join(" · ")}` : "运行时版本未记录";
  };

  /* 定向内容发现：候选数、基线、存在/受保护路径。数据全部来自 report.discovery。 */
  const renderDiscovery = (rep) => {
    const card = $("discoveryCard");
    const disc = rep.discovery || {};
    if (!disc.enabled) {
      card.hidden = true;
      return;
    }
    card.hidden = false;
    const stats = disc.stats || {};
    const baseline = disc.baseline || {};
    const statusLabel = {
      ok: "完成", empty: "无候选", truncated: "预算截断",
      "baseline-blocked": "基线被拦截", error: "错误",
    };
    $("discoveryStatus").textContent = statusLabel[disc.status] || disc.status || "";
    $("discoveryMeta").textContent =
      `候选 ${stats.candidates ?? 0} · 探测 ${stats.probed ?? 0} · 存在 ${stats.present ?? 0}`
      + ` · 受保护 ${stats.gated ?? 0} · 不存在 ${stats.absent ?? 0}`
      + (stats.skipped_by_baseline ? ` · 基线拦截跳过 ${stats.skipped_by_baseline}` : "")
      + ` · 基线 HTTP ${baseline.status ?? 0}${baseline.soft_404 ? "（soft-404）" : ""}`;
    const list = $("discoveryPaths");
    list.replaceChildren();
    const labels = { present: "存在", gated: "受保护" };
    for (const row of (disc.rows || [])
      .filter((r) => labels[r.label]).slice(0, 8)) {
      list.appendChild(el("li", null,
        `${row.path} — ${labels[row.label]}（HTTP ${row.status} · ${row.source}）`));
    }
    const notes = [];
    if (disc.reason) notes.push(`未探测：${disc.reason}`);
    if (stats.truncated) notes.push("预算/时间在候选耗尽前中断；未探测部分不是「不存在」。");
    if (stats.dropped_by_cap) notes.push(`另有 ${stats.dropped_by_cap} 条候选被上限丢弃（不是不存在）。`);
    $("discoveryNote").textContent = notes.join(" ");
  };

  /* 未知面与下一步：report.uncertainty 的排序动作，不是概率。 */
  const renderUncertainty = (rep) => {
    const card = $("uncertaintyCard");
    const unc = rep.uncertainty || {};
    const actions = unc.next_actions || [];
    if (!actions.length) {
      card.hidden = true;
      return;
    }
    card.hidden = false;
    const facts = unc.facts || {};
    const pct = (v) => (v == null ? "—" : `${v}%`);
    $("uncertaintyMeta").textContent =
      `${unc.unknowns ? unc.unknowns.length : 0} 个未闭合项`;
    $("uncertaintyFacts").textContent =
      `带参端点已判定 ${facts.parameterised_answered ?? 0}/${facts.parameterised_total ?? 0}`
      + `（${pct(facts.parameterised_checked_pct)}）· 子域已探 `
      + `${facts.subdomains_probed ?? 0}/${facts.subdomains_total ?? 0}`
      + `（${pct(facts.subdomains_checked_pct)}）`
      + (facts.stages_incomplete?.length
        ? ` · 未完成阶段 ${facts.stages_incomplete.join(", ")}` : "");
    const list = $("uncertaintyActions");
    list.replaceChildren();
    for (const item of actions) {
      const li = el("li", null,
        `#${item.rank} ${item.title}（${item.impact} 影响，约 ${item.cost_requests} 次请求）`
        + ` — ${item.action}`);
      if (item.samples?.length) li.title = `样本：${item.samples.join("、")}`;
      list.appendChild(li);
    }
    $("uncertaintyFlips").textContent = (unc.verdict_flips || [])
      .map((flip) => `${flip.from} → ${flip.to}：${flip.condition}`)
      .join("；");
  };

  /* 目标画像：价值 / 难度 / 机会窗口。全部来自 report.profile，规则表计算，无模型。 */
  const renderProfile = (rep) => {
    const prof = rep.profile || {};
    const axes = prof.axes || {};
    const succ = prof.success || {};
    const dims = prof.dimensions || {};
    const mode = prof.mode_split || {};
    const passive = (mode.passive || []).length;
    const active = (mode.active || []).length;
    $("profileMode").textContent = (passive || active)
      ? `被动 ${passive} 项 · 主动 ${active} 项` : "";

    const paint = (scoreId, barId, metaId, axis) => {
      const axisData = axis || {};
      $(scoreId).textContent = axisData.score == null ? "—" : String(axisData.score);
      $(barId).style.width = `${axisData.score || 0}%`;
      $(metaId).textContent = axisData.coverage_pct == null ? "未采集"
        : `覆盖 ${axisData.coverage_pct}% · ${axisData.checks_evaluated ?? "?"}/` +
          `${axisData.checks_total ?? "?"} 项判定`;
    };
    paint("worthScore", "worthBar", "worthMeta", axes.worth);
    paint("hardScore", "hardBar", "hardMeta", axes.hardness);

    $("succIndex").textContent = succ.index == null ? "—" : String(succ.index);
    $("succBand").textContent = succ.label || "未评估";
    $("succBand").dataset.band = succ.band || "";

    const geo = dims.geo || {};
    const subs = dims.subdomains || {};
    const hist = dims.history || {};
    const cves = dims.cve_hints || {};
    const infra = dims.infra || {};
    const rows = [
      ["网站类型", (dims.site_type || {}).primary || "unknown"],
      ["地理位置", [geo.country, geo.city, geo.isp].filter(Boolean).join(" ") ||
        `未采集（${geo.status || "?"}）`],
      ["子域", subs.count != null ? `${subs.count} 个（${subs.source || "?"}）` : "未采集"],
      ["历史存档", hist.snapshots ? `${hist.snapshots} 条快照` : "未采集"],
      ["CVE 线索", (cves.hits || []).length ? `${(cves.hits || []).length} 条（${cves.source || "?"}）`
        : `无/未采集（${cves.status || "?"}）`],
      ["基础设施", [infra.server, infra.powered_by, infra.tls_version].filter(Boolean).join(" · ") || "—"],
    ];
    const dl = $("profileDims");
    dl.replaceChildren();
    for (const [label, value] of rows) {
      const item = el("div", "profile__dim");
      item.appendChild(el("dt", null, label));
      item.appendChild(el("dd", null, String(value)));
      dl.appendChild(item);
    }
    $("profileNote").textContent = prof.disclaimer || "";
    renderRadar(rep);
  };

  const renderReport = (rep) => {
    const score = rep.score || {};
    const triage = score.triage || {};
    const axes = score.axes || {};
    const bet = rep.bet || {};
    const betLabel = BET_LABEL[bet.verdict] || "";
    const decision = rep.decision || {};
    const headline = decision.headline || {};
    const FACTOR_STATUS = {
      supports: "支持", opposes: "阻碍", uncertain: "未知", neutral: "中性",
    };

    /* decision 是唯一结论；bet/profile/uncertainty 只在它下面作为证据。 */
    const acts = $("verdictActs");
    acts.replaceChildren();
    if (headline.label) {
      $("verdictLabel").textContent = `决策：${headline.label}`;
      renderRichText($("verdictWhy"), decision.why || "");
      for (const factor of decision.factors || []) {
        acts.appendChild(el("li", null,
          `${factor.label}（${FACTOR_STATUS[factor.status] || factor.status}）：${factor.value}`));
      }
    } else if (betLabel) {
      $("verdictLabel").textContent = `下注判决：${betLabel}`;
      const criteria = (bet.criteria || [])
        .map((c) => `${c.rule}：${BET_STATUS[c.status] || c.status} — ${c.detail || ""}`);
      const meta = `阈值 ${bet.threshold || "A"} · 置信度 ${bet.confidence || "low"}`
        + ` · 身份模型 ${bet.identity || "anonymous"}`;
      renderRichText($("verdictWhy"), [meta].concat(criteria).join("；"));
      const structured = (rep.uncertainty && (rep.uncertainty.unknowns || []).length)
        ? [] : (bet.unknowns || []);
      for (const u of structured) acts.appendChild(el("li", null, `还不确定：${u}`));
      for (const k of bet.kill_criteria || []) acts.appendChild(el("li", null, `改判条件：${k}`));
    } else {
      $("verdictLabel").textContent = triage.label || "未评估";
      renderRichText($("verdictWhy"), triage.why || "");
      for (const a of triage.actions || []) acts.appendChild(el("li", null, a));
    }
    $("scoreVerdictNote").textContent = headline.label
      ? "评分明细只提供信号；是否值得打以顶部「决策」为准。"
      : (triage.label ? `评分层信号：${triage.label}` : "");

    /* 两个轴 */
    const hy = axes.hygiene || {};
    const op = axes.opportunity || {};
    $("hyScore").textContent = fmt(hy.score);
    $("hyGrade").textContent = hy.grade || "";
    $("hyBar").style.width = `${hy.score || 0}%`;
    $("hyMeta").textContent = hy.coverage_pct == null ? "" :
      `覆盖 ${hy.coverage_pct}% · ${hy.checks_evaluated ?? "?"}/${hy.checks_total ?? "?"} 项判定`;

    $("opScore").textContent = fmt(op.score);
    $("opGrade").textContent = op.grade || "";
    $("opBar").style.width = `${op.score || 0}%`;
    $("opMeta").textContent = op.coverage_pct == null ? "" :
      `覆盖 ${op.coverage_pct}% · ${op.checks_evaluated ?? "?"}/${op.checks_total ?? "?"} 项判定`;

    /* 计数 */
    const counts = (rep.coverage && rep.coverage.counts) || {};
    const dl = $("counts");
    dl.replaceChildren();
    for (const [key, label] of COUNT_LABEL) {
      if (counts[key] == null) continue;
      const row = el("div", "counts__item");
      row.appendChild(el("dt", null, label));
      row.appendChild(el("dd", "num", String(counts[key])));
      dl.appendChild(row);
    }

    /* 盲区：始终渲染，绝不隐藏 */
    const blind = triage.blind_spots || [];
    $("blind").textContent = blind.length ? "本结论不覆盖：" + blind.join(" ") : "";

    renderProfile(rep);
    renderDiscovery(rep);
    renderUncertainty(rep);
    renderEndpointMix(rep);
    renderIntel(rep);

    /* 评分明细 */
    const checks = (score.checks || []).slice().sort(
      (a, b) => (ORDER[a.status] - ORDER[b.status]) || ((b.weight || 0) - (a.weight || 0)));
    const maxW = Math.max(1, ...checks.map((c) => c.weight || 0));
    const tbody = $("checksBody");
    tbody.replaceChildren();
    for (const c of checks) {
      const tr = el("tr");
      const tdSt = el("td"); tdSt.appendChild(statusTag(c.status)); tr.appendChild(tdSt);
      tr.appendChild(el("td", "dim", AXIS_LABEL[c.axis] || c.axis));
      tr.appendChild(el("td", "id mono", c.id || ""));
      tr.appendChild(el("td", "dim", c.title || ""));
      const tdW = el("td", "al-r col-w");
      const meter = el("span", "meter");
      const track = el("span", "meter__track");
      const fill = el("span", "meter__fill");
      fill.style.width = `${Math.round((c.weight || 0) / maxW * 100)}%`;
      track.appendChild(fill);
      meter.appendChild(track);
      meter.appendChild(el("span", "num", fmt(c.weight)));
      tdW.appendChild(meter);
      tr.appendChild(tdW);
      tr.appendChild(el("td", "al-r col-w num", fmt(c.earned)));
      tbody.appendChild(tr);
    }
    $("checksCount").textContent = checks.length ? `${checks.length} 项 · 未通过优先` : "";
    if (!checks.length) {
      const tr = el("tr");
      tr.appendChild(el("td", "empty", "没有检查项"));
      tbody.appendChild(tr);
    }

    /* 端点：默认只展开前 25 条。 */
    const eps = rep.endpoints || [];
    const LIMIT = 25;
    const epsBody = $("epsBody");
    const more = $("epMore");
    let shownAll = eps.length <= LIMIT;

    const paintEndpoints = () => {
      epsBody.replaceChildren();
      const rows = shownAll ? eps : eps.slice(0, LIMIT);
      rows.forEach((e, i) => {
        const tr = el("tr");
        const verdict = e.verified || "";
        if (verdict === "usable") tr.classList.add("is-live");
        else if (verdict === "unusable") tr.classList.add("is-dead");
        tr.appendChild(el("td", "num al-r col-n", String(i + 1)));
        tr.appendChild(el("td", "mono", (e.methods || []).join(",")));
        const pathCell = el("td", "mono");
        pathCell.appendChild(el("span", null, e.path || ""));
        if (e.discovered) pathCell.appendChild(el("span", "tag tag--ghost", "内容发现"));
        tr.appendChild(pathCell);
        tr.appendChild(el("td", "dim", e.confidence || ""));
        tr.appendChild(el("td", "ep-verdict", verdict === "usable" ? "可用"
          : verdict === "unusable" ? "不可用" : "—"));
        tr.appendChild(el("td", "mono dim", (e.params || []).join(", ")));
        epsBody.appendChild(tr);
      });
      if (!eps.length) {
        const tr = el("tr");
        tr.appendChild(el("td", "empty", "没有发现端点"));
        epsBody.appendChild(tr);
      }
      more.hidden = shownAll || !eps.length;
      more.textContent = `展开全部 ${eps.length} 个`;
      const usable = eps.filter((e) => e.verified === "usable").length;
      const dead = eps.filter((e) => e.verified === "unusable").length;
      $("epCount").textContent = eps.length
        ? `${shownAll ? `${eps.length} 个` : `显示 ${Math.min(LIMIT, eps.length)} / ${eps.length} 个`}` +
          ` · 可用 ${usable}（红）/ 不可用 ${dead}（灰）`
        : "";
    };
    more.onclick = () => { shownAll = true; paintEndpoints(); };
    paintEndpoints();

    /* 参数 */
    const params = rep.parameters || [];
    const bodyFields = params.filter((p) => ["body", "form"].includes((p.in || "").toLowerCase()));

    const bodyBody = $("bodyBody");
    bodyBody.replaceChildren();
    for (const p of bodyFields) {
      const tr = el("tr");
      tr.appendChild(el("td", "mono", p.name || ""));
      tr.appendChild(el("td", "dim", p.in || ""));
      tr.appendChild(el("td", "mono dim", (p.source || "").split("/").pop()));
      bodyBody.appendChild(tr);
    }
    if (!bodyFields.length) {
      const tr = el("tr");
      tr.appendChild(el("td", "empty", "未从脚本中提取到请求体字段 —— 写端点需动态探测"));
      bodyBody.appendChild(tr);
    }

    const paramBody = $("paramBody");
    paramBody.replaceChildren();
    for (const p of params) {
      const tr = el("tr");
      tr.appendChild(el("td", "mono", p.name || ""));
      tr.appendChild(el("td", "dim", p.in || ""));
      tr.appendChild(el("td", "al-r col-n num", String((p.endpoints || []).length)));
      paramBody.appendChild(tr);
    }
    $("paramCount").textContent = params.length ? `${params.length} 个` : "";
    if (!params.length) {
      const tr = el("tr");
      tr.appendChild(el("td", "empty", "没有参数"));
      paramBody.appendChild(tr);
    }

    /* 日志 */
    const logBox = $("logBox");
    logBox.textContent = "";
    const evs = (state.job && state.job.events) || [];
    if (!evs.length) {
      logBox.textContent = `本报告从磁盘读取（${(rep.meta && rep.meta.generated_at) || "时间未知"}），` +
        "没有本次会话的运行事件。重新扫描可看到逐阶段进度。";
    } else {
      const lines = evs.map((ev) => {
        const who = ev.target ? `${ev.target} ` : "";
        return `${who}[${ev.stage || "·"}] ${ev.message || ""}`;
      });
      logBox.textContent = lines.join("\n");
    }

    /* 侧栏：当前产物与目标 */
    const dom = rep.target && rep.target.domain;
    if (dom) $("sideTarget").textContent = dom;
    const run = rep.run && rep.run.name;
    if (run) {
      $("sideRun").hidden = false;
      $("currentRun").textContent = run;
    }

    $("emptyState").hidden = true;
    $("badgeChecks").textContent = checks.length ? String(checks.length) : "";
    $("badgeEps").textContent = eps.length ? String(eps.length) : "";
    $("badgeParams").textContent = params.length ? String(params.length) : "";
    refreshDataFlags();
  };

  const loadReport = async (runName) => {
    try {
      const query = runName ? `?run=${encodeURIComponent(runName)}` : "";
      const res = await fetch(`/api/report${query}`, { credentials: "same-origin" });
      if (res.status === 401) { state.authed = false; renderGate(true); return; }
      if (!res.ok) { state.report = null; refreshDataFlags(); return; }
      state.report = await res.json();
      renderReport(state.report);
    } catch (_) { /* keep previous view */ }
  };

  /* ───────────────────────────── boot ───────────────────────────── */

  bootLook();
  fetch("/api/state", { credentials: "same-origin" })
    .then((r) => r.json())
    .then((data) => {
      state.configured = !!data.configured;
      state.rememberDays = data.remember_days || 30;
      $("ver").textContent = data.version || "";
      applyAuthorization(data.authorization);
      if (data.authed) enterApp();
      else renderGate(state.configured);
    })
    .catch(() => renderGate(false));
})();
