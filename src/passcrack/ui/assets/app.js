"use strict";

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

const state = {
  api: null,
  timers: {},
  jobs: {},
};

// ---------------------------------------------------------------------
// 启动
// ---------------------------------------------------------------------
function onReady(fn) {
  if (window.pywebview && window.pywebview.api) {
    fn();
  } else {
    document.addEventListener("pywebviewready", () => fn());
  }
}

onReady(async () => {
  state.api = window.pywebview.api;
  const info = await state.api.info();
  $("#version").textContent = "口令恢复工具 " + info.version;
  $("#platform-pill").textContent = info.platform;
  $("#disclaimer-short").textContent = info.short;
  $("#ack-text").textContent = info.ack;
  $("#modal-text").textContent = info.disclaimer;
  const list = $("#rule-list");
  list.innerHTML = "";
  info.rules.forEach(([name, desc]) => {
    const li = document.createElement("li");
    li.innerHTML = "<code>" + name + "</code> " + desc;
    list.appendChild(li);
  });
  bind();
});

// ---------------------------------------------------------------------
// 交互绑定
// ---------------------------------------------------------------------
function bind() {
  $$(".tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      $$(".tab").forEach((t) => t.classList.remove("active"));
      $$(".panel").forEach((p) => p.classList.remove("active"));
      tab.classList.add("active");
      $("#panel-" + tab.dataset.tab).classList.add("active");
    });
  });

  $("#ack").addEventListener("change", () => {
    const on = $("#ack").checked;
    $$("[data-start]").forEach((b) => (b.disabled = !on));
  });
  $$("[data-start]").forEach((b) => (b.disabled = true));

  $$("[data-start]").forEach((btn) => {
    btn.addEventListener("click", () => start(btn.dataset.start));
  });
  $$("[data-cancel]").forEach((btn) => {
    btn.addEventListener("click", () => cancel(btn.dataset.cancel));
  });

  $("#btn-disclaimer").addEventListener("click", () => $("#modal").classList.add("on"));
  $("#modal-close").addEventListener("click", () => $("#modal").classList.remove("on"));
  $("#modal").addEventListener("click", (e) => {
    if (e.target.id === "modal") $("#modal").classList.remove("on");
  });

  $("#wifi-pick").addEventListener("click", () => pickInto("#wifi-capture"));
  $("#arc-pick").addEventListener("click", () => pickInto("#arc-file"));
  $("#opt-pick").addEventListener("click", () => pickInto("#opt-wordlist", ";"));

  $("#saved-run").addEventListener("click", runSaved);
}

// ---------------------------------------------------------------------
// 参数收集
// ---------------------------------------------------------------------
function splitList(value) {
  return value
    .split(/[;,\n]/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function commonOptions() {
  return {
    builtin: $("#opt-builtin").checked,
    wordlists: splitList($("#opt-wordlist").value),
    masks: splitList($("#opt-mask").value),
    rules: splitList($("#opt-rules").value),
    workers: parseInt($("#opt-workers").value, 10) || 0,
  };
}

function ftpParams() {
  return Object.assign(commonOptions(), {
    host: $("#ftp-host").value.trim(),
    user: $("#ftp-user").value.trim(),
    port: parseInt($("#ftp-port").value, 10) || 21,
    delay: parseFloat($("#ftp-delay").value) || 0.5,
    max_attempts: parseInt($("#ftp-max").value, 10) || 0,
    tls: $("#ftp-tls").checked,
    saved_only: $("#ftp-saved").checked,
  });
}

function wifiParams() {
  return Object.assign(commonOptions(), {
    ssid: $("#wifi-ssid").value.trim(),
    capture: $("#wifi-capture").value.trim(),
    saved_only: $("#wifi-saved").checked,
  });
}

function archiveParams() {
  return Object.assign(commonOptions(), {
    file: $("#arc-file").value.trim(),
  });
}

// ---------------------------------------------------------------------
// 任务
// ---------------------------------------------------------------------
async function start(kind) {
  if (!$("#ack").checked) {
    alert("请先勾选授权确认。");
    return;
  }
  let jobId;
  try {
    if (kind === "ftp") jobId = await state.api.start_ftp(ftpParams());
    else if (kind === "wifi") jobId = await state.api.start_wifi(wifiParams());
    else if (kind === "archive") jobId = await state.api.start_archive(archiveParams());
  } catch (err) {
    showResult(kind, false, String(err.message || err));
    return;
  }
  state.jobs[kind] = jobId;
  const box = $('[data-progress="' + kind + '"]');
  box.classList.add("on");
  box.querySelector(".fill").classList.add("indeterminate");
  $('[data-result="' + kind + '"]').innerHTML = "";
  $(`[data-start="${kind}"]`).disabled = true;
  $(`[data-cancel="${kind}"]`).disabled = false;
  poll(kind);
}

async function cancel(kind) {
  const jobId = state.jobs[kind];
  if (!jobId) return;
  await state.api.cancel(jobId);
}

function poll(kind) {
  clearTimeout(state.timers[kind]);
  state.timers[kind] = setTimeout(async () => {
    const jobId = state.jobs[kind];
    if (!jobId) return;
    let snap;
    try {
      snap = await state.api.status(jobId);
    } catch (err) {
      return;
    }
    const box = $('[data-progress="' + kind + '"]');
    box.querySelector(".tried").textContent = snap.tried || 0;
    box.querySelector(".rate").textContent = formatRate(snap.rate);
    box.querySelector(".elapsed").textContent = formatDuration(snap.elapsed);
    if (snap.state === "running") {
      poll(kind);
    } else {
      box.querySelector(".fill").classList.remove("indeterminate");
      box.querySelector(".fill").style.width = "100%";
      $(`[data-start="${kind}"]`).disabled = false;
      $(`[data-cancel="${kind}"]`).disabled = true;
      if (snap.found) {
        showResult(kind, true, snap.found);
      } else {
        showResult(kind, false, snap.message || "没有找到");
      }
      if (snap.errors && snap.errors.length) {
        console.warn(snap.errors);
      }
    }
  }, 500);
}

function showResult(kind, ok, text) {
  const box = $('[data-result="' + kind + '"]');
  box.className = "result " + (ok ? "ok" : "bad");
  if (ok) {
    box.innerHTML =
      '<div class="label">找到的口令</div>' +
      '<div class="value"></div>' +
      '<button class="copy ghost small">复制</button>';
    box.querySelector(".value").textContent = text;
    box.querySelector(".copy").addEventListener("click", () => {
      navigator.clipboard.writeText(text).then(() => {
        box.querySelector(".copy").textContent = "已复制";
        setTimeout(() => (box.querySelector(".copy").textContent = "复制"), 1500);
      });
    });
  } else {
    box.innerHTML = '<div class="label">结果</div><div class="value"></div>';
    box.querySelector(".value").textContent = text;
  }
}

async function runSaved() {
  const host = $("#sv-host").value.trim();
  const ssid = $("#sv-ssid").value.trim();
  if (!host && !ssid) {
    alert("请填写 FTP 服务器地址或 WiFi SSID。");
    return;
  }
  const box = $('[data-result="saved"]');
  box.className = "result bad";
  box.innerHTML = '<div class="label">结果</div><div class="value"></div>';
  const out = [];
  if (host) {
    try {
      const r = await state.api.saved_ftp(host, $("#sv-user").value.trim());
      out.push(r ? host + "：" + r : host + "：没有找到");
    } catch (e) {
      out.push(host + "：" + e.message);
    }
  }
  if (ssid) {
    try {
      const r = await state.api.saved_wifi(ssid);
      out.push(r ? ssid + "：" + r : ssid + "：没有找到");
    } catch (e) {
      out.push(ssid + "：" + e.message);
    }
  }
  box.querySelector(".value").textContent = out.join("；");
}

async function pickInto(selector, joiner) {
  const paths = await state.api.pick_file();
  if (!paths || !paths.length) return;
  const input = $(selector);
  if (joiner) {
    const existing = splitList(input.value);
    existing.push(paths[0]);
    input.value = existing.join(joiner);
  } else {
    input.value = paths[0];
  }
}

// ---------------------------------------------------------------------
function formatRate(rate) {
  if (!rate) return "0/秒";
  if (rate >= 1000000) return (rate / 1000000).toFixed(2) + "M/秒";
  if (rate >= 1000) return (rate / 1000).toFixed(1) + "k/秒";
  return Math.round(rate) + "/秒";
}

function formatDuration(seconds) {
  const s = Math.max(0, Math.floor(seconds || 0));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  if (h) return h + ":" + String(m).padStart(2, "0") + ":" + String(sec).padStart(2, "0");
  return m + ":" + String(sec).padStart(2, "0");
}
