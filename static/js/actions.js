// actions.js — 完整覆蓋版（含排程倒數、分析圖表、簡易綁定）

// ===== 小工具 =====
function ready(fn) {
  if (document.readyState !== "loading") fn();
  else document.addEventListener("DOMContentLoaded", fn);
}

async function jsonFetch(url, opts = {}) {
  const r = await fetch(url, { credentials: "same-origin", ...opts });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return await r.json();
}

// ===== 分析：OWASP Top 圖表（從 /api/stats 抓 A1~A10） =====
function ensureOwaspChartContainer() {
  let host = document.querySelector("#chart-owasp");
  if (!host) {
    const box = document.createElement("div");
    box.id = "chart-owasp";
    box.style.width = "100%";
    box.style.height = "420px";
    // 插在搜尋列後（或頁面最下）
    const searchRow = document.querySelector("input#kw")?.closest("div") || document.body;
    searchRow.parentNode.insertBefore(box, searchRow.nextSibling);
    host = box;
  }
  return host;
}

async function fetchLabelCountsForA1A10() {
  const j = await jsonFetch("/api/stats");
  if (!j.ok) throw new Error("取得標籤統計失敗");
  // 正常回傳 { ok: true, by_class: [{class:'A1',count:..}, ...] }
  const labels = Array.from({ length: 10 }, (_, i) => `A${i + 1}`);
  const map = new Map(j.by_class.map(x => [x.class, x.count]));
  return labels.map(l => ({ label: l, count: map.get(l) || 0 }));
}

function renderOwaspBar(data) {
  if (typeof echarts === "undefined") {
    console.warn("echarts 未載入；略過渲染");
    return;
  }
  const host = ensureOwaspChartContainer();
  const chart = echarts.init(host);
  const labels = data.map(d => d.label);
  const counts = data.map(d => d.count);

  chart.setOption({
    title: { text: "OWASP Top 分佈（來源：comment_train）" },
    tooltip: { trigger: "axis" },
    xAxis: { type: "category", data: labels },
    yAxis: { type: "value" },
    series: [
      { type: "bar", data: counts, label: { show: true, position: "top" }, barMaxWidth: 40 }
    ],
    toolbox: { feature: { saveAsImage: {} } }
  });
  window.addEventListener("resize", () => chart.resize());
}

async function generateOwaspChart() {
  // 先叫後端寫一份 ECharts 設定檔（可給 Dashboard 用）
  try { await fetch("/analysis/generate", { credentials: "same-origin" }); } catch (e) {}
  // 直接現場畫圖
  const data = await fetchLabelCountsForA1A10();
  renderOwaspBar(data);
}

// ===== 排程倒數（Dashboard / 爬蟲控制） =====
function bindScheduleCountdown() {
  // 允許同頁多個倒數（用 data-target 對應）
  const targets = [
    { time: document.getElementById("next-run-time"), cd: document.getElementById("next-run-countdown") }
  ].filter(t => t.time || t.cd);

  if (!targets.length) {
    // 保底：嘗試找到「下次執行」那一行並插一個 span
    const label = Array.from(document.querySelectorAll("*"))
      .find(n => n.textContent && n.textContent.trim().startsWith("下次執行"));
    if (label && label.parentNode) {
      const timeEl = document.createElement("div");
      timeEl.id = "next-run-time";
      timeEl.className = "font-mono";
      timeEl.textContent = "-";
      label.parentNode.appendChild(timeEl);

      const cdEl = document.createElement("span");
      cdEl.id = "next-run-countdown";
      cdEl.className = "ml-2 text-slate-500 text-sm";
      label.parentNode.appendChild(cdEl);

      targets.push({ time: timeEl, cd: cdEl });
    }
  }

  if (!targets.length) return;

  let timer = null;

  const pad = n => String(n).padStart(2, "0");
  function fmtLeft(ms) {
    let s = Math.max(0, Math.floor(ms / 1000));
    const h = Math.floor(s / 3600);
    s %= 3600;
    const m = Math.floor(s / 60);
    s %= 60;
    return h > 0 ? `${h}:${pad(m)}:${pad(s)}` : `${m}:${pad(s)}`;
  }

  async function loadAndStart() {
    try {
      const j = await jsonFetch("/api/schedule_info");
      if (!j.ok || !j.enabled || !j.next_epoch) {
        targets.forEach(t => t.cd && (t.cd.textContent = "—"));
        if (timer) { clearInterval(timer); timer = null; }
        return;
      }
      const nextEpoch = j.next_epoch;
      targets.forEach(t => t.time && (t.time.textContent = j.next_iso || "-"));

      function tick() {
        const left = nextEpoch - Date.now();
        if (left <= 0) {
          targets.forEach(t => t.cd && (t.cd.textContent = "即將執行…"));
          clearInterval(timer);
          timer = setTimeout(loadAndStart, 3000); // 等 Scheduler 更新下一次時間
          return;
        }
        const txt = `倒數 ${fmtLeft(left)}`;
        targets.forEach(t => {
          if (t.cd) {
            t.cd.textContent = txt;
            t.cd.title = `下次執行：${j.next_iso || ""}`;
          }
        });
      }

      if (timer) clearInterval(timer);
      tick();
      timer = setInterval(tick, 1000);
    } catch (e) {
      console.error(e);
      targets.forEach(t => t.cd && (t.cd.textContent = "（讀取失敗）"));
      if (timer) { clearInterval(timer); timer = null; }
    }
  }

  loadAndStart();
}

// ===== 綁定區 =====
function bindUX() {
  // 可自行擴充（深色模式、提示等）
}

function bindAnalysis() {
  const btn = document.getElementById("btn-gen-owasp");
  if (btn) btn.addEventListener("click", (e) => {
    e.preventDefault();
    generateOwaspChart().catch(err => {
      console.error(err);
      alert("產生圖表失敗");
    });
  });
}

function bindCrawler() {
  // 來源開關 / 立即更新等按鈕如需在此綁定可擴充
}

// ===== 初始化 =====
ready(() => {
  bindUX();
  bindAnalysis();
  bindCrawler();
  bindScheduleCountdown();   // ← 倒數計時
});
