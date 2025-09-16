// /static/js/trends.js

let trendChart = null;

function withLoading(on) {
  const btns = document.querySelectorAll("button[data-trend]");
  btns.forEach(b => {
    b.disabled = on;
    b.classList.toggle("opacity-60", on);
  });
}

async function fetchTrend(days) {
  const res = await fetch(`/analysis/trends?days=${days}`, {
    headers: { "Accept": "application/json" }
  });
  if (!res.ok) {
    throw new Error(`Server returned ${res.status}`);
  }
  return res.json(); // { labels: [], datasets: [] }
}

function renderTrend(ctx, payload) {
  const { labels, datasets } = payload;

  // 先銷毀舊圖
  if (trendChart) {
    trendChart.destroy();
    trendChart = null;
  }

  trendChart = new Chart(ctx, {
    type: "line",
    data: {
      labels,
      datasets
    },
    options: {
      responsive: true,
      maintainAspectRatio: false, // 讓 h-96 生效
      interaction: { mode: "index", intersect: false },
      plugins: {
        legend: {
          position: "bottom",
          labels: { usePointStyle: true, boxWidth: 8 }
        },
        tooltip: {
          callbacks: {
            // e.g. "A01: 12"
            label: (ctx) => `${ctx.dataset.label}: ${ctx.parsed.y}`
          }
        }
      },
      scales: {
        x: {
          grid: { display: false },
          ticks: { autoSkip: true, maxTicksLimit: 12 }
        },
        y: {
          beginAtZero: true,
          grid: { color: "rgba(0,0,0,0.06)" }
        }
      }
    }
  });
}

async function loadTrend(days = 7) {
  const canvas = document.getElementById("trendChart");
  if (!canvas) return;
  try {
    withLoading(true);
    const payload = await fetchTrend(days);
    renderTrend(canvas.getContext("2d"), payload);
  } catch (err) {
    console.error("[Trend] Load error:", err);
    alert(`趨勢載入失敗：${err.message}`);
  } finally {
    withLoading(false);
  }
}

// 讓 HTML 的按鈕好綁事件
window.loadTrend = loadTrend;

// 預設載入 7 天
document.addEventListener("DOMContentLoaded", () => loadTrend(7));
