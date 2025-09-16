document.addEventListener("DOMContentLoaded", () => {
  const logs = document.getElementById("logs");

  function append(msg) {
    logs.textContent += msg + "\n";
    logs.scrollTop = logs.scrollHeight;
  }

  async function startTrain() {
    logs.textContent = "";
    const dotenv = document.getElementById("dotenv").value.trim();
    append("🚀 開始抓取訓練評論...");
    const r = await fetch("/api/crawl", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mode: "train", dotenv_path: dotenv || null })
    });
    const j = await r.json();
    append("Task started: " + JSON.stringify(j));
  }

  async function startClassify() {
    logs.textContent = "";
    append("🚀 開始重新分類...");
    const r = await fetch("/api/classify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ db: "webcommentIT_train", collection: "comment_train" })
    });
    const j = await r.json();
    append("Task started: " + JSON.stringify(j));
  }

  document.getElementById("btnTrainCrawl").addEventListener("click", startTrain);
  document.getElementById("btnClassify").addEventListener("click", startClassify);
});
