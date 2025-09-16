(function(){
  const $ = s => document.querySelector(s);
  const logs = $("#logs");
  const statsList = $("#statsList");
  const monList = $("#monList");

  // ------------- UI helpers -------------
  function appendLog(msg){
    logs.textContent += (msg + "\n");
    logs.scrollTop = logs.scrollHeight;
  }
  function statRow(label, count){
    const li = document.createElement("li");
    li.className = "stat-li";
    li.innerHTML = `
      <span class="stat-class">${label}</span>
      <span class="text-xs text-slate-500 mr-2">筆數</span>
      <span class="stat-count">${count.toLocaleString()}</span>
    `;
    return li;
  }

  // ------------- Stats -------------
  async function refreshStats(){
    statsList.innerHTML = `<li class="text-slate-500 text-sm">⏳ 載入中…</li>`;
    try{
      const r = await fetch("/api/stats");
      const j = await r.json();
      statsList.innerHTML = "";
      (j.by_class || []).forEach(it => {
        statsList.appendChild(statRow(it.class || "Uncategorized", it.count || 0));
      });
      if(!j.by_class || j.by_class.length === 0){
        statsList.innerHTML = `<li class="text-slate-500 text-sm">（無資料）</li>`;
      }
    }catch(e){
      statsList.innerHTML = `<li class="text-rose-600 text-sm">❌ 讀取失敗：${e}</li>`;
    }
  }

  // ------------- Crawl / Classify -------------
  async function startCrawl(mode){
    logs.textContent = "";
    appendLog(`🚀 開始抓取：${mode}`);
    const r = await fetch("/api/crawl", {
      method: "POST", headers: {"Content-Type":"application/json"},
      body: JSON.stringify({ mode })
    });
    const j = await r.json();
    $("#taskId").value = j.task_id || "";
    if(j.task_id){ watchTask(j.task_id); }
  }
  async function startClassify(){
    logs.textContent = "";
    appendLog(`🚀 開始重新分類`);
    const r = await fetch("/api/classify", {
      method: "POST", headers: {"Content-Type":"application/json"},
      body: JSON.stringify({ db: "webcommentIT", collection: "comment" })
    });
    const j = await r.json();
    $("#taskId").value = j.task_id || "";
    if(j.task_id){ watchTask(j.task_id); }
  }
  async function watchTask(taskId){
    appendLog(`--- 監看任務 ${taskId} ---`);
    const timer = setInterval(async ()=>{
      try{
        const r = await fetch(`/api/task/${taskId}`);
        if(!r.ok){ clearInterval(timer); appendLog("task not found"); return; }
        const j = await r.json();
        logs.textContent = (j.logs || []).join("\n");
        logs.scrollTop = logs.scrollHeight;
        if(j.status !== "running"){
          appendLog(`\nstatus: ${j.status}`);
          clearInterval(timer);
          refreshStats();
        }
      }catch(e){
        clearInterval(timer);
        appendLog(String(e));
      }
    }, 1200);
  }

  // ------------- Monitor panel (mock or real) -------------
  function renderMonitor(data){
    monList.innerHTML = "";
    const items = [
      {title:"運行中容器", value: data.containersRunning ?? 2, badge:"健康", level:"green"},
      {title:"總容器數", value: data.containersTotal ?? 2, badge:"管理", level:"yellow"},
      {title:"映像檔數量", value: data.imagesTotal ?? 2, badge:"可用資源", level:"yellow"},
      {title:"CPU 使用率", value: (data.cpu ?? 56.5) + "%", badge:"即時", level:"green"},
      {title:"記憶體使用率", value: (data.mem ?? 33.2) + "%", badge:"RAM", level:"yellow"},
      {title:"磁碟使用率", value: (data.disk ?? 72.1) + "%", badge:"Storage", level:"red"},
    ];
    items.forEach(it=>{
      const div = document.createElement("div");
      div.className = "monitor-item";
      div.innerHTML = `
        <div class="monitor-title flex items-center justify-between">
          <span>${it.title}</span>
          <span class="monitor-badge ${it.level==='green'?'badge-green':it.level==='yellow'?'badge-yellow':'badge-red'}">${it.badge}</span>
        </div>
        <div class="monitor-sub">${it.value}</div>
      `;
      monList.appendChild(div);
    });
  }
  async function loadMonitor(){
    // 這裡可以改成呼叫你的系統 API，例如 /api/host
    renderMonitor({});
  }

  // ------------- Events -------------
  $("#btnRefresh")?.addEventListener("click", refreshStats);
  $("#btnHot")?.addEventListener("click", () => startCrawl("hot"));
  $("#btnTrain")?.addEventListener("click", () => startCrawl("train"));
  $("#btnClassify")?.addEventListener("click", startClassify);

  $("#toggleMonitor")?.addEventListener("click", ()=>{
    const p = $("#monitorPanel");
    if(!p) return;
    p.classList.toggle("hidden");
  });

  // init
  refreshStats();
  loadMonitor();
})();
