(function(){
  const $ = s => document.querySelector(s);
  const list = $("#statsList");
  const btnRefresh = $("#btnRefresh");
  const btnSort = $("#btnSort");
  const linkExport = $("#linkExport");

  let current = [];

  function row(label, count){
    const li = document.createElement("li");
    li.className = "flex items-center justify-between bg-white border border-slate-200 rounded-xl px-4 py-2";
    li.innerHTML = `
      <span class="font-medium text-slate-700">${label}</span>
      <span class="text-xs text-slate-500 mr-2">筆數</span>
      <span class="font-bold text-blue-600">${(count||0).toLocaleString()}</span>
    `;
    return li;
  }

  function render(){
    list.innerHTML = "";
    if (!current.length){
      list.innerHTML = `<li class="text-slate-500 text-sm">（無資料）</li>`;
      return;
    }
    current.forEach(it => list.appendChild(row(it.class || "Uncategorized", it.count || 0)));
  }

  async function load(){
    list.innerHTML = `<li class="text-slate-500 text-sm">⏳ 載入中…</li>`;
    try{
      const r = await fetch("/api/stats");
      const j = await r.json();
      if (!j.ok){ list.innerHTML = `<li class="text-rose-600 text-sm">❌ 讀取失敗</li>`; return; }
      current = j.by_class || [];
      render();
    }catch(e){
      list.innerHTML = `<li class="text-rose-600 text-sm">❌ 讀取失敗：${e}</li>`;
    }
  }

  btnRefresh && btnRefresh.addEventListener("click", load);
  btnSort && btnSort.addEventListener("click", ()=>{
    current.sort((a,b)=>(b.count||0)-(a.count||0));
    render();
  });
  linkExport && linkExport.addEventListener("click", (e)=>{
    e.preventDefault();
    const url = "/api/export?format=csv";
    window.open(url, "_blank");
  });

  load();
})();
