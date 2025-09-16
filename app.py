# app.py — 完整覆蓋版（爬蟲寫 webcommentIT.comment；分析讀 webcommentIT_train.comment_train A1~A10；狀態持久化；排程倒數 API）

import os
import io
import re
import csv
import sys
import json
from glob import glob
from threading import Thread
from typing import Optional, List, Dict, Any
from datetime import datetime, date, timedelta

# 先載入 .env（一定要在讀取 os.environ 前）
try:
    from dotenv import load_dotenv
    load_dotenv(override=True)
except Exception:
    pass

from flask import (
    Flask, render_template, redirect, url_for, flash,
    request, jsonify, send_file, session, render_template_string
)
from flask_apscheduler import APScheduler
from pymongo import MongoClient, ASCENDING, TEXT

# =========================
# Flask
# =========================
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change-me-secret")

# =========================
# MongoDB（主庫：爬蟲寫入用）
# =========================
MONGO_URL  = os.environ.get("MONGO_URL", "mongodb://localhost:27017")
MONGO_DB   = os.environ.get("MONGO_DB", "webcommentIT")
MONGO_COLL = os.environ.get("MONGO_COLL", "comment")

mongo_client = MongoClient(MONGO_URL, tz_aware=True)
db   = mongo_client[MONGO_DB]
coll = db[MONGO_COLL]

def ensure_indexes():
    try:
        coll.create_index([("created_at", ASCENDING)], name="created_at_idx")
        coll.create_index([("owasp_top", ASCENDING)], name="owasp_top_idx")
        coll.create_index([("title", TEXT), ("content", TEXT)], name="text_all", default_language="english")
    except Exception as e:
        print("[Index] create index error:", e)

ensure_indexes()
print(f"[DB] connect to(main): {MONGO_URL}  db={MONGO_DB}  coll={MONGO_COLL}")

# =========================
# 分析專用資料源（讀訓練庫：webcommentIT_train.comment_train）
# =========================
ANALYSIS_DB   = os.environ.get("ANALYSIS_DB",   "webcommentIT_train")
ANALYSIS_COLL = os.environ.get("ANALYSIS_COLL", "comment_train")
ANALYSIS_CONF_MIN = float(os.environ.get("ANALYSIS_CONF_MIN", "0.0"))  # 如需信心門檻可設 0.4

mdb_an  = mongo_client[ANALYSIS_DB]
coll_an = mdb_an[ANALYSIS_COLL]
OWASP_LABELS = [f"A{i}" for i in range(1, 11)]  # A1~A10

print(f"[DB] connect to(analysis): {MONGO_URL}  db={ANALYSIS_DB}  coll={ANALYSIS_COLL}")

# =========================
# App 狀態持久化（存到主庫的 _app_state）
# =========================
STATE_COLL = db["_app_state"]  # 存在 webcommentIT 裡

def _state_get() -> dict:
    doc = STATE_COLL.find_one({"_id": "app_state"}) or {}
    return doc.get("data", {})

def _state_set(patch: dict):
    cur = _state_get()
    cur.update(patch or {})
    STATE_COLL.update_one(
        {"_id": "app_state"},
        {"$set": {"data": cur}},
        upsert=True
    )
    return cur

# =========================
# 任務 / 狀態（記憶體 + 持久化）
# =========================
TASKS: Dict[str, Any] = {}
LAST_CRAWL_AT: Optional[datetime] = None

# 三個來源的開關狀態（預設關閉）
SOURCES = {"hn": False, "reddit": False, "stackex": False}
def enabled_sources_list() -> List[str]:
    return [k for k, v in SOURCES.items() if v]

# =========================
# APScheduler
# =========================
class Config:
    SCHEDULER_API_ENABLED = True
app.config.from_object(Config())
scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()

# =========================
# 小工具
# =========================
SAFE_ID = re.compile(r"^[\w\-]+$")

def minutes_sanitized(val: int, mn: int = 1, mx: int = 24*60*7) -> int:
    try:
        val = int(val)
    except Exception:
        val = 60
    return max(mn, min(mx, val))

def template_exists(name: str) -> bool:
    try:
        app.jinja_loader.get_source(app.jinja_env, name)
        return True
    except Exception:
        return False

def render_first(*candidates, **ctx):
    """依序嘗試多個模板；找不到時回可讀提示而非 500"""
    for name in candidates:
        if template_exists(name):
            try:
                return render_template(name, **ctx)
            except Exception as e:
                return render_template_string(
                    "<h3>模板渲染錯誤</h3><pre>{{ err }}</pre>", err=str(e)
                )
    missing = "、".join(candidates)
    return render_template_string(f"<h3>缺少模板</h3><p>請提供：{missing}</p>")

# 圖表（ECharts option JSON）
CHART_DIR = os.path.join("static", "charts")
os.makedirs(CHART_DIR, exist_ok=True)

def chart_path(chart_id: str) -> str:
    if not SAFE_ID.match(chart_id):
        raise ValueError("bad chart id")
    return os.path.join(CHART_DIR, f"{chart_id}.json")

def list_charts_meta() -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    for fp in glob(os.path.join(CHART_DIR, "*.json")):
        try:
            with open(fp, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            stat = os.stat(fp)
            items.append({
                "id": cfg.get("id") or os.path.splitext(os.path.basename(fp))[0],
                "title": cfg.get("title") or "Chart",
                "mtime": stat.st_mtime,
                "created_at": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            })
        except Exception:
            continue
    items.sort(key=lambda x: x["mtime"], reverse=True)
    return items

def latest_chart_meta():
    items = list_charts_meta()
    return items[0] if items else None

# =========================
# 統一：透過 unified 爬蟲執行（串流回報）
# =========================
from subprocess import Popen, PIPE

PY_BIN = os.environ.get("PYTHON_BIN", sys.executable)
CRAWLER_TIMEOUT = int(os.environ.get("CRAWLER_TIMEOUT", "1800"))

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CRAWLER_PATH = os.path.join(BASE_DIR, "crawler_unified.py")  # 明確指向本專案內的檔案

def _run_proc_stream(cmd: list, name: str, timeout_sec: int, on_line=None) -> bool:
    """
    串流讀子程序 stdout/stderr（逐行），確保無緩衝（-u）
    cmd 僅包含參數；實際執行檔與 -u 在此函式處理。
    """
    if not os.path.exists(CRAWLER_PATH):
        if on_line:
            on_line(f"[error] 找不到 {CRAWLER_PATH}", stream="stderr")
        return False

    real_cmd = [PY_BIN, "-u", CRAWLER_PATH] + cmd
    print(f"[crawler] start {name}: {' '.join([str(x) for x in real_cmd])}")

    p = Popen(
        real_cmd,
        cwd=BASE_DIR,
        stdout=PIPE,
        stderr=PIPE,
        bufsize=1,              # 行緩衝
        universal_newlines=True # text mode
    )

    try:
        # 先讀 stdout
        for line in iter(p.stdout.readline, ""):
            if not line:
                break
            if on_line:
                on_line(line.rstrip("\n"), stream="stdout")
        # 再讀 stderr（避免阻塞）
        for line in iter(p.stderr.readline, ""):
            if not line:
                break
            if on_line:
                on_line(line.rstrip("\n"), stream="stderr")
    except Exception as e:
        if on_line:
            on_line(f"[error] {e}", stream="stderr")

    rc = p.wait(timeout=timeout_sec)
    print(f"[crawler] {name} rc={rc}")
    return rc == 0

def run_unified_only(sources: List[str], mode: str = None, progress: Dict[str, Any] = None) -> bool:
    """
    呼叫 crawler_unified.py（支援 --only 多值與別名），即時解析 stdout 更新進度。
    會先把各來源狀態設為 starting → 避免 UI 空白。
    """
    alias = {"se": "stackex", "stackexchange": "stackex", "stack": "stackex"}
    only: List[str] = []
    for s in (sources or []):
        if not s:
            continue
        k = str(s).lower().strip()
        only.append(alias.get(k, k))

    mode = (mode or os.environ.get("CRAWLER_MODE") or "default").strip()

    # 初始化進度
    if progress is not None:
        progress.setdefault("phase", "crawling")
        progress.setdefault("sources", only or ["all"])
        progress.setdefault("counts", {"processed": 0, "written": 0})
        progress.setdefault("per_source", {})
        progress.setdefault("log", [])
        for s in (only or ["all"]):
            progress["per_source"].setdefault(s, {
                "posts_total": 0, "posts_inc": 0,
                "comments_total": 0, "comments_inc": 0,
                "page_cur": 0, "page_max": 0, "status": "starting"
            })

    # 子行程只吃參數；實際路徑與 -u 在 _run_proc_stream 處理
    args = ["--mode", mode, "--include-comments"]
    if only:
        args += ["--only", ",".join(only)]

    # 正則：抓來源/頁數/統計/分類
    rx_source = re.compile(r"^\s*\[(hn|reddit|stackex|stackexchange)\]\s*", re.I)
    rx_page   = re.compile(r"(?:^|\s)page\s*[:=]\s*(\d+)\s*/\s*(\d+)", re.I)
    rx_counts = re.compile(
        r"posts\s*[:=]\s*(\d+)\s*(?:\(\+?|\+)\s*(\d+)\)?"
        r".*?(comments|replies)\s*[:=]\s*(\d+)\s*(?:\(\+?|\+)\s*(\d+)\)?",
        re.I,
    )
    rx_class  = re.compile(
        r"classif(?:y|ication).*(?:processed|proc)\s*[:=]\s*(\d+)\s*(?:\(\+?|\+)\s*(\d+)\)?.*?"
        r"(?:written|train|insert)\s*[:=]\s*(\d+)\s*(?:\(\+?|\+)\s*(\d+)\)?",
        re.I,
    )

    cur_src = None
    def on_line(line: str, stream="stdout"):
        nonlocal cur_src
        if progress is None:
            return
        # ring log
        log = progress["log"]
        tag = "E" if stream == "stderr" else " "
        log.append(f"{tag} {line}")
        if len(log) > 200:
            del log[:len(log) - 200]

        # 來源切換（如 "[hn] ..."）
        m = rx_source.search(line)
        if m:
            name = m.group(1).lower()
            cur_src = "stackex" if name.startswith("stack") else name
            progress["current_source"] = cur_src
            progress["per_source"].setdefault(cur_src, {
                "posts_total": 0, "posts_inc": 0,
                "comments_total": 0, "comments_inc": 0,
                "page_cur": 0, "page_max": 0, "status": "crawling"
            })
        # 頁數
        m = rx_page.search(line)
        if m and cur_src:
            cur, total = int(m.group(1)), int(m.group(2))
            ps = progress["per_source"][cur_src]
            ps.update({"page_cur": cur, "page_max": total, "status": "crawling"})
        # 統計
        m = rx_counts.search(line)
        if m and cur_src:
            posts_total = int(m.group(1))
            posts_added = int(m.group(2))
            comments_total = int(m.group(4))
            comments_added = int(m.group(5))
            ps = progress["per_source"][cur_src]
            ps.update({
                "posts_total": posts_total,
                "posts_inc": posts_added,
                "comments_total": comments_total,
                "comments_inc": comments_added,
                "status": "crawling"
            })
        # 分類進度
        m = rx_class.search(line)
        if m:
            processed_total, processed_inc, written_total, written_inc = map(int, m.groups())
            progress["counts"]["processed"] += processed_inc
            progress["counts"]["written"]  += written_inc
            progress["phase"] = "label"

        # 完成提示（若子程式有印）
        if cur_src and (" done" in line.lower() or " finished" in line.lower()):
            progress["per_source"][cur_src]["status"] = "done"

    ok = _run_proc_stream(args, f"unified({mode}|only={','.join(only) if only else 'all'})", CRAWLER_TIMEOUT, on_line)
    if progress is not None:
        progress["phase"] = "crawl_done"
        for s, v in progress["per_source"].items():
            if v.get("status") in ("starting", "crawling"):
                v["status"] = "done" if ok else "error"
    return ok

def _run_enabled_sources() -> List[tuple]:
    """依 UI 開關，統一只呼叫 unified；移除舊的單站執行路徑"""
    chosen = enabled_sources_list()
    if not chosen:
        print("  （無啟用來源，略過）")
        return []
    ok = run_unified_only(chosen, os.environ.get("CRAWLER_MODE", "default"), progress=TASKS.get("last_refresh"))
    return [("unified", ok)]

# =========================
# 分析圖表（改讀訓練庫 A1~A10 / auto_label）
# =========================
def create_owasp_top_chart() -> Optional[str]:
    """
    產生 ECharts 圖表設定檔到 static/charts/*.json
    資料來源：webcommentIT_train.comment_train（coll_an）
    統計欄位：auto_label（僅 A1~A10）
    """
    try:
        match = {"auto_label": {"$in": OWASP_LABELS}}
        # 如需信心門檻請解除下一行註解：
        # match["$expr"] = {"$gte": [{"$ifNull": ["$auto_conf", 1.0]}, ANALYSIS_CONF_MIN]}

        pipeline = [
            {"$match": match},
            {"$group": {"_id": "$auto_label", "count": {"$sum": 1}}},
        ]
        rows = list(coll_an.aggregate(pipeline))
        have = {r["_id"]: int(r["count"]) for r in rows}
        labels = OWASP_LABELS
        values = [have.get(k, 0) for k in labels]

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        chart_id = f"owasp_top_stats_{ts}"

        option = {
            "title": {"text": "OWASP Top 分佈（來源：comment_train）"},
            "tooltip": {"trigger": "axis"},
            "toolbox": {"feature": {"saveAsImage": {}, "dataView": {}, "restore": {}, "dataZoom": {}}},
            "grid": {"left": 40, "right": 20, "bottom": 60, "top": 50, "containLabel": True},
            "dataZoom": [{"type": "inside"}, {"type": "slider"}],
            "xAxis": {"type": "category", "data": labels, "axisLabel": {"rotate": 45}},
            "yAxis": {"type": "value"},
            "series": [{"type": "bar", "name": "Count", "data": values, "barMaxWidth": 40}],
        }
        cfg = {"id": chart_id, "title": "OWASP Top 分佈", "option": option}
        with open(chart_path(chart_id), "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        return chart_id
    except Exception as e:
        print("[create_owasp_top_chart] error:", e)
        return None

# =========================
# Pages
# =========================
@app.route("/")
def index():
    return dashboard()

@app.route("/dashboard")
def dashboard():
    latest = latest_chart_meta()
    job = scheduler.get_job("crawler_job")
    schedule = None
    if job:
        try:
            interval_min = int(getattr(job.trigger, "interval").total_seconds() // 60)
        except Exception:
            interval_min = None
        schedule = {
            "minutes": interval_min,
            "next": job.next_run_time.strftime("%Y-%m-%d %H:%M:%S") if job.next_run_time else "-"
        }
    last_crawl_iso = LAST_CRAWL_AT.strftime("%Y-%m-%d %H:%M:%S") if LAST_CRAWL_AT else None

    return render_first(
        "manage/dashboard.html", "dashboard.html",
        latest_chart=latest, schedule=schedule, last_crawl_at=last_crawl_iso
    )

@app.route("/manage/system")
def manage_system():
    return render_first("manage/system_ops.html", "system_ops.html")

@app.route("/manage/analysis")
def manage_analysis():
    return render_first("manage/data_analysis.html", "data_analysis.html")

@app.route("/manage/crawler")
def manage_crawler():
    job = scheduler.get_job("crawler_job")
    schedule = None
    if job:
        try:
            interval_min = int(getattr(job.trigger, "interval").total_seconds() // 60)
        except Exception:
            interval_min = None
        schedule = {
            "minutes": interval_min,
            "next": job.next_run_time.strftime("%Y-%m-%d %H:%M:%S") if job.next_run_time else "-"
        }
    return render_first("manage/crawler_control.html", "crawler_control.html",
                        schedule=schedule, sources=SOURCES, enabled_list=enabled_sources_list())

@app.route("/manage/ux")
def manage_ux():
    return render_first("manage/user_experience.html", "user_experience.html")

# =========================
# 系統維運
# =========================
@app.route("/ops/clear", methods=["POST"], endpoint="clear_data")
def clear_data():
    try:
        res = coll.delete_many({})
        flash(f"🗑️ 已清空 {MONGO_DB}.{MONGO_COLL}，刪除 {res.deleted_count} 筆")
    except Exception as e:
        flash(f"❌ 清空失敗：{e}")
    return redirect(url_for("manage_system"))

@app.route("/ops/export", methods=["POST"], endpoint="export_data")
def export_data():
    limit = int(request.form.get("limit", 50000))
    cur = coll.find({}, projection={"_id": 0}).limit(limit)

    buf = io.StringIO()
    writer = None
    count = 0
    for doc in cur:
        if writer is None:
            headers = sorted(doc.keys())
            writer = csv.DictWriter(buf, fieldnames=headers, extrasaction="ignore")
            writer.writeheader()
        row = {k: (v if isinstance(v, (str, int, float, type(None))) else str(v)) for k, v in doc.items()}
        writer.writerow(row)
        count += 1

    byte_buf = io.BytesIO(buf.getvalue().encode("utf-8-sig"))
    fname = f"{MONGO_DB}_{MONGO_COLL}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    flash(f"📁 已匯出 {count} 筆資料為 CSV")
    return send_file(byte_buf, as_attachment=True, download_name=fname, mimetype="text/csv")

@app.route("/ops/refresh_cache", methods=["POST"], endpoint="refresh_cache")
def ops_refresh_cache():
    flash("✅ 快取已重新整理（示範）")
    return redirect(url_for("manage_system"))

# 小工具：檢查目前 DB 與筆數
@app.route("/api/db_info")
def api_db_info():
    return jsonify({
        "url": MONGO_URL, "db": MONGO_DB, "coll": MONGO_COLL,
        "count": coll.count_documents({})
    })

# =========================
# 分析：圖表 / 趨勢 / 搜尋（改讀 coll_an + auto_label）
# =========================
@app.route("/analysis/generate")
def generate_charts():
    cid = create_owasp_top_chart()
    flash("📑 已產生互動式圖表" if cid else "❌ 產生圖表失敗")
    return redirect(url_for("manage_analysis"))

@app.route("/analysis/trends")
def view_trends():
    """
    改讀 coll_an（訓練庫），以 auto_label(A1~A10) 為類別，
    依 day 進行分組統計；Accept: application/json 則回資料，否則 render 頁面。
    """
    wants_json = request.accept_mimetypes.best == "application/json"
    days = minutes_sanitized(int(request.args.get("days", 7)), mn=1, mx=90)

    if wants_json:
        try:
            start_dt = datetime.combine(date.today() - timedelta(days=days - 1), datetime.min.time())
            match = {
                "auto_label": {"$in": OWASP_LABELS},
                "created_at": {"$gte": start_dt},
            }
            # 如需信心門檻請解除下一行註解：
            # match["$expr"] = {"$gte": [{"$ifNull": ["$auto_conf", 1.0]}, ANALYSIS_CONF_MIN]}

            pipeline = [
                {"$match": match},
                {"$project": {"day": {"$dateToString": {"format": "%m/%d", "date": "$created_at"}}, "cls": "$auto_label"}},
                {"$group": {"_id": {"day": "$day", "cls": "$cls"}, "c": {"$sum": 1}}},
                {"$sort": {"_id.day": 1}}
            ]
            rows = list(coll_an.aggregate(pipeline))
            labels = [(date.today() - timedelta(days=i)).strftime("%m/%d") for i in range(days - 1, -1, -1)]
            labels_set = set(labels)
            by_cls: Dict[str, Dict[str, int]] = {}
            for r in rows:
                d = r["_id"]["day"]
                cls = r["_id"].get("cls") or "Uncategorized"
                if d not in labels_set:
                    continue
                by_cls.setdefault(cls, {lab: 0 for lab in labels})
                by_cls[cls][d] = int(r["c"])
            datasets = []
            order = {f"A{i}": i for i in range(1, 11)}
            for cls in sorted(by_cls.keys(), key=lambda k: order.get(k, 99)):
                day_map = by_cls[cls]
                datasets.append({"label": cls, "data": [day_map[lab] for lab in labels]})
            return jsonify({"labels": labels, "datasets": datasets})
        except Exception as e:
            print("[trends] error:", e)
            return jsonify({"labels": [], "datasets": []})

    return render_first("manage/trends.html", "trends.html")

@app.route("/search")
def search():
    q = (request.args.get("q") or "").strip()
    if not q:
        flash("🔎 搜尋：關鍵字為空")
        return redirect(url_for("manage_analysis"))
    try:
        cursor = coll.find(
            {"$text": {"$search": q}},
            {"score": {"$meta": "textScore"}, "title": 1, "content": 1, "url": 1}
        ).sort([("score", {"$meta": "textScore"})]).limit(50)
        count = len(list(cursor))
        flash(f"🔎 搜尋「{q}」找到 {count} 筆（top 50）")
    except Exception:
        count = coll.count_documents({"content": {"$regex": q, "$options": "i"}})
        flash(f"🔎 搜尋「{q}）」找到 {count} 筆（regex）")
    return redirect(url_for("manage_analysis"))

# =========================
# /api/stats（改讀訓練庫 A1~A10 / auto_label）
# =========================
@app.route("/api/stats")
def api_stats():
    try:
        match = {"auto_label": {"$in": OWASP_LABELS}}
        # 如需信心門檻請解除下一行註解：
        # match["$expr"] = {"$gte": [{"$ifNull": ["$auto_conf", 1.0]}, ANALYSIS_CONF_MIN]}

        pipeline = [
            {"$match": match},
            {"$group": {"_id": "$auto_label", "count": {"$sum": 1}}}
        ]
        rows = list(coll_an.aggregate(pipeline))
        have = {r["_id"]: int(r["count"]) for r in rows}
        by_class = [{"class": lab, "count": have.get(lab, 0)} for lab in OWASP_LABELS]
        return jsonify({"ok": True, "by_class": by_class})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

# =========================
# 取得排程資訊（倒數計時用）
# =========================
@app.get("/api/schedule_info")
def api_schedule_info():
    try:
        job = scheduler.get_job("crawler_job")
        enabled = job is not None
        minutes = None
        next_epoch = None
        next_iso = None

        if enabled:
            try:
                td = getattr(job.trigger, "interval", None)
                if td:
                    minutes = int(td.total_seconds() // 60)
            except Exception:
                minutes = None

            if job.next_run_time:
                nxt = job.next_run_time
                next_epoch = int(nxt.timestamp() * 1000)  # 給前端做倒數
                next_iso = nxt.strftime("%Y-%m-%d %H:%M:%S")

        return jsonify({
            "ok": True,
            "enabled": enabled,
            "minutes": minutes,
            "next_epoch": next_epoch,
            "next_iso": next_iso,
            "server_now_epoch": int(datetime.now().timestamp() * 1000),
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

# =========================
# 圖表 API（ECharts）
# =========================
@app.route("/api/charts")
def api_charts():
    return jsonify({"ok": True, "items": list_charts_meta()})

@app.route("/api/chart/<chart_id>")
def api_chart(chart_id: str):
    try:
        with open(chart_path(chart_id), "r", encoding="utf-8") as f:
            return jsonify(json.load(f))
    except Exception as e:
        return jsonify({"error": str(e)}), 404

@app.route("/api/charts/delete", methods=["POST"])
def api_charts_delete():
    data = request.get_json(silent=True) or {}
    chart_id = (data.get("id") or "").strip()
    if not chart_id or not SAFE_ID.match(chart_id):
        return jsonify({"ok": False, "error": "invalid id"}), 400
    try:
        os.remove(chart_path(chart_id))
        return jsonify({"ok": True})
    except FileNotFoundError:
        return jsonify({"ok": False, "error": "not found"}), 404
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

# =========================
# 來源開關（加：持久化）
# =========================
@app.route("/crawler/source/<src>/toggle", methods=["POST"])
def toggle_source(src: str):
    if src not in SOURCES:
        flash("⚠️ 未知來源")
        return redirect(url_for("manage_crawler"))
    SOURCES[src] = not SOURCES[src]
    _state_set({"sources": SOURCES})  # ← 寫回持久化
    state = "已開啟" if SOURCES[src] else "已關閉"
    flash(f"來源 {src}：{state}")
    return redirect(url_for("manage_crawler"))

@app.route("/api/sources")
def api_sources():
    return jsonify({"ok": True, "sources": SOURCES, "enabled": enabled_sources_list()})

# =========================
# 即時更新（背景）
# =========================
def _touch_last_crawl():
    global LAST_CRAWL_AT
    LAST_CRAWL_AT = datetime.now()

def do_refresh_now_task(sources_override: Optional[List[str]] = None, mode: Optional[str] = None):
    """可接受 sources_override 直接跑 unified；若未提供則依 UI 開關"""
    progress: Dict[str, Any] = {
        "status": "running",
        "phase": "init",
        "log": [],
        "counts": {"processed": 0, "written": 0},
        "per_source": {},
        "sources": sources_override or enabled_sources_list(),
    }
    TASKS["last_refresh"] = progress
    try:
        print("⏱️ 立即更新：開始  sources_override=", sources_override, " mode=", mode)
        before = coll.count_documents({})

        ok = run_unified_only(progress["sources"], mode or os.environ.get("CRAWLER_MODE", "default"), progress=progress)
        results = [("unified", ok)]

        _touch_last_crawl()
        _state_set({"last_crawl_at": LAST_CRAWL_AT.isoformat()})  # ← 持久化「上次更新」
        chart_id = create_owasp_top_chart()  # 產圖改讀訓練庫
        after = coll.count_documents({})
        delta = after - before

        progress.update({
            "status": "done",
            "phase": "done",
            "results": results,
            "chart_id": chart_id,
            "finished_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "added": int(delta)
        })
        print("⏱️ 立即更新：完成", results)
    except Exception as e:
        progress.update({"status": "error", "error": str(e)})
        print("⏱️ 立即更新：錯誤", e)

@app.route("/crawler/refresh_now", methods=["POST"])
def refresh_now():
    if not enabled_sources_list():
        flash("⚠️ 尚未開啟任何來源，請先在上方卡片「開啟」至少一個來源")
        return redirect(url_for("manage_crawler"))
    TASKS["last_refresh"] = {"status": "running", "started_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "log": [], "counts": {"processed":0,"written":0}, "per_source": {}}
    Thread(target=do_refresh_now_task, daemon=True).start()
    flash("⏱️ 已觸發即時更新（背景執行），完成後首頁會出現最新圖表")
    return redirect(url_for("manage_crawler"))

@app.route("/api/refresh_now", methods=["POST"])
def refresh_now_api():
    """
    JSON body（可選）:
    {
      "mode": "default" | "refresh" | "backfill",
      "sources": ["hn","reddit","stackex"]  // 若提供，將忽略 UI 開關；若未提供，將使用已開啟來源
    }
    """
    data = request.get_json(silent=True) or {}
    mode = (data.get("mode") or os.environ.get("CRAWLER_MODE") or "default").strip()
    sources = data.get("sources")

    # 若沒提供 sources 且 UI 也沒開啟任何來源 → 回 400
    if not sources and not enabled_sources_list():
        return jsonify({"ok": False, "error": "no_sources", "message": "請指定 sources 或先開啟至少一個來源"}), 400

    TASKS["last_refresh"] = {"status": "running", "started_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "log": [], "counts": {"processed":0,"written":0}, "per_source": {}}
    Thread(target=do_refresh_now_task, kwargs={"sources_override": sources or enabled_sources_list(), "mode": mode}, daemon=True).start()
    return jsonify({"ok": True, "message": "已觸發即時更新（背景執行）", "mode": mode, "sources": sources or enabled_sources_list()})

def _compose_status_text(info: Dict[str, Any]) -> str:
    lines = []
    lines.append(f"狀態：{info.get('status','idle')}（階段：{info.get('phase','-')}）")
    per = info.get("per_source") or {}
    order = ["hn", "reddit", "stackex"]
    for s in order:
        if s not in per: 
            continue
        v = per[s]
        lines.append(
            f"[{s}] 貼文={v.get('posts_total',0)}（+{v.get('posts_inc',0)}）  "
            f"留言={v.get('comments_total',0)}（+{v.get('comments_inc',0)}）  "
            f"頁={v.get('page_cur',0)}/{v.get('page_max',0)}  狀態={v.get('status','')}"
        )
    counts = info.get("counts") or {}
    lines.append(f"分類：processed={counts.get('processed',0)} / 寫入訓練 +{counts.get('written',0)}")
    return "\n".join(lines)

@app.route("/api/refresh_status")
def refresh_status():
    info = TASKS.get("last_refresh", {"status": "idle"})
    log_tail = (info.get("log") or [])[-80:]
    return jsonify({
        "ok": True,
        "status": info.get("status", "idle"),
        "phase": info.get("phase", "idle"),
        "sources": info.get("sources"),
        "current_source": info.get("current_source"),
        "page": info.get("page"),
        "counts": info.get("counts", {}),
        "per_source": info.get("per_source", {}),
        "status_text": _compose_status_text(info),
        "results": info.get("results"),
        "chart_id": info.get("chart_id"),
        "finished_at": info.get("finished_at"),
        "added": info.get("added"),
        "last_crawl_at": LAST_CRAWL_AT.strftime("%Y-%m-%d %H:%M:%S") if LAST_CRAWL_AT else None,
        "log_tail": log_tail,
    })

# =========================
# 排程（定期更新）+ 啟動時回填
# =========================
def scheduled_crawl():
    print("⏰ 排程觸發")
    TASKS["last_refresh"] = {"status": "running", "phase": "init", "log": [], "counts": {"processed":0,"written":0}, "per_source": {}}
    _run_enabled_sources()
    _touch_last_crawl()
    _state_set({"last_crawl_at": LAST_CRAWL_AT.isoformat()})  # ← 持久化
    TASKS["last_refresh"].update({"status": "done", "phase": "done", "finished_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})

def _rehydrate_from_state():
    """重啟伺服器時，從 Mongo 還原 SOURCES / LAST_CRAWL_AT / Scheduler"""
    global SOURCES, LAST_CRAWL_AT
    st = _state_get()

    # 來源開關
    if "sources" in st and isinstance(st["sources"], dict):
        for k in SOURCES.keys():
            if k in st["sources"]:
                SOURCES[k] = bool(st["sources"][k])

    # 上次更新時間
    try:
        if st.get("last_crawl_at"):
            LAST_CRAWL_AT = datetime.fromisoformat(st["last_crawl_at"])
    except Exception:
        LAST_CRAWL_AT = None

    # 排程
    sch = st.get("scheduler") or {}
    enabled = bool(sch.get("enabled"))
    minutes = int(sch.get("minutes") or 60)
    old = scheduler.get_job("crawler_job")
    if old:
        scheduler.remove_job("crawler_job")
    if enabled:
        scheduler.add_job(id="crawler_job", func=scheduled_crawl, trigger="interval", minutes=minutes)

# 啟動後立即回填狀態（需在 scheduled_crawl 定義之後）
_rehydrate_from_state()

@app.route("/crawler/schedule/start", methods=["POST"])
def start_schedule():
    preset = (request.form.get("preset") or "").strip()
    custom_value = (request.form.get("custom_value") or "").strip()
    custom_unit = (request.form.get("custom_unit") or "minutes").strip()

    minutes = 60
    if preset and preset != "custom":
        if preset.endswith("m"):
            minutes = minutes_sanitized(preset[:-1])
        elif preset.endswith("h"):
            minutes = minutes_sanitized(int(preset[:-1]) * 60)
    elif preset == "custom" and custom_value.isdigit():
        val = int(custom_value)
        minutes = minutes_sanitized(val if custom_unit == "minutes" else val * 60)

    old = scheduler.get_job("crawler_job")
    if old:
        scheduler.remove_job("crawler_job")
    scheduler.add_job(id="crawler_job", func=scheduled_crawl, trigger="interval", minutes=minutes)

    _state_set({"scheduler": {"enabled": True, "minutes": minutes}})  # ← 持久化
    flash(f"📅 定期更新已啟動，每 {minutes} 分鐘執行一次")
    return redirect(url_for("manage_crawler"))

@app.route("/crawler/schedule/stop", methods=["POST"])
def stop_schedule():
    job = scheduler.get_job("crawler_job")
    if job:
        scheduler.remove_job("crawler_job")
        _state_set({"scheduler": {"enabled": False}})  # ← 持久化
        flash("✋ 定期更新已停止")
    else:
        flash("⚠️ 沒有正在執行的定期任務")
    return redirect(url_for("manage_crawler"))

# =========================
# 其它簡易 API
# =========================
@app.route("/api/ux/toggle_dark", methods=["POST"])
def api_ux_toggle_dark():
    cur = bool(session.get("dark_mode", False))
    session["dark_mode"] = not cur
    return jsonify({"ok": True, "enabled": session["dark_mode"]})

@app.route("/ux/darkmode", methods=["POST"])
def toggle_dark_mode():
    cur = bool(session.get("dark_mode", False))
    session["dark_mode"] = not cur
    flash("🌙 深色模式：已切換 " + ("（深色）" if session["dark_mode"] else "（淺色）"))
    return redirect(url_for("manage_ux"))

@app.route("/api/export")
def api_export():
    return redirect(url_for("export_data"))

@app.route("/api/clear", methods=["POST"])
def api_clear():
    try:
        res = coll.delete_many({})
        return jsonify({"ok": True, "deleted": res.deleted_count, "db": MONGO_DB, "collection": MONGO_COLL})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/crawl", methods=["POST"])
def api_crawl():
    data = request.get_json(silent=True) or {}
    mode = data.get("mode", "hot")
    task_id = f"task_{datetime.now().strftime('%H%M%S%f')}"
    TASKS[task_id] = {"status": "running", "logs": [f"Started crawl: {mode}"]}
    return jsonify({"ok": True, "task_id": task_id})

@app.route("/api/classify", methods=["POST"])
def api_classify():
    _ = request.get_json(silent=True) or {}
    task_id = f"task_{datetime.now().strftime('%H%M%S%f')}"
    TASKS[task_id] = {"status": "running", "logs": ["Started classify"]}
    return jsonify({"ok": True, "task_id": task_id})

@app.route("/api/task/<task_id>")
def api_task(task_id: str):
    t = TASKS.get(task_id)
    if not t:
        return jsonify({"error": "not found"}), 404
    if t["status"] == "running" and len(t["logs"]) < 5:
        t["logs"].append("執行中 …")
    elif t["status"] == "running":
        t["status"] = "done"
        t["logs"].append("✅ 任務完成")
    return jsonify(t)

@app.route("/api/trends")
def api_trends():
    # 示範資料（保留）
    days = minutes_sanitized(int(request.args.get("days", 7)), mn=1, mx=90)
    today = date.today()
    labels = [(today - timedelta(days=i)).strftime("%m/%d") for i in range(days - 1, -1, -1)]
    datasets = []
    for cat, mul in [("A01", 1), ("A02", 2), ("A03", 3)]:
        datasets.append({"label": cat, "data": [((i * mul) % 10) for i in range(days)]})
    return jsonify({"labels": labels, "datasets": datasets})

# ========= 你要求的結尾 =========
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
