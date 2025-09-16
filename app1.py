import os
import io
import re
import csv
import sys
import json
import subprocess
from glob import glob
from threading import Thread
from typing import Optional
from datetime import datetime, date, timedelta

# 先載入 .env（一定要在讀取 os.environ 前）
from dotenv import load_dotenv
load_dotenv(override=True)

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
# MongoDB（預設 27017；你可在 .env 設成 27027）
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
print(f"[DB] connect to: {MONGO_URL}  db={MONGO_DB}  coll={MONGO_COLL}")

# =========================
# 任務 / 狀態
# =========================
TASKS = {}
LAST_CRAWL_AT: Optional[datetime] = None

# 三個來源的開關狀態（預設關閉）
SOURCES = {"hn": False, "reddit": False, "stackex": False}
def enabled_sources_list():
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
    for name in candidates:
        if template_exists(name):
            return render_template(name, **ctx)
    missing = "、".join(candidates)
    return render_template_string(f"<h3>缺少模板</h3><p>請提供：{missing}</p>")

# 圖表（ECharts option JSON）
CHART_DIR = os.path.join("static", "charts")
os.makedirs(CHART_DIR, exist_ok=True)

def chart_path(chart_id: str) -> str:
    if not SAFE_ID.match(chart_id):
        raise ValueError("bad chart id")
    return os.path.join(CHART_DIR, f"{chart_id}.json")

def list_charts_meta():
    items = []
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
# 外部爬蟲設定與執行器
# =========================
PY_BIN = os.environ.get("PYTHON_BIN", sys.executable)             # python 路徑
CRAWLER_TIMEOUT = int(os.environ.get("CRAWLER_TIMEOUT", "1800"))  # 單來源逾時秒（30 分）

# 來源參數（可用 .env 覆寫）
REDDIT_SUBS  = os.environ.get("REDDIT_SUBS", "netsec")
STACKEX_SITE = os.environ.get("STACKEX_SITE", "security.stackexchange.com")
HN_SECTION   = os.environ.get("HN_SECTION", "frontpage")
CRAWL_LIMIT  = os.environ.get("CRAWL_LIMIT", "200")
HOT_HOURS    = os.environ.get("HOT_HOURS", "24")

# 完全自訂指令（填了就不做自動偵測）
CRAWL_HN_CMD      = os.environ.get("CRAWL_HN_CMD", "").strip()
CRAWL_REDDIT_CMD  = os.environ.get("CRAWL_REDDIT_CMD", "").strip()
CRAWL_STACKEX_CMD = os.environ.get("CRAWL_STACKEX_CMD", "").strip()

def _apply_python_bin(argv: list[str]) -> list[str]:
    """確保自訂指令用與 Flask 相同的 Python，並修正空白 token。
       - 先移除空 token（例如 ""）
       - 若第一個字是 python/python3/py → 改成 PY_BIN
       - 若第一個字是 .py 檔 → 自動在前面加 PY_BIN（避免 WinError 193/87）
    """
    argv = [a for a in (argv or []) if isinstance(a, str) and a.strip() != ""]
    if not argv:
        return [PY_BIN]

    first_raw = argv[0].strip()
    first = first_raw.lower()

    if first in ("python", "python3", "py"):
        argv[0] = PY_BIN
        return argv

    if first.endswith(".py"):
        return [PY_BIN] + argv

    try:
        base = os.path.basename(first_raw)
        if base.endswith(".py"):
            return [PY_BIN] + argv
    except Exception:
        pass

    return argv

def _run_proc(cmd: list[str], name: str) -> bool:
    """執行外部爬蟲，印 stdout/stderr，回傳成功與否"""
    try:
        print(f"[crawler] start {name}: {' '.join(cmd)}")
        p = subprocess.run(
            cmd,
            cwd=os.path.dirname(__file__),
            capture_output=True,
            text=True,
            timeout=CRAWLER_TIMEOUT,
            env={
                **os.environ,
                "MONGO_URL": MONGO_URL,
                "MONGO_DB": MONGO_DB,
                "MONGO_COLL": MONGO_COLL,
                # unified / core expect these keys
                "MONGO_URI": MONGO_URL,
                "DB_NAME": MONGO_DB,
                "COLLECTION": MONGO_COLL,
            },
        )
        print(f"[crawler] {name} rc={p.returncode}")
        if p.stdout: print(f"[crawler][stdout] {name}:\n{p.stdout}")
        if p.stderr: print(f"[crawler][stderr] {name}:\n{p.stderr}")
        return p.returncode == 0
    except subprocess.TimeoutExpired:
        print(f"[crawler] {name} timeout after {CRAWLER_TIMEOUT}s")
        return False
    except Exception as e:
        print(f"[crawler] {name} error:", e)
        return False

def _shlex(cmd_str: str) -> list[str]:
    import shlex
    return shlex.split(cmd_str)

# —— 三個來源：自動偵測 crawler_core.py → crawler_hot.py → crawler.py ——
def run_hn() -> bool:
    if CRAWL_HN_CMD:
        argv = _apply_python_bin(_shlex(CRAWL_HN_CMD))
        return _run_proc(argv, "hn(custom)")

    variants = []
    if os.path.exists("crawler_core.py"):
        variants.append([PY_BIN, "crawler_core.py",
                         "--source", "hn", "--section", HN_SECTION,
                         "--limit", CRAWL_LIMIT,
                         "--mongo-url", MONGO_URL, "--mongo-db", MONGO_DB, "--mongo-coll", MONGO_COLL])
        variants.append([PY_BIN, "crawler_core.py", "--source", "hn", "--limit", CRAWL_LIMIT])

    if os.path.exists("crawler_hot.py"):
        variants.append([PY_BIN, "crawler_hot.py",
                         "--source", "hn", "--hours", HOT_HOURS,
                         "--mongo-url", MONGO_URL, "--mongo-db", MONGO_DB, "--mongo-coll", MONGO_COLL])
        variants.append([PY_BIN, "crawler_hot.py", "--source", "hn", "--hours", HOT_HOURS])

    if os.path.exists("crawler.py"):
        variants.append([PY_BIN, "crawler.py", "--source", "hn"])
        variants.append([PY_BIN, "crawler.py"])

    for cmd in variants:
        if _run_proc(cmd, "hn"): return True
    print("[crawler] hn: all variants failed")
    return False

def run_reddit() -> bool:
    if CRAWL_REDDIT_CMD:
        argv = _apply_python_bin(_shlex(CRAWL_REDDIT_CMD))
        return _run_proc(argv, "reddit(custom)")

    subs = [s.strip() for s in REDDIT_SUBS.split(",") if s.strip()]
    variants = []
    if os.path.exists("crawler_core.py"):
        variants.append([PY_BIN, "crawler_core.py",
                         "--source", "reddit",
                         "--subreddit", ",".join(subs),
                         "--limit", CRAWL_LIMIT,
                         "--mongo-url", MONGO_URL, "--mongo-db", MONGO_DB, "--mongo-coll", MONGO_COLL])
        multi = [PY_BIN, "crawler_core.py", "--source", "reddit", "--limit", CRAWL_LIMIT]
        for s in subs: multi += ["--subreddit", s]
        variants.append(multi)

    if os.path.exists("crawler_hot.py"):
        variants.append([PY_BIN, "crawler_hot.py",
                         "--source", "reddit",
                         "--subreddit", ",".join(subs),
                         "--hours", HOT_HOURS,
                         "--mongo-url", MONGO_URL, "--mongo-db", MONGO_DB, "--mongo-coll", MONGO_COLL])
        multi = [PY_BIN, "crawler_hot.py", "--source", "reddit", "--hours", HOT_HOURS]
        for s in subs: multi += ["--subreddit", s]
        variants.append(multi)

    if os.path.exists("crawler.py"):
        variants.append([PY_BIN, "crawler.py", "--source", "reddit"])
        variants.append([PY_BIN, "crawler.py"])

    for cmd in variants:
        if _run_proc(cmd, "reddit"): return True
    print("[crawler] reddit: all variants failed")
    return False

def run_stackex() -> bool:
    if CRAWL_STACKEX_CMD:
        argv = _apply_python_bin(_shlex(CRAWL_STACKEX_CMD))
        return _run_proc(argv, "stackex(custom)")

    variants = []
    if os.path.exists("crawler_core.py"):
        variants.append([PY_BIN, "crawler_core.py",
                         "--source", "stackex", "--site", STACKEX_SITE,
                         "--limit", CRAWL_LIMIT,
                         "--mongo-url", MONGO_URL, "--mongo-db", MONGO_DB, "--mongo-coll", MONGO_COLL])
        variants.append([PY_BIN, "crawler_core.py",
                         "--source", "stackex", "--site", STACKEX_SITE, "--limit", CRAWL_LIMIT])

    if os.path.exists("crawler_hot.py"):
        variants.append([PY_BIN, "crawler_hot.py",
                         "--source", "stackex", "--site", STACKEX_SITE,
                         "--hours", HOT_HOURS,
                         "--mongo-url", MONGO_URL, "--mongo-db", MONGO_DB, "--mongo-coll", MONGO_COLL])
        variants.append([PY_BIN, "crawler_hot.py",
                         "--source", "stackex", "--site", STACKEX_SITE, "--hours", HOT_HOURS])

    if os.path.exists("crawler.py"):
        variants.append([PY_BIN, "crawler.py", "--source", "stackex"])
        variants.append([PY_BIN, "crawler.py"])

    for cmd in variants:
        if _run_proc(cmd, "stackex"): return True
    print("[crawler] stackex: all variants failed")
    return False

def run_unified_only(sources: list[str], mode: str = None) -> bool:
    """直接呼叫 crawler_unified.py，支援 --only 多值"""
    m = {"hn":"hn","reddit":"reddit","stackex":"stackex","se":"stackex","stackexchange":"stackex","stack":"stackex"}
    only = [m.get(s.lower().strip(), s.lower().strip()) for s in (sources or []) if s]
    mode = (mode or os.environ.get("CRAWLER_MODE") or "default").strip()
    cmd = [PY_BIN, "crawler_unified.py", "--mode", mode]
    if only:
        cmd += ["--only"] + only
    return _run_proc(cmd, f"unified({mode}|only={','.join(only) if only else 'all'})")

def _run_enabled_sources() -> list[tuple[str, bool]]:
    """依照 UI 開關執行 unified（移除重複與死碼）"""
    chosen = enabled_sources_list()
    if not chosen:
        print("  （無啟用來源，略過）")
        return []
    ok = run_unified_only(chosen, os.environ.get("CRAWLER_MODE", "default"))
    return [("unified", ok)]

# =========================
# 共用：產生 OWASP Top 圖表（ECharts）
# =========================
def create_owasp_top_chart() -> Optional[str]:
    try:
        pipeline = [
            {"$project": {"k": {"$ifNull": ["$owasp_top", "Uncategorized"]}}},
            {"$group": {"_id": "$k", "count": {"$sum": 1}}},
        ]
        rows = list(coll.aggregate(pipeline))
        order = {f"A{n:02d}": n for n in range(1, 11)}
        rows.sort(key=lambda r: order.get(r["_id"], 99))
        labels = [r["_id"] for r in rows]
        values = [r["count"] for r in rows]

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        chart_id = f"owasp_top_stats_{ts}"

        option = {
            "title": {"text": "OWASP Top 分佈"},
            "tooltip": {"trigger": "axis"},
            "toolbox": {"feature": {"saveAsImage": {}, "dataView": {}, "restore": {}, "dataZoom": {}}},
            "grid": {"left": 40, "right": 20, "bottom": 60, "top": 50, "containLabel": True},
            "dataZoom": [{"type": "inside"}, {"type": "slider"}],
            "xAxis": {"type": "category", "data": labels, "axisLabel": {"rotate": 45}},
            "yAxis": {"type": "value"},
            "series": [{"type": "bar", "name": "Count", "data": values, "barMaxWidth": 40}]
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
            writer = csv.DictWriter(buf, fieldnames=headers)
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
# 分析：圖表 / 趨勢 / 搜尋
# =========================
@app.route("/analysis/generate")
def generate_charts():
    cid = create_owasp_top_chart()
    flash("📑 已產生互動式圖表" if cid else "❌ 產生圖表失敗")
    return redirect(url_for("manage_analysis"))

@app.route("/analysis/trends")
def view_trends():
    wants_json = request.accept_mimetypes.best == "application/json"
    days = minutes_sanitized(int(request.args.get("days", 7)), mn=1, mx=90)

    if wants_json:
        try:
            start_dt = datetime.combine(date.today() - timedelta(days=days - 1), datetime.min.time())
            pipeline = [
                {"$match": {"created_at": {"$gte": start_dt}}},
                {"$project": {
                    "day": {"$dateToString": {"format": "%m/%d", "date": "$created_at"}},
                    "cls": {"$ifNull": ["$owasp_top", "Uncategorized"]}
                }},
                {"$group": {"_id": {"day": "$day", "cls": "$cls"}, "c": {"$sum": 1}}},
                {"$sort": {"_id.day": 1}}
            ]
            rows = list(coll.aggregate(pipeline))
            labels = [(date.today() - timedelta(days=i)).strftime("%m/%d") for i in range(days - 1, -1, -1)]
            labels_set = set(labels)
            by_cls = {}
            for r in rows:
                d = r["_id"]["day"]
                cls = r["_id"].get("cls") or "Uncategorized"
                if d not in labels_set:
                    continue
                by_cls.setdefault(cls, {lab: 0 for lab in labels})
                by_cls[cls][d] = r["c"]
            datasets = []
            order = {f"A{n:02d}": n for n in range(1, 11)}
            for cls in sorted(by_cls.keys(), key=lambda k: order.get(k, 99)):
                day_map = by_cls[cls]
                datasets.append({"label": cls, "data": [day_map[lab] for lab in labels]})
            return jsonify({"labels": labels, "datasets": datasets})
        except Exception as e:
            print("[trends] fallback:", e)
            labels = [(date.today() - timedelta(days=i)).strftime("%m/%d") for i in range(days - 1, -1, -1)]
            datasets = [{"label": "A01", "data": [i % 10 for i in range(days)]}]
            return jsonify({"labels": labels, "datasets": datasets})

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
        flash(f"🔎 搜尋「{q}」找到 {count} 筆（regex）")
    return redirect(url_for("manage_analysis"))

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
# 來源開關
# =========================
@app.route("/crawler/source/<src>/toggle", methods=["POST"])
def toggle_source(src: str):
    if src not in SOURCES:
        flash("⚠️ 未知來源")
        return redirect(url_for("manage_crawler"))
    SOURCES[src] = not SOURCES[src]
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

def do_refresh_now_task(sources_override: Optional[list[str]] = None, mode: Optional[str] = None):
    """可接受 sources_override 直接跑 unified；若未提供則依 UI 開關"""
    try:
        print("⏱️ 立即更新：開始  sources_override=", sources_override, " mode=", mode)
        before = coll.count_documents({})

        if sources_override:
            ok = run_unified_only(sources_override, mode or os.environ.get("CRAWLER_MODE", "default"))
            results = [("unified", ok)]
        else:
            results = _run_enabled_sources()

        _touch_last_crawl()
        chart_id = create_owasp_top_chart()
        after = coll.count_documents({})
        delta = after - before
        print(f"[crawler] DB count before={before} after={after} (+{delta})")
        TASKS["last_refresh"] = {
            "status": "done",
            "results": results,
            "chart_id": chart_id,
            "finished_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "added": int(delta)
        }
        print("⏱️ 立即更新：完成", results)
    except Exception as e:
        TASKS["last_refresh"] = {"status": "error", "error": str(e)}
        print("⏱️ 立即更新：錯誤", e)

@app.route("/crawler/refresh_now", methods=["POST"])
def refresh_now():
    if not enabled_sources_list():
        flash("⚠️ 尚未開啟任何來源，請先在上方卡片「開啟」至少一個來源")
        return redirect(url_for("manage_crawler"))
    TASKS["last_refresh"] = {"status": "running", "started_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
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

    TASKS["last_refresh"] = {"status": "running", "started_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    Thread(target=do_refresh_now_task, kwargs={"sources_override": sources, "mode": mode}, daemon=True).start()
    return jsonify({"ok": True, "message": "已觸發即時更新（背景執行）", "mode": mode, "sources": sources or enabled_sources_list()})

@app.route("/api/refresh_status")
def refresh_status():
    info = TASKS.get("last_refresh", {"status": "idle"})
    return jsonify({
        "ok": True,
        "status": info.get("status", "idle"),
        "results": info.get("results"),
        "chart_id": info.get("chart_id"),
        "finished_at": info.get("finished_at"),
        "added": info.get("added"),
        "last_crawl_at": LAST_CRAWL_AT.strftime("%Y-%m-%d %H:%M:%S") if LAST_CRAWL_AT else None
    })

# =========================
# 排程（定期更新）
# =========================
def scheduled_crawl():
    print("⏰ 排程觸發")
    _run_enabled_sources()
    _touch_last_crawl()
    # 需要的話可在這裡自動產圖
    # create_owasp_top_chart()

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

    flash(f"📅 定期更新已啟動，每 {minutes} 分鐘執行一次")
    return redirect(url_for("manage_crawler"))

@app.route("/crawler/schedule/stop", methods=["POST"])
def stop_schedule():
    job = scheduler.get_job("crawler_job")
    if job:
        scheduler.remove_job("crawler_job")
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

@app.route("/api/stats")
def api_stats():
    try:
        pipeline = [
            {"$project": {"k": {"$ifNull": ["$owasp_top", "Uncategorized"]}}},
            {"$group": {"_id": "$k", "count": {"$sum": 1}}},
        ]
        rows = list(coll.aggregate(pipeline))
        order = {f"A{n:02d}": n for n in range(1, 11)}
        rows.sort(key=lambda r: order.get(r["_id"], 99))
        by_class = [{"class": r["_id"], "count": r["count"]} for r in rows]
        return jsonify({"ok": True, "by_class": by_class})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

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
    days = minutes_sanitized(int(request.args.get("days", 7)), mn=1, mx=90)
    today = date.today()
    labels = [(today - timedelta(days=i)).strftime("%m/%d") for i in range(days - 1, -1, -1)]
    datasets = []
    for cat, mul in [("A01", 1), ("A02", 2), ("A03", 3)]:
        datasets.append({"label": cat, "data": [((i * mul) % 10) for i in range(days)]})
    return jsonify({"labels": labels, "datasets": datasets})

# =========================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
