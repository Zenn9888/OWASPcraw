# -*- coding: utf-8 -*-
"""
OWASP 類別熱度折線圖（總量版）
- 從 MongoDB 讀取 webcommentIT_train.comment_train
- 彙總所有來源在 A01~A10 的討論數
- 匯出 CSV（owasp_code, count）
- 產生折線圖（單條線，總數量）

依賴：
    pip install pymongo pandas matplotlib pytz tzdata
"""

from __future__ import annotations
import os
from collections import Counter
from typing import Any, Dict, Optional, List
from matplotlib import rcParams, font_manager as fm
import pandas as pd
from pymongo import MongoClient
from datetime import datetime, timedelta, timezone as dt_timezone
import matplotlib.pyplot as plt
import numpy as np
CANDIDATES = [
    # Windows
    r"C:\Windows\Fonts\msjh.ttc",            # Microsoft JhengHei
    r"C:\Windows\Fonts\msjh.ttf",
    r"C:\Windows\Fonts\mingliu.ttc",
    # macOS
    "/System/Library/Fonts/PingFang.ttc",    # 蘋方體
    "/System/Library/Fonts/Supplemental/Songti.ttc",
    # Linux（先安裝 noto 字型：sudo apt-get install fonts-noto-cjk）
    "/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",
    "/usr/share/fonts/truetype/noto/NotoSansCJK.ttc",
]

font_path = next((p for p in CANDIDATES if os.path.exists(p)), None)
if font_path:
    fm.fontManager.addfont(font_path)             # 註冊字型檔
    prop = fm.FontProperties(fname=font_path)
    # 設為全域預設字型（sans-serif）
    rcParams["font.sans-serif"] = [prop.get_name()]
else:
    # 沒找到中文字型就先嘗試用這些家族名（若系統本身有）
    rcParams["font.sans-serif"] = [
        "Microsoft JhengHei", "PingFang TC", "Noto Sans CJK TC", "Arial Unicode MS"
    ]

# 避免負號顯示成方框
rcParams["axes.unicode_minus"] = False
# ========= 請依環境調整 =========
MONGO_URI   = "mongodb://localhost:27017"   # ← 改成你的連線字串
DB_NAME     = "webcommentIT_train"
COLL_NAME   = "comment_train"

# 只統計這些 bucket；若不限制，設為 None
BUCKETS_IN: Optional[List[str]] = ["train"]

# 日期篩選（含首日，不含次日）
DATE_FROM: Optional[str] = None
DATE_TO  : Optional[str] = None

# created_at 若是字串，預設依 UTC 解析
ASSUME_UTC = True              

# 輸出檔
OUT_CSV = "owasp_total_counts.csv"
OUT_PNG = "owasp_total_heatline.png"

# OWASP Top 10 類別
OWASP_CODES = [f"A{i:02d}" for i in range(1, 11)]

# 如果中文字顯示亂碼（Windows 常見），取消下面兩行註解
# from matplotlib import rcParams
# rcParams["font.sans-serif"] = ["Microsoft JhengHei", "Taipei Sans TC Beta", "Arial Unicode MS"]


# ================ 工具函式 ================

def _parse_created_at(val: Any) -> Optional[datetime]:
    """轉成 UTC datetime"""
    if val is None:
        return None
    if isinstance(val, datetime):
        if val.tzinfo is None:
            return val.replace(tzinfo=dt_timezone.utc)
        return val.astimezone(dt_timezone.utc)
    if isinstance(val, str):
        dt = pd.to_datetime(val, utc=ASSUME_UTC, errors="coerce")
        if isinstance(dt, pd.Timestamp) and pd.notna(dt):
            return dt.to_pydatetime().astimezone(dt_timezone.utc)
    return None


def normalize_code(code_or_label: Optional[str]) -> Optional[str]:
    """把 'A03' 或 'A03: Injection' 標準化成 'A03'。"""
    if not code_or_label:
        return None
    s = code_or_label.strip().upper()
    if s.startswith("A") and s[1:].isdigit():
        try:
            return f"A{int(s[1:]):02d}"
        except Exception:
            return None
    if ":" in s and s[:1] == "A":
        left = s.split(":", 1)[0].strip()
        if left[1:].isdigit():
            try:
                return f"A{int(left[1:]):02d}"
            except Exception:
                return None
    return None


def pick_category(doc: Dict[str, Any]) -> Optional[str]:
    """優先 owasp_top；若無，從 owasp_hits 多數決推一個。"""
    top = normalize_code(doc.get("owasp_top"))
    if top in OWASP_CODES:
        return top

    hits = doc.get("owasp_hits")
    if isinstance(hits, list) and hits:
        normalized = [normalize_code(h) for h in hits]
        normalized = [x for x in normalized if x in OWASP_CODES]
        if normalized:
            return Counter(normalized).most_common(1)[0][0]
    return None


# ================ 主流程 ================

def main() -> None:
    client = MongoClient(MONGO_URI)
    coll = client[DB_NAME][COLL_NAME]

    query: Dict[str, Any] = {}
    if BUCKETS_IN:
        query["bucket"] = {"$in": BUCKETS_IN}

    projection = {"_id": 0, "owasp_top": 1, "owasp_hits": 1, "created_at": 1}

    cursor = coll.find(query, projection, no_cursor_timeout=True)
    rows: List[Dict[str, Any]] = []

    date_from_dt = pd.Timestamp(DATE_FROM).tz_localize("UTC").to_pydatetime() if DATE_FROM else None
    date_to_dt   = (pd.Timestamp(DATE_TO).tz_localize("UTC") + pd.Timedelta(days=1)).to_pydatetime() if DATE_TO else None

    for doc in cursor:
        if DATE_FROM or DATE_TO:
            ts = _parse_created_at(doc.get("created_at"))
            if ts is None:
                continue
            if date_from_dt and ts < date_from_dt:
                continue
            if date_to_dt and ts >= date_to_dt:
                continue

        code = pick_category(doc)
        if code:
            rows.append({"owasp_code": code})

    if not rows:
        print("⚠️ 查無符合條件資料")
        return

    df = pd.DataFrame(rows)

    # 彙總
    stat = (
        df.groupby("owasp_code")
          .size()
          .reset_index(name="count")
    )

    # 確保 A01~A10 都有；缺補 0
    full_rows = []
    for code in OWASP_CODES:
        v = stat[stat["owasp_code"] == code]["count"]
        cnt = int(v.iloc[0]) if not v.empty else 0
        full_rows.append({"owasp_code": code, "count": cnt})
    result = pd.DataFrame(full_rows)

    # 輸出 CSV
    result.to_csv(OUT_CSV, index=False, encoding="utf-8-sig")
    print(f"✅ 已輸出 CSV：{OUT_CSV}")

    # 畫圖
    x = np.arange(len(OWASP_CODES))
    y = result["count"].values

    plt.figure(figsize=(12, 6))
    plt.plot(x, y, marker="o", color="blue", label="總討論數")
    plt.title("OWASP 類別熱度折線圖（總量）")
    plt.xlabel("OWASP Top 10 類別")
    plt.ylabel("討論數量 / 熱度")
    plt.xticks(x, OWASP_CODES)
    plt.grid(True, linewidth=0.5, alpha=0.6)
    plt.legend()
    plt.tight_layout()

    plt.savefig(OUT_PNG, dpi=150)
    print(f"📈 已輸出 圖檔：{OUT_PNG}")
    plt.show()


if __name__ == "__main__":
    main()
