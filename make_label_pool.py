
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Make a balanced labeling pool from MongoDB and export to CSV.

import os, csv, argparse
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv(Path(".") / ".env", override=True)
    load_dotenv(Path(".") / ".env.local", override=True)
except Exception:
    pass

from pymongo import MongoClient

DEF_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")
DEF_DB = os.getenv("MONGO_DB", "webcommentIT")
DEF_COLL = os.getenv("MONGO_COLL", "comment")

SOURCES = ["hn", "reddit", "stackex"]

def iso(dt):
    if not dt:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat(timespec="seconds")

def make_text(doc):
    title = doc.get("title") or ""
    content = doc.get("content") or ""
    txt = (title.strip() + "\n\n" + content.strip()).strip()
    return " ".join(txt.split())

def word_count(s: str) -> int:
    return len([w for w in s.strip().split() if w])

def sample_bucket(coll, q: Dict[str, Any], size: int) -> List[Dict[str, Any]]:
    if size <= 0:
        return []
    cur = coll.aggregate([
        {"$match": q},
        {"$sample": {"size": size}},
        {"$project": {
            "_id": 1, "source": 1, "type": 1, "title": 1, "content": 1,
            "url": 1, "created_at": 1, "author": 1, "score": 1,
            "subreddit": 1, "site": 1, "parent_id": 1, "post_id": 1
        }},
    ], allowDiskUse=True)
    return list(cur)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mongo-url", default=DEF_URL)
    ap.add_argument("--mongo-db", default=DEF_DB)
    ap.add_argument("--mongo-coll", default=DEF_COLL)
    ap.add_argument("--size", type=int, default=3000)
    ap.add_argument("--min-words", type=int, default=5)
    ap.add_argument("--out", default=f"label_pool_{datetime.now().strftime('%Y%m%d_%H%M')}.csv")
    args = ap.parse_args()

    cli = MongoClient(args.mongo_url, tz_aware=True)
    coll = cli[args.mongo_db][args.mongo_coll]

    now = datetime.now(timezone.utc)
    t90 = now - timedelta(days=90)
    t365 = now - timedelta(days=365)

    total = max(1, args.size)
    per_source = {s: total // len(SOURCES) for s in SOURCES}
    for s in list(SOURCES)[: total % len(SOURCES)]:
        per_source[s] += 1

    posts_ratio = 0.6
    ratios_time = {"last90":0.40, "d91_365":0.30, "gt365":0.30}

    picked_ids = set()
    rows: List[Dict[str, Any]] = []

    for src, src_n in per_source.items():
        n_posts = int(round(src_n * posts_ratio))
        n_comments = src_n - n_posts

        for typ, n_typ in (("post", n_posts), ("comment", n_comments)):
            for bucket, r in ratios_time.items():
                n_bucket = int(round(n_typ * r))
                if n_bucket <= 0: 
                    continue

                if bucket == "last90":
                    q_time = {"$gte": t90}
                elif bucket == "d91_365":
                    q_time = {"$gte": t365, "$lt": t90}
                else:
                    q_time = {"$lt": t365}

                q = {"source": src, "type": typ, "created_at": q_time}
                docs = sample_bucket(coll, q, n_bucket)

                for d in docs:
                    _id = str(d.get("_id"))
                    if _id in picked_ids:
                        continue
                    txt = make_text(d)
                    if word_count(txt) < args.min_words:
                        continue
                    picked_ids.add(_id)
                    rows.append({
                        "_id": _id,
                        "source": d.get("source"),
                        "type": d.get("type"),
                        "subreddit": d.get("subreddit") or "",
                        "site": d.get("site") or "",
                        "url": d.get("url") or "",
                        "created_at": iso(d.get("created_at")),
                        "author": d.get("author") or "",
                        "score": d.get("score") if isinstance(d.get("score"), (int, float)) else "",
                        "parent_id": d.get("parent_id") or "",
                        "post_id": d.get("post_id") or "",
                        "title": (d.get("title") or "").replace("\r"," ").replace("\n"," ").strip(),
                        "text": make_text(d)[:2000],
                        "label": "",
                        "notes": "",
                        "difficulty": ""
                    })

    if len(rows) < total:
        need = total - len(rows)
        extra = sample_bucket(coll, {"source": {"$in": SOURCES}}, need*2)
        for d in extra:
            if len(rows) >= total:
                break
            _id = str(d.get("_id"))
            if _id in picked_ids:
                continue
            txt = make_text(d)
            if word_count(txt) < args.min_words:
                continue
            picked_ids.add(_id)
            rows.append({
                "_id": _id,
                "source": d.get("source"),
                "type": d.get("type"),
                "subreddit": d.get("subreddit") or "",
                "site": d.get("site") or "",
                "url": d.get("url") or "",
                "created_at": iso(d.get("created_at")),
                "author": d.get("author") or "",
                "score": d.get("score") if isinstance(d.get("score"), (int, float)) else "",
                "parent_id": d.get("parent_id") or "",
                "post_id": d.get("post_id") or "",
                "title": (d.get("title") or "").replace("\r"," ").replace("\n"," ").strip(),
                "text": make_text(d)[:2000],
                "label": "",
                "notes": "",
                "difficulty": ""
            })

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["_id","source","type","subreddit","site","url","created_at","author","score",
                  "parent_id","post_id","title","text","label","notes","difficulty"]
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows[:total]:
            w.writerow(r)

    print(f"[ok] wrote {min(total, len(rows))} rows to {out}")

if __name__ == "__main__":
    import sys
    sys.exit(main())
