#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
crawler_core.py (skeleton)
- Called by crawler_unified.py with args like:
    --source hn|reddit|stackex
    --mongo-url ... --mongo-db ... --mongo-coll ...
    --limit N --include-comments
    HN:      --hn-pages --hn-page-size --recent-days --hn-min-points
    Reddit:  --reddit-subs --reddit-pages --reddit-page-size
    StackEx: --se-site --se-pages --se-page-size --respect-backoff

This is a minimal, self-contained "core" that demonstrates the expected
progress outputs and (optionally) shows where to insert real crawling +
MongoDB upserts. By default it uses a deterministic demo loop; replace
`demo_fetch_*` with your real fetchers and keep the same print formats.
"""

import os
import sys
import time
import argparse
from datetime import datetime, timezone
from typing import List, Tuple, Dict, Any, Optional

# ---------------------------------------------------------------------
# Helpers: stdout formatting for app.py parser (DO NOT change formats)
# ---------------------------------------------------------------------
def p(msg: str):
    print(msg, flush=True)  # unbuffered (crawler_unified runs python -u)

def emit_page(source: str, cur: int, total: int):
    # [page] hn 3/10
    p(f"[page] {source} {cur}/{total}")

def emit_counts(source: str, posts_total: int, posts_inc: int,
                comments_total: int, comments_inc: int):
    # [hn] posts=500 +120 comments=3000 +450
    p(f"[{source}] posts={posts_total} +{posts_inc} comments={comments_total} +{comments_inc}")

# Optional: you may also emit a final "(+N)" hint in free-form lines.
def emit_added_hint(n: int):
    p(f"(+{n})")  # crawler_unified.py can parse (+N) as fallback "added"

# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------
def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="crawler_core skeleton")
    ap.add_argument("--source", required=True, choices=["hn", "reddit", "stackex"])
    ap.add_argument("--mongo-url", dest="mongo_url", default=os.environ.get("MONGO_URL", "mongodb://localhost:27017"))
    ap.add_argument("--mongo-db", dest="mongo_db", default=os.environ.get("MONGO_DB", "webcommentIT"))
    ap.add_argument("--mongo-coll", dest="mongo_coll", default=os.environ.get("MONGO_COLL", "comment"))
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--include-comments", action="store_true")

    # HN
    ap.add_argument("--hn-pages", type=int, default=3)
    ap.add_argument("--hn-page-size", type=int, default=30)
    ap.add_argument("--recent-days", type=int, default=7)
    ap.add_argument("--hn-min-points", type=int, default=0)

    # Reddit
    ap.add_argument("--reddit-subs", default="netsec,cybersecurity")
    ap.add_argument("--reddit-pages", type=int, default=2)
    ap.add_argument("--reddit-page-size", type=int, default=100)

    # StackEx
    ap.add_argument("--se-site", default="security")
    ap.add_argument("--se-pages", type=int, default=2)
    ap.add_argument("--se-page-size", type=int, default=100)
    ap.add_argument("--respect-backoff", action="store_true")
    return ap

# ---------------------------------------------------------------------
# Demo fetchers (replace with real implementations)
# They emit standardized progress lines so UI can update immediately.
# ---------------------------------------------------------------------
def demo_fetch_hn(pages: int, page_size: int, limit: Optional[int]) -> Tuple[int, int]:
    posts_total = 0
    comments_total = 0
    max_items = limit or pages * page_size
    per_page = min(page_size, max_items // max(1, pages))
    for page in range(1, pages + 1):
        emit_page("hn", page, pages)
        added_posts = min(per_page, max(0, max_items - posts_total))
        added_comments = added_posts * 2  # demo heuristic
        posts_total += added_posts
        comments_total += added_comments
        emit_counts("hn", posts_total, added_posts, comments_total, added_comments)
        if posts_total >= max_items:
            break
        time.sleep(0.15)
    return posts_total, comments_total

def demo_fetch_reddit(subs_csv: str, pages: int, page_size: int, limit: Optional[int], include_comments: bool) -> Tuple[int, int]:
    posts_total = 0
    comments_total = 0
    max_items = limit or pages * page_size
    per_page = min(page_size, max_items // max(1, pages))
    for page in range(1, pages + 1):
        emit_page("reddit", page, pages)
        added_posts = min(per_page, max(0, max_items - posts_total))
        added_comments = added_posts * (3 if include_comments else 0)  # demo heuristic
        posts_total += added_posts
        comments_total += added_comments
        emit_counts("reddit", posts_total, added_posts, comments_total, added_comments)
        if posts_total >= max_items:
            break
        time.sleep(0.15)
    return posts_total, comments_total

def demo_fetch_stackex(site: str, pages: int, page_size: int, limit: Optional[int], include_comments: bool, respect_backoff: bool) -> Tuple[int, int]:
    posts_total = 0
    comments_total = 0
    max_items = limit or pages * page_size
    per_page = min(page_size, max_items // max(1, pages))
    for page in range(1, pages + 1):
        emit_page("stackex", page, pages)
        added_posts = min(per_page, max(0, max_items - posts_total))
        # demo: include answers as comments if include_comments
        added_comments = added_posts * (2 if include_comments else 0)
        posts_total += added_posts
        comments_total += added_comments
        emit_counts("stackex", posts_total, added_posts, comments_total, added_comments)
        if respect_backoff:
            time.sleep(0.25)  # simulate backoff
        else:
            time.sleep(0.15)
        if posts_total >= max_items:
            break
    return posts_total, comments_total

# ---------------------------------------------------------------------
# Mongo upsert placeholder (optional; keep off by default)
# ---------------------------------------------------------------------
USE_DB = False  # set True to enable minimal PyMongo upserts

def db_upsert_placeholder(mongo_url: str, mongo_db: str, mongo_coll: str, docs: List[Dict[str, Any]]):
    if not USE_DB or not docs:
        return 0
    try:
        from pymongo import MongoClient, UpdateOne
        client = MongoClient(mongo_url, tz_aware=True)
        coll = client[mongo_db][mongo_coll]
        ops = []
        now = datetime.now(timezone.utc)
        for d in docs:
            key = {"source": d.get("source"), "platform_id": d.get("platform_id")}
            d["created_at"] = d.get("created_at") or now
            ops.append(UpdateOne(key, {"$set": d}, upsert=True))
        if ops:
            res = coll.bulk_write(ops, ordered=False)
            return (res.upserted_count or 0) + (res.modified_count or 0)
    except Exception as e:
        p(f"[db][warn] {e}")
    return 0

# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------
def main() -> int:
    ap = build_arg_parser()
    args = ap.parse_args()

    p(f"[core] start source={args.source} mode=unknown @ {datetime.now(timezone.utc).isoformat(timespec='seconds')}")
    total_posts = 0
    total_comments = 0

    try:
        if args.source == "hn":
            posts, comments = demo_fetch_hn(args.hn_pages, args.hn_page_size, args.limit)
        elif args.source == "reddit":
            posts, comments = demo_fetch_reddit(args.reddit_subs, args.reddit_pages, args.reddit_page_size, args.limit, args.include_comments)
        elif args.source == "stackex":
            posts, comments = demo_fetch_stackex(args.se_site, args.se_pages, args.se_page_size, args.limit, args.include_comments, args.respect_backoff)
        else:
            p(f"[core][error] unknown source {args.source}")
            return 2

        total_posts += posts
        total_comments += comments

        # optional hint for (+N) fallback
        emit_added_hint(total_posts)

        p(f"[core] done source={args.source} posts={total_posts} comments={total_comments}")
        return 0
    except KeyboardInterrupt:
        p("[core] interrupted")
        return 130
    except Exception as e:
        p(f"[core][error] {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
