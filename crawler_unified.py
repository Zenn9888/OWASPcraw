#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
crawler_unified.py
- Unified entrypoint to crawl Hacker News (hn), Reddit (reddit), Security StackExchange (stackex).
- Designed to be launched by app.py with `python -u` for unbuffered output.
- Emits standardized progress lines for UI parsing:

  [page] {source} {cur}/{total}
  [{source}] posts={total} +{inc} comments={total} +{inc}
  [classify] processed={total} +{inc} written={total} +{inc}
  [crawler] unified({mode}|only={hn,reddit,stackex}) done +{added}

It prefers an external core script (crawler_core.py). If not found, it falls back
to a tiny built-in fetcher that only demonstrates paging & counting (no network),
so you can still see live progress numbers during integration.
"""

from __future__ import annotations

import os
import re
import sys
import time
import argparse
from datetime import datetime, timezone
from typing import List, Dict, Any, Set, Tuple, Optional

# ------------------------------------------------------------------------------
# Progress printer (standardized stdout for app.py)
# ------------------------------------------------------------------------------
class ProgressPrinter:
    def __init__(self):
        try:
            sys.stdout.reconfigure(line_buffering=True)  # py3.7+
        except Exception:
            pass

    @staticmethod
    def _p(msg: str):
        print(msg, flush=True)

    def page(self, source: str, cur: int, total: int):
        # example: [page] hn 3/10
        self._p(f"[page] {source} {cur}/{total}")

    def counts(self, source: str, posts_total: int, posts_inc: int,
               comments_total: int, comments_inc: int):
        # example: [hn] posts=500 +120 comments=3000 +450
        self._p(f"[{source}] posts={posts_total} +{posts_inc} "
                f"comments={comments_total} +{comments_inc}")

    def classify(self, processed_total: int, processed_inc: int,
                 written_total: int, written_inc: int):
        self._p(f"[classify] processed={processed_total} +{processed_inc} "
                f"written={written_total} +{written_inc}")

    def done(self, mode: str, only_list: str, added: int):
        # example: [crawler] unified(default|only=hn,reddit,stackex) done +150
        self._p(f"[crawler] unified({mode}|only={only_list}) done +{added}")

PROG = ProgressPrinter()

# ------------------------------------------------------------------------------
# Utilities
# ------------------------------------------------------------------------------
VALID_SOURCES = ("hn", "reddit", "stackex")

def which_python() -> str:
    # honor PYTHON_BIN if set, else current interpreter
    return os.environ.get("PYTHON_BIN") or sys.executable

def parse_only_list(only: str | None) -> Set[str]:
    if not only:
        return set()
    items = [x.strip().lower() for x in str(only).split(",") if x.strip()]
    out: Set[str] = set()
    for it in items:
        if it in ("se", "stack", "stackexchange"):
            it = "stackex"
        if it not in VALID_SOURCES:
            raise ValueError(f"unknown source '{it}'")
        out.add(it)
    return out

# ------------------------------------------------------------------------------
# External core runner (preferred)
# ------------------------------------------------------------------------------
def run_via_core(source: str, args) -> int:
    """
    Call external crawler_core.py if it exists. While reading its stdout,
    mirror/normalize progress lines so app.py can parse them.
    Returns an estimated 'added' count (>=0). If core not found returns -1.
    """
    core_script = os.environ.get("CRAWLER_CORE", "crawler_core.py")
    if not os.path.exists(core_script):
        print(f"[crawler][{source}] skip: {core_script} 不存在；將使用內建抓取器")
        return -1

    from subprocess import Popen, PIPE
    py = which_python()
    cmd = [py, core_script,
           "--source", source,
           "--mongo-url", args.mongo_url,
           "--mongo-db", args.mongo_db,
           "--mongo-coll", args.mongo_coll]
    if args.limit is not None:
        cmd += ["--limit", str(args.limit)]

    if source == "hn":
        cmd += ["--hn-page-size", str(args.hn_page_size),
                "--hn-pages", str(args.hn_pages),
                "--recent-days", str(args.recent_days),
                "--hn-min-points", str(args.hn_min_points)]
    elif source == "reddit":
        cmd += ["--reddit-subs", args.reddit_subs,
                "--reddit-page-size", str(args.reddit_page_size),
                "--reddit-pages", str(args.reddit_pages)]
        if args.include_comments:
            cmd += ["--include-comments"]
    elif source == "stackex":
        cmd += ["--se-site", args.se_site,
                "--se-page-size", str(args.se_page_size),
                "--se-pages", str(args.se_pages)]
        if args.include_comments:
            cmd += ["--include-comments"]
        if args.respect_backoff:
            cmd += ["--respect-backoff"]

    print(f"[crawler][{source}] run external: {' '.join(cmd)}")
    proc = Popen(cmd, stdout=PIPE, stderr=PIPE, text=True)

    rx_page   = re.compile(r"page\s*[:=]?\s*(\d+)\s*/\s*(\d+)", re.I)
    rx_counts = re.compile(r"posts\s*[:=]\s*(\d+)\s*\+(\d+).*(comments|replies)\s*[:=]\s*(\d+)\s*\+(\d+)", re.I)
    rx_plus   = re.compile(r"\(\+(\d+)\)")  # capture "(+N)" as a fallback added

    # synthesize [page] lines if core doesn't emit them
    if source == "hn":
        expected_pages = int(args.hn_pages or 0)
    elif source == "reddit":
        expected_pages = int(args.reddit_pages or 0)
    else:
        expected_pages = int(args.se_pages or 0)
    cur_page = 0

    added = 0
    for raw in proc.stdout:
        line = raw.rstrip("\n")
        # pass-through [page] if core prints it
        m = rx_page.search(line)
        if m:
            try:
                cur_page = int(m.group(1))
                expected_pages = int(m.group(2))
            except Exception:
                pass
            PROG.page(source, int(m.group(1)), int(m.group(2)))

        # counts (posts/comments)
        m = rx_counts.search(line)
        if m:
            posts_total = int(m.group(1)); posts_inc = int(m.group(2))
            comments_total = int(m.group(4)); comments_inc = int(m.group(5))

            # synthesize a [page] line if needed
            if expected_pages > 0:
                nxt = min(cur_page + 1, expected_pages)
                if nxt > cur_page:
                    PROG.page(source, nxt, expected_pages)
                    cur_page = nxt

            PROG.counts(source, posts_total, posts_inc, comments_total, comments_inc)

        # fallback: (+N)
        m = rx_plus.search(line)
        if m:
            try:
                added = max(added, int(m.group(1)))
            except Exception:
                pass

    for raw in proc.stderr:
        print(f"[{source}][stderr] {raw.rstrip()}")

    rc = proc.wait()
    if rc != 0:
        print(f"[crawler][{source}] exit rc={rc}")
    return max(0, added)

# ------------------------------------------------------------------------------
# Built-in lightweight crawlers (offline-friendly placeholders)
# ------------------------------------------------------------------------------
def demo_pages(source: str, pages: int = 3, sleep_sec: float = 0.2) -> Tuple[int, int]:
    """
    A tiny demo crawler that emits progress without doing network calls.
    Returns (posts_added_total, comments_added_total).
    """
    posts_total = 0
    comments_total = 0
    for i in range(1, pages + 1):
        PROG.page(source, i, pages)
        # simulate added numbers
        p_add = 10 * i
        c_add = 30 * i if source != "hn" else 20 * i
        posts_total += p_add
        comments_total += c_add
        PROG.counts(source, posts_total, p_add, comments_total, c_add)
        time.sleep(sleep_sec)
    return posts_total, comments_total

def run_hn(args) -> int:
    added = run_via_core("hn", args)
    if added >= 0:
        return added
    # fallback demo
    posts, _comments = demo_pages("hn", pages=args.hn_pages or 3)
    return posts

def run_reddit(args) -> int:
    added = run_via_core("reddit", args)
    if added >= 0:
        return added
    posts, _comments = demo_pages("reddit", pages=args.reddit_pages or 2)
    return posts

def run_stackex(args) -> int:
    added = run_via_core("stackex", args)
    if added >= 0:
        return added
    posts, _comments = demo_pages("stackex", pages=args.se_pages or 2)
    return posts

# ------------------------------------------------------------------------------
# CLI
# ------------------------------------------------------------------------------
def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Unified crawler for hn/reddit/stackex")
    p.add_argument("--mode", default="default", help="default|refresh|backfill")
    p.add_argument("--only", default="", help="comma-separated sources (hn,reddit,stackex)")
    p.add_argument("--limit", type=int, default=None, help="limit items per source")
    p.add_argument("--include-comments", action="store_true", help="include comments when supported")

    # Mongo
    p.add_argument("--mongo-url", dest="mongo_url", default=os.environ.get("MONGO_URL", "mongodb://localhost:27017"))
    p.add_argument("--mongo-db",  dest="mongo_db",  default=os.environ.get("MONGO_DB", "webcommentIT"))
    p.add_argument("--mongo-coll",dest="mongo_coll",default=os.environ.get("MONGO_COLL", "comment"))

    # HN options
    p.add_argument("--hn-pages", type=int, default=3)
    p.add_argument("--hn-page-size", type=int, default=30)
    p.add_argument("--hn-min-points", type=int, default=0)
    p.add_argument("--recent-days", type=int, default=7)

    # Reddit options
    p.add_argument("--reddit-subs", default="netsec,cybersecurity")
    p.add_argument("--reddit-pages", type=int, default=2)
    p.add_argument("--reddit-page-size", type=int, default=100)

    # StackExchange options
    p.add_argument("--se-site", default="security")
    p.add_argument("--se-pages", type=int, default=2)
    p.add_argument("--se-page-size", type=int, default=100)
    p.add_argument("--respect-backoff", action="store_true")

    return p

# ------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------
def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    try:
        selected = parse_only_list(args.only)
    except ValueError as e:
        print(f"[crawler] error: {e}")
        return 2

    if not selected:
        selected = set(VALID_SOURCES)

    only_str = ",".join(sorted(selected))
    print(f"[crawler] unified({args.mode}|only={only_str}): start @ {datetime.now(timezone.utc).isoformat(timespec='seconds')}")

    total_inserted = 0
    ok_sources: List[Tuple[str, int]] = []
    bad_sources: List[Tuple[str, str]] = []

    if "hn" in selected:
        try:
            ins = run_hn(args)
            total_inserted += ins
            ok_sources.append(("hn", ins))
        except Exception as e:
            print(f"[crawler][hn] error: {e}")
            bad_sources.append(("hn", str(e)))

    if "reddit" in selected:
        try:
            ins = run_reddit(args)
            total_inserted += ins
            ok_sources.append(("reddit", ins))
        except Exception as e:
            print(f"[crawler][reddit] error: {e}")
            bad_sources.append(("reddit", str(e)))

    if "stackex" in selected:
        try:
            ins = run_stackex(args)
            total_inserted += ins
            ok_sources.append(("stackex", ins))
        except Exception as e:
            print(f"[crawler][stackex] error: {e}")
            bad_sources.append(("stackex", str(e)))

    # Only keep standardized final line for app.py parser
    PROG.done(args.mode, only_str, total_inserted)

    if ok_sources:
        detail = ", ".join([f"{name}=+{cnt}" for name, cnt in ok_sources])
        print(f"[crawler] ok: {detail}")
    if bad_sources:
        for name, msg in bad_sources:
            print(f"[crawler] {name} failed: {msg}")
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
