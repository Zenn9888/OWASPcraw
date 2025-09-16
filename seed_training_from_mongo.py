#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
seed_training_from_mongo.py
---------------------------
從現有 MongoDB 的爬蟲資料 (預設: webcommentIT.comment) 讀取文件，
用規則(Rules Prior)初步判斷是否屬於 OWASP Top 10 類別 (A01..A10)；
若是，將其寫入訓練資料庫 webcommentIT_train.comment_train，並標記為
status="auto_pending"、confirmed=False，供日後人工確認。

也支援直接從 webcommentIT_train.comment_train 匯出已確認(confirmed=True)的資料為 CSV。

安裝：
  pip install pymongo regex pandas

用法：
  # 只做規則篩選 + 入庫
  python seed_training_from_mongo.py seed \
    --mongo "mongodb://localhost:27017" \
    --src-db webcommentIT --src-coll comment \
    --dst-db webcommentIT_train --dst-coll comment_train \
    --per-class-max 1000 --min-length 30

  # 匯出已確認資料到 CSV（給 train_tfidf.py 使用）
  python seed_training_from_mongo.py export \
    --mongo "mongodb://localhost:27017" \
    --dst-db webcommentIT_train --dst-coll comment_train \
    --csv out/train_confirmed.csv

欄位說明（寫入到 comment_train）：
  {
    _id: ObjectId,
    text: str,           # 用於訓練
    label: "A01".. "A10",
    confirmed: False,    # 人工確認後改 True
    status: "auto_pending" or "confirmed",
    matched: ["sql injection", ...],  # 規則命中的關鍵詞/模式（可輔助審核）
    source_ref: { db, coll, oid, source, platform_id, url, title },
    created_at: ISODate
  }

之後你可以：
  # 人工審核後確認一批
  # 在 mongosh 內：
  # use webcommentIT_train
  # db.comment_train.updateMany({label:"A01", confirmed:false}, {$set:{confirmed:true, status:"confirmed"}})

"""
import argparse
import datetime as dt
import os
import re
import sys
from typing import Dict, List, Optional, Tuple

import pandas as pd
import regex
from pymongo import MongoClient, ASCENDING, UpdateOne
from bson import ObjectId

OWASP = {
  "A01": "Broken Access Control",
  "A02": "Cryptographic Failures",
  "A03": "Injection",
  "A04": "Insecure Design",
  "A05": "Security Misconfiguration",
  "A06": "Vulnerable and Outdated Components",
  "A07": "Identification and Authentication Failures",
  "A08": "Software and Data Integrity Failures",
  "A09": "Security Logging and Monitoring Failures",
  "A10": "Server-Side Request Forgery (SSRF)"
}

# 關鍵詞規則（可自行增補）
RULES: Dict[str, List[regex.Pattern]] = {
  "A03": [  # Injection
    regex.compile(r"\bsql\s*injection|\bsqli\b", regex.I),
    regex.compile(r"\bxss\b|cross[-\s]?site\s*scripting", regex.I),
    regex.compile(r"\bcommand\s*injection|\bos\s*command\b", regex.I),
    regex.compile(r"\btemplate\s*injection|\bssti\b", regex.I),
    regex.compile(r"\bldap\s*injection|\bxpath\s*injection\b", regex.I),
    regex.compile(r"\bxxe\b|xml\s*external\s*entity", regex.I),
  ],
  "A05": [  # Misconfiguration
    regex.compile(r"\bdefault\s+(password|creds?)\b", regex.I),
    regex.compile(r"\bexposed\s+(admin|panel|port|s3|bucket)\b", regex.I),
    regex.compile(r"\b(open|public)\s+(s3|bucket|kibana|prometheus)\b", regex.I),
    regex.compile(r"\b(cors)\s*(\*|wildcard| misconfig| allow all)", regex.I),
    regex.compile(r"\b(directories?|dir)\s*listing\b", regex.I),
    regex.compile(r"\b(hsts)\s+(missing|disabled)\b", regex.I),
  ],
  "A06": [  # Vulnerable components
    regex.compile(r"\b(cve|nvd)[- :#]?\d{4}-\d{3,7}\b", regex.I),
    regex.compile(r"\b(outdated|vulnerable)\s+(library|dependency|component)\b", regex.I),
    regex.compile(r"\blog4j|struts2|openssl|spring4shell|shellshock\b", regex.I),
  ],
  "A01": [  # Broken access control
    regex.compile(r"\b(idor|insecure\s+direct\s+object\s+reference)\b", regex.I),
    regex.compile(r"\b(access|authorization)\s*(bypass|control\s*fail|broken)\b", regex.I),
    regex.compile(r"\bprivilege\s*escalation\b", regex.I),
  ],
  "A02": [  # Crypto failures
    regex.compile(r"\b(md5|sha1)\s*(hash)?\s*(weak|insecure)", regex.I),
    regex.compile(r"\b(tls|ssl)\s*(1\.0|1\.1|rc4|cbc)\b", regex.I),
    regex.compile(r"\bno\s*(https|tls)\b|\bplaintext\b|\bunencrypted\b", regex.I),
  ],
  "A07": [  # AuthN/AuthZ failures（偏向身份驗證）
    regex.compile(r"\bbf[a-z-]*\b|\bbrute\s*force\b|\bcredential\s*stuffing\b", regex.I),
    regex.compile(r"\b2fa|mfa|otp|totp\b\s*(bypass|disable|missing)?", regex.I),
    regex.compile(r"\bsession\s*(fixation|hijack)\b", regex.I),
  ],
  "A08": [  # Integrity failures
    regex.compile(r"\bsupply\s*chain\b|\bdependency\s*confusion\b", regex.I),
    regex.compile(r"\bci/cd\b.*(tamper|inject|compromis)", regex.I),
    regex.compile(r"\bsignature\s*(bypass|forge)\b", regex.I),
  ],
  "A09": [  # Logging/Monitoring
    regex.compile(r"\bno\s*(logging|audit)\b|\binsufficient\s*logging\b", regex.I),
    regex.compile(r"\bno\s*(alert|monitor)\b|\binsufficient\s*monitor", regex.I),
  ],
  "A10": [  # SSRF
    regex.compile(r"\bssrf\b|\bserver[-\s]*side\s*request\s*forgery\b", regex.I),
    regex.compile(r"\bmetadata\s*service\b|\b169\.254\.169\.254\b", regex.I),
  ],
  "A04": [  # Insecure design（概念性風險，弱規則，最後才命中）
    regex.compile(r"\binsecure\s*design\b|\bthreat\s*model(ing)?\b", regex.I),
  ],
}

def build_text(doc: dict) -> str:
    parts = []
    raw = doc.get("raw") or {}
    for k in ("title","url"):
        v = raw.get(k)
        if isinstance(v, str):
            parts.append(v)
    for k in ("title","content","url"):
        v = doc.get(k)
        if isinstance(v, str):
            parts.append(v)
    text = " ".join([p for p in parts if p]).strip()
    # normalize whitespace
    text = regex.sub(r"\s+", " ", text)
    return text

def classify_rules(text: str) -> Tuple[Optional[str], List[str]]:
    matched_terms: List[str] = []
    text_lc = text.lower()
    if not text_lc:
        return None, matched_terms

    # 依照更強語義 -> 較弱語義的順序檢查（A03/A10/A06優先）
    priority = ["A03","A10","A06","A01","A07","A05","A02","A08","A09","A04"]
    for label in priority:
        for pat in RULES[label]:
            m = pat.search(text_lc)
            if m:
                frag = m.group(0)
                matched_terms.append(frag)
                # 累積 2~3 個關鍵詞更有把握
                more = 0
                for pat2 in RULES[label]:
                    if pat2 is pat: 
                        continue
                    m2 = pat2.search(text_lc)
                    if m2:
                        matched_terms.append(m2.group(0))
                        more += 1
                    if more >= 2:
                        break
                return label, matched_terms
    return None, matched_terms

def ensure_indexes(dst_coll):
    # 基於來源 oid 做唯一性，避免重複寫入
    dst_coll.create_index([("source_ref.oid", ASCENDING)], unique=True, background=True)
    dst_coll.create_index([("label", ASCENDING), ("confirmed", ASCENDING)], background=True)

def seed(args):
    cli = MongoClient(args.mongo, uuidRepresentation="standard")
    src = cli[args.src_db][args.src_coll]
    dst = cli[args.dst_db][args.dst_coll]
    ensure_indexes(dst)

    # 現有已確認/候選的計數，用於 per-class 上限
    existing_counts = {lab: dst.count_documents({"label": lab}) for lab in OWASP.keys()}

    q = {}
    if args.start_id:
        try:
            q["_id"] = {"$gt": ObjectId(args.start_id)}
        except Exception:
            print("[WARN] --start-id 不是有效的 ObjectId，忽略。")
    if args.start_ts:
        q["created_at"] = {"$gte": args.start_ts}

    cursor = src.find(q, no_cursor_timeout=True).batch_size(args.batch)
    ops: List[UpdateOne] = []
    added = {lab: 0 for lab in OWASP.keys()}
    scanned = 0

    for doc in cursor:
        scanned += 1
        text = build_text(doc)
        if len(text) < args.min_length:
            continue
        label, matched = classify_rules(text)
        if not label:
            continue

        # 檢查 per-class 上限
        cap = args.per_class_max
        total_for_label = existing_counts[label] + added[label]
        if cap and total_for_label >= cap:
            continue

        origin = {
            "db": args.src_db,
            "coll": args.src_coll,
            "oid": str(doc.get("_id")),
            "source": doc.get("source"),
            "platform_id": doc.get("platform_id"),
            "url": (doc.get("raw") or {}).get("url") or doc.get("url"),
            "title": (doc.get("raw") or {}).get("title") or doc.get("title"),
        }

        train_doc = {
            "text": text,
            "label": label,
            "confirmed": False,
            "status": "auto_pending",
            "matched": matched[:5],
            "source_ref": origin,
            "created_at": dt.datetime.utcnow(),
        }

        ops.append(UpdateOne(
            {"source_ref.oid": origin["oid"]},
            {"$setOnInsert": train_doc},
            upsert=True
        ))
        added[label] += 1

        if len(ops) >= args.commit_every:
            res = dst.bulk_write(ops, ordered=False)
            ops.clear()

        if args.limit and sum(added.values()) >= args.limit:
            break

    if ops:
        dst.bulk_write(ops, ordered=False)

    print(f"[DONE] scanned={scanned} added_total={sum(added.values())}")
    for lab in sorted(OWASP.keys()):
        if added[lab]:
            print(f"  {lab} (+{added[lab]})  {OWASP[lab]}")

def export_confirmed(args):
    cli = MongoClient(args.mongo, uuidRepresentation="standard")
    coll = cli[args.dst_db][args.dst_coll]

    q = {"confirmed": True}
    if args.labels:
        labs = [lab.strip().upper() for lab in args.labels.split(",")]
        q["label"] = {"$in": labs}

    cur = coll.find(q, {"text":1, "label":1})
    rows = [{"text": d.get("text",""), "label": d.get("label","")} for d in cur]
    os.makedirs(os.path.dirname(args.csv), exist_ok=True)
    pd.DataFrame(rows).to_csv(args.csv, index=False)
    print(f"[EXPORT] saved {len(rows)} rows to {args.csv}")

def parse_args():
    p = argparse.ArgumentParser(description="Seed OWASP training data from MongoDB using rules prior, and export confirmed to CSV.")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_seed = sub.add_parser("seed", help="Scan source comments, classify by rules, insert candidates into training collection.")
    p_seed.add_argument("--mongo", default="mongodb://localhost:27017", help="Mongo URI")
    p_seed.add_argument("--src-db", default="webcommentIT", help="Source DB name")
    p_seed.add_argument("--src-coll", default="comment", help="Source collection")
    p_seed.add_argument("--dst-db", default="webcommentIT_train", help="Target DB name")
    p_seed.add_argument("--dst-coll", default="comment_train", help="Target collection")
    p_seed.add_argument("--batch", type=int, default=500, help="Mongo batch size")
    p_seed.add_argument("--min-length", type=int, default=30, help="Minimum text length")
    p_seed.add_argument("--per-class-max", type=int, default=1000, help="Per-class upper bound in target collection")
    p_seed.add_argument("--limit", type=int, default=0, help="Stop after N inserted (0 = no limit)")
    p_seed.add_argument("--commit-every", type=int, default=500, help="Bulk write every N upserts")
    p_seed.add_argument("--start-id", default=None, help="Only scan documents with _id > this ObjectId")
    p_seed.add_argument("--start-ts", type=lambda s: dt.datetime.fromisoformat(s), default=None, help="Only scan created_at >= ISO-8601 timestamp")

    p_exp = sub.add_parser("export", help="Export confirmed training rows to CSV (text,label).")
    p_exp.add_argument("--mongo", default="mongodb://localhost:27017", help="Mongo URI")
    p_exp.add_argument("--dst-db", default="webcommentIT_train", help="DB name")
    p_exp.add_argument("--dst-coll", default="comment_train", help="Collection name")
    p_exp.add_argument("--csv", required=True, help="Output CSV path")
    p_exp.add_argument("--labels", default=None, help="Optional subset, e.g. A01,A03,A06")

    return p.parse_args()

if __name__ == "__main__":
    args = parse_args()
    if args.cmd == "seed":
        seed(args)
    elif args.cmd == "export":
        export_confirmed(args)
