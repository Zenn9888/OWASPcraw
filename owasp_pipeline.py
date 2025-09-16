#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OWASP Pipeline (Upgraded)
- Adds --cv and --class-weight for training
- Supports vectorizers: char, word, tfidf
- Supports models: lr (LogisticRegression), linear_svm (LinearSVC), comp_nb (ComplementNB)
- Saves classification report and confusion matrix
- Allows custom text/label fields from MongoDB

Minimal seeding pass-through is kept (copy labeled docs with conf>=threshold),
so you can still run your old-style seed → train workflow. If your source
collection isn't pre-labeled, this seeding will simply skip docs without labels.

Author: ChatGPT (GPT‑5 Thinking)
Date: 2025-09-13
"""

import argparse
import json
import os
import sys
import time
import math
import shutil
from datetime import datetime
from pathlib import Path
from typing import List, Tuple, Dict, Any

import numpy as np
from pymongo import MongoClient

from sklearn.feature_extraction.text import CountVectorizer, TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import ComplementNB
from sklearn.svm import LinearSVC
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix

import matplotlib
matplotlib.use("Agg")  # headless
import matplotlib.pyplot as plt

try:
    import joblib
except Exception:
    from sklearn.externals import joblib  # older sklearn fallback

OWASP_ALIASES = {
    # Accept either plain codes or full names; we normalize to A01..A10
    "A01": "A01",
    "A01: Broken Access Control": "A01",
    "Broken Access Control": "A01",

    "A02": "A02",
    "A02: Cryptographic Failures": "A02",
    "Cryptographic Failures": "A02",

    "A03": "A03",
    "A03: Injection": "A03",
    "Injection": "A03",

    "A04": "A04",
    "A04: Insecure Design": "A04",
    "Insecure Design": "A04",

    "A05": "A05",
    "A05: Security Misconfiguration": "A05",
    "Security Misconfiguration": "A05",

    "A06": "A06",
    "A06: Vulnerable and Outdated Components": "A06",
    "Vulnerable and Outdated Components": "A06",

    "A07": "A07",
    "A07: Identification and Authentication Failures": "A07",
    "Identification and Authentication Failures": "A07",

    "A08": "A08",
    "A08: Software and Data Integrity Failures": "A08",
    "Software and Data Integrity Failures": "A08",

    "A09": "A09",
    "A09: Security Logging and Monitoring Failures": "A09",
    "Security Logging and Monitoring Failures": "A09",

    "A10": "A10",
    "A10: Server-Side Request Forgery": "A10",
    "Server-Side Request Forgery": "A10",
}

OWASP_ORDER = [f"A{str(i).zfill(2)}" for i in range(1, 11)]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="OWASP seeding & training pipeline (upgraded)")

    # Mongo & collections
    p.add_argument("--mongo", default="mongodb://localhost:27017", help="MongoDB URL")
    p.add_argument("--src-db", required=True, help="Source database (seed: from; train: already prepared)")
    p.add_argument("--src-coll", required=True, help="Source collection")
    p.add_argument("--dst-db", help="Destination database for seeding")
    p.add_argument("--dst-coll", help="Destination collection for seeding")

    # Data & filtering
    p.add_argument("--min-length", type=int, default=0, help="Minimum text length")
    p.add_argument("--limit", type=int, default=0, help="Limit number of docs to read (0=all)")
    p.add_argument("--query", default="{}", help="JSON query string for Mongo find()")
    p.add_argument("--query-file", help="Path to JSON file for query")

    # Seeding behavior (simple pass-through based on existing labels/conf)
    p.add_argument("--conf-threshold", type=float, default=0.0, help="Confidence threshold for seeding (field: conf)")
    p.add_argument("--per-class-target", type=int, default=0, help="Stop seeding when each class hits target (0=off)")
    p.add_argument("--until-target", action="store_true", help="Enable target-based seeding")
    p.add_argument("--exclude-existing", action="store_true", help="Skip docs already present in dst by source _id")
    p.add_argument("--exclude-processed", action="store_true", help="Skip docs previously processed (flag=processed=True)")
    p.add_argument("--no-noise-filter", action="store_true", help="Ignore any noise filter (kept for compat)")
    p.add_argument("--parent-hops", type=int, default=0, help="Kept for compat; no-op in this minimal seeding")
    p.add_argument("--page-size", type=int, default=20000, help="Pagination size during seeding")

    # Fields
    p.add_argument("--text-field", default="content", help="Field name for text")
    p.add_argument("--label-field", default="label", help="Field name for class label (expects A01..A10 or full name)")
    p.add_argument("--conf-field", default="conf", help="Field name for confidence (float 0~1)")

    # Training controls
    p.add_argument("--no-train", action="store_true", help="Skip training step")
    p.add_argument("--model", default="lr", choices=["lr", "linear_svm", "comp_nb"], help="Classifier")
    p.add_argument("--vectorizer", default="word", choices=["char", "word", "tfidf"], help="Vectorizer type")
    p.add_argument("--test-size", type=float, default=0.2, help="Test split ratio")
    p.add_argument("--cv", type=int, default=0, help="Stratified k-fold CV on full data (0=off)")
    p.add_argument("--class-weight", default="none", choices=["none", "balanced"], help="Class weight for LR/SVM")

    # Output
    p.add_argument("--outdir", default="models/owasp_model", help="Output directory for model & reports")

    return p.parse_args()


def load_query(args: argparse.Namespace) -> Dict[str, Any]:
    if args.query_file:
        with open(args.query_file, "r", encoding="utf-8") as f:
            return json.load(f)
    try:
        return json.loads(args.query)
    except Exception:
        print("❌ --query 必須是 JSON 物件字串，例如: '{}' 或 '{\"source\":\"reddit\"}'", file=sys.stderr)
        sys.exit(2)


def norm_label(v: Any) -> str:
    if v is None:
        return ""
    s = str(v).strip()
    if s in OWASP_ALIASES:
        return OWASP_ALIASES[s]
    # try prefix like "A01:" forms
    if s[:3] in OWASP_ALIASES:
        return OWASP_ALIASES[s[:3]]
    return s


def build_vectorizer(kind: str):
    if kind == "char":
        return CountVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2)
    if kind == "word":
        return CountVectorizer(analyzer="word", ngram_range=(1, 2), min_df=2, token_pattern=r"(?u)\b\w+\b")
    if kind == "tfidf":
        return TfidfVectorizer(analyzer="word", ngram_range=(1, 2), min_df=2, token_pattern=r"(?u)\b\w+\b")
    raise ValueError(f"Unknown vectorizer: {kind}")


def build_model(kind: str, class_weight: str):
    cw = None if class_weight == "none" else class_weight
    if kind == "lr":
        return LogisticRegression(max_iter=2000, n_jobs=None, class_weight=cw)
    if kind == "linear_svm":
        return LinearSVC(class_weight=cw)
    if kind == "comp_nb":
        return ComplementNB()
    raise ValueError(f"Unknown model: {kind}")


def ensure_outdir(path: str) -> Path:
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def human_counts(y: List[str]) -> str:
    from collections import Counter
    c = Counter(y)
    parts = [f"{k}={c.get(k,0)}" for k in OWASP_ORDER]
    return ", ".join(parts)


def do_seeding(args: argparse.Namespace, client: MongoClient):
    if not args.dst_db or not args.dst_coll:
        print("[seed] ⚠️  未指定 --dst-db / --dst-coll，略過 seeding。")
        return

    src = client[args.src_db][args.src_coll]
    dst = client[args.dst_db][args.dst_coll]

    q = load_query(args)
    cursor = src.find(q, no_cursor_timeout=True)
    total = 0
    inserted = 0
    skipped = 0

    # per-class counters for until-target
    per_target = args.per_class_target if args.until_target and args.per_class_target > 0 else 0
    per_counts: Dict[str, int] = {k: 0 for k in OWASP_ORDER}

    print(f"[seed] ▶️ Start seeding from {args.src_db}.{args.src_coll} to {args.dst_db}.{args.dst_coll}")
    print(f"[seed] filters: min_len>={args.min_length}, conf>={args.conf_threshold}, per_class_target={per_target}")

    for doc in cursor:
        total += 1
        text = str(doc.get(args.text_field, "") or "")
        if len(text) < args.min_length:
            skipped += 1
            continue

        label_raw = doc.get(args.label_field)
        label = norm_label(label_raw)
        if label not in OWASP_ORDER:
            skipped += 1
            continue

        conf = doc.get(args.conf_field, 1.0)
        try:
            conf = float(conf)
        except Exception:
            conf = 0.0

        if conf < args.conf_threshold:
            skipped += 1
            continue

        if per_target:
            if per_counts[label] >= per_target:
                skipped += 1
                continue

        # Optionally skip if already exists by source _id
        if args.exclude_existing and doc.get("_id") is not None:
            if dst.find_one({"_src_id": doc["_id"]}):
                skipped += 1
                continue

        out_doc = {
            "_src_id": doc.get("_id"),
            args.text_field: text,
            args.label_field: label,
            args.conf_field: conf,
            "seeded_at": datetime.utcnow(),
        }
        dst.insert_one(out_doc)
        inserted += 1
        if per_target:
            per_counts[label] += 1

        if inserted % 500 == 0:
            print(f"[seed] ... inserted={inserted} skipped={skipped} (total={total}) per-class: " + human_counts(list(per_counts.keys())*0))

    print(f"[seed] 📊 Summary: total={total}, inserted={inserted}, skipped={skipped}")


def plot_confusion(cm: np.ndarray, labels: List[str], out_png: Path):
    fig = plt.figure(figsize=(8, 7))
    ax = fig.add_subplot(111)
    im = ax.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
    ax.figure.colorbar(im, ax=ax)
    ax.set(xticks=np.arange(cm.shape[1]), yticks=np.arange(cm.shape[0]), xticklabels=labels, yticklabels=labels, ylabel='True label', xlabel='Predicted label', title='Confusion Matrix')

    # rotate tick labels
    plt.setp(ax.get_xticklabels(), rotation=45, ha="right", rotation_mode="anchor")

    thresh = cm.max() / 2.0 if cm.size else 0
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(j, i, format(cm[i, j], 'd'), ha="center", va="center", color="white" if cm[i, j] > thresh else "black")
    fig.tight_layout()
    fig.savefig(out_png, dpi=160, bbox_inches='tight')
    plt.close(fig)


def train_and_eval(args: argparse.Namespace, client: MongoClient):
    print("[train] ▶️ Loading data…")
    src = client[args.src_db][args.src_coll]
    q = load_query(args)

    texts: List[str] = []
    labels: List[str] = []

    for doc in src.find(q):
        t = str(doc.get(args.text_field, "") or "")
        if len(t) < args.min_length:
            continue
        y_raw = doc.get(args.label_field)
        y = norm_label(y_raw)
        if y in OWASP_ORDER:
            texts.append(t)
            labels.append(y)

    if not texts:
        print("[train] ❌ No data to train. Check --src-db/--src-coll and fields.")
        sys.exit(1)

    # Class distribution & reduce to only classes that have >=1 sample
    from collections import Counter
    cnt = Counter(labels)
    nonzero_classes = sorted([c for c, n in cnt.items() if n > 0])
    print("[train] Class counts:", {c: cnt[c] for c in nonzero_classes})
    if len(nonzero_classes) < 2:
        print("[train] ❌ Need at least 2 classes to train.")
        sys.exit(2)

    # Prepare output dir
    outdir = ensure_outdir(args.outdir)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Build pipeline
    vec = build_vectorizer(args.vectorizer)
    clf = build_model(args.model, args.class_weight)
    pipe = Pipeline([
        ("vec", vec),
        ("clf", clf),
    ])

    X = np.array(texts)
    y = np.array(labels)

    # Adjust CV if requested
    cv_n = max(0, int(args.cv))
    min_class = min(cnt[c] for c in nonzero_classes)
    if cv_n > 0:
        if min_class < cv_n:
            print(f"[train] ⚠️ Requested cv={cv_n} but min class count is {min_class}. Reducing cv to {min_class}.")
            cv_n = min_class
        if cv_n < 2:
            print("[train] ⚠️ After adjustment, cv<2, disabling CV.")
            cv_n = 0

    # Optional CV on full data
    if cv_n >= 2:
        print(f"[train] ⏳ Running stratified {cv_n}-fold CV…")
        skf = StratifiedKFold(n_splits=cv_n, shuffle=True, random_state=42)
        try:
            scores = cross_val_score(pipe, X, y, cv=skf, scoring="f1_macro", n_jobs=None)
            print(f"[train] CV f1_macro: mean={scores.mean():.4f} ± {scores.std():.4f} → {scores}")
        except Exception as e:
            print(f"[train] ⚠️ CV failed: {e}")

    # Train/test split for holdout evaluation
    print("[train] ⏳ Train/Test split…")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=42, stratify=y
    )
    print(f"[train] Train={len(y_train)}  Test={len(y_test)}  test_size={args.test_size}")

    print("[train] ⏳ Fitting model…")
    pipe.fit(X_train, y_train)

    print("[train] ⏳ Predict on holdout…")
    y_pred = pipe.predict(X_test)

    # Report
    rep = classification_report(y_test, y_pred, labels=OWASP_ORDER, zero_division=0, digits=2, output_dict=False)
    print("[train] 📄 Report:\n" + rep)

    # Save artifacts
    model_path = outdir / f"model_{args.model}_{args.vectorizer}_{timestamp}.joblib"
    joblib.dump(pipe, model_path)

    # Save report txt
    report_txt = outdir / f"report_{args.model}_{args.vectorizer}_{timestamp}.txt"
    with open(report_txt, "w", encoding="utf-8") as f:
        f.write("OWASP Training Report\n")
        f.write(f"Time: {timestamp}\n")
        f.write(f"Model: {args.model}\nVectorizer: {args.vectorizer}\nClassWeight: {args.class_weight}\n")
        f.write(f"Classes: {sorted(list(set(y)))}\n")
        f.write("\n")
        f.write(rep)

    # Confusion matrix (only on labels that appear in y_test)
    uniq_test_labels = sorted(list(set(y_test)))
    cm = confusion_matrix(y_test, y_pred, labels=uniq_test_labels)
    cm_png = outdir / f"cm_{args.model}_{args.vectorizer}_{timestamp}.png"
    plot_confusion(cm, uniq_test_labels, cm_png)

    print(f"[train] 💾 Saved model → {model_path}")
    print(f"[train] 💾 Saved report → {report_txt}")
    print(f"[train] 💾 Saved confusion matrix → {cm_png}")


def main():
    args = parse_args()

    client = MongoClient(args.mongo)
    t0 = time.time()

    # Seeding (optional)
    do_seeding(args, client)

    if args.no_train:
        print("[main] ⏭️ 跳過訓練（--no-train）")
        return

    # Training
    train_and_eval(args, client)

    print(f"[main] ✅ Done in {time.time()-t0:.1f}s")


if __name__ == "__main__":
    main()
