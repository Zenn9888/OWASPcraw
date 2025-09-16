#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
train_tfidf.py
--------------
Quickly train a TF‑IDF + LogisticRegression classifier for OWASP Top 10 (A01..A10)
from a CSV dataset with columns: text,label

Usage:
  python train_tfidf.py --csv data.csv --out models/owasp/tfidf.joblib

Optional flags (see --help):
  --test-size 0.2 --seed 42 --max-features 40000 --ngram 1 2 --lower True
  --stop-words english --C 4.0 --penalty l2 --solver lbfgs

The saved joblib bundle structure:
  {
    "vectorizer": TfidfVectorizer,
    "model": LogisticRegression,
    "labels": ["A01", ... , "A10"]  # stored for sanity check
  }

Requirements:
  pip install scikit-learn pandas numpy joblib
"""
import argparse
import json
import os
import sys
from typing import List, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.utils.class_weight import compute_class_weight

OWASP_LABELS = ["A01","A02","A03","A04","A05","A06","A07","A08","A09","A10"]

def read_data(csv_path: str) -> pd.DataFrame:
    if not os.path.exists(csv_path):
        sys.exit(f"[ERR] CSV not found: {csv_path}")
    df = pd.read_csv(csv_path)
    # normalize column names
    cols = {c.lower(): c for c in df.columns}
    text_col = cols.get("text")
    label_col = cols.get("label")
    if text_col is None or label_col is None:
        sys.exit("[ERR] CSV must contain columns: text,label")
    df = df[[text_col, label_col]].rename(columns={text_col:"text", label_col:"label"})
    # dropna & strip
    df = df.dropna(subset=["text","label"]).copy()
    df["text"] = df["text"].astype(str).str.replace(r"\s+", " ", regex=True).str.strip()
    df["label"] = df["label"].astype(str).str.strip().str.upper()
    return df

def validate_labels(labels: List[str]):
    uniq = sorted(set(labels))
    bad = [x for x in uniq if x not in OWASP_LABELS]
    if bad:
        sys.exit(f"[ERR] Found unknown labels: {bad}. Allowed: {OWASP_LABELS}")

def build_vectorizer(max_features: int, ngram: Tuple[int,int], lowercase: bool, stop_words):
    return TfidfVectorizer(
        max_features=max_features,
        ngram_range=ngram,
        lowercase=lowercase,
        stop_words=stop_words,
        strip_accents=None,  # keep accents for multilingual
        token_pattern=r"(?u)\b\w[\w\-\./]+\b"  # keep tokens like XSS/SQLi/CVE-2024-XXXX
    )

def build_classifier(C: float, penalty: str, solver: str, class_weight):
    # lbfgs/saga support multinomial softmax; saga supports l1/l2/elasticnet
    return LogisticRegression(
        C=C,
        penalty=penalty,
        solver=solver,
        max_iter=1000,
        n_jobs=-1,
        class_weight=class_weight,
        multi_class="auto",
        verbose=0
    )

def main():
    ap = argparse.ArgumentParser(description="Train TF‑IDF + LogisticRegression for OWASP Top 10 (A01..A10)")
    ap.add_argument("--csv", required=True, help="Input CSV with columns text,label")
    ap.add_argument("--out", default="models/owasp/tfidf.joblib", help="Output joblib path")
    ap.add_argument("--test-size", type=float, default=0.2, help="Test split ratio")
    ap.add_argument("--seed", type=int, default=42, help="Random seed")
    ap.add_argument("--max-features", type=int, default=40000, help="TF‑IDF max features")
    ap.add_argument("--ngram", nargs=2, type=int, default=[1,2], metavar=("MIN_N","MAX_N"), help="N‑gram range")
    ap.add_argument("--lower", type=lambda x: str(x).lower() in {"1","true","yes"}, default=True, help="Lowercase text")
    ap.add_argument("--stop-words", default=None, choices=[None,"english"], help="Stop words (None or english)")
    ap.add_argument("--C", type=float, default=4.0, help="LogReg inverse regularization strength")
    ap.add_argument("--penalty", default="l2", choices=["l1","l2","elasticnet","none"], help="LogReg penalty")
    ap.add_argument("--solver", default="lbfgs", choices=["lbfgs","liblinear","saga","newton-cg","sag"], help="LogReg solver")
    ap.add_argument("--class-weight", default="balanced", choices=["balanced","none"], help="Class weighting strategy")
    ap.add_argument("--report-json", default=None, help="Optional path to write metrics JSON")
    args = ap.parse_args()

    df = read_data(args.csv)
    validate_labels(df["label"].tolist())

    # split
    X_train, X_test, y_train, y_test = train_test_split(
        df["text"].tolist(),
        df["label"].tolist(),
        test_size=args.test_size,
        random_state=args.seed,
        stratify=df["label"].tolist()
    )

    # class weights
    if args["class_weight"] if isinstance(args, dict) else args.class_weight == "balanced":
        classes = np.array(OWASP_LABELS)
        # compute weights only for classes that exist in training set
        present = sorted(set(y_train))
        cw = compute_class_weight(class_weight="balanced", classes=np.array(present), y=y_train)
        class_weight = {cls:w for cls, w in zip(present, cw)}
    else:
        class_weight = None

    vec = build_vectorizer(args.max_features, tuple(args.ngram), args.lower, args.stop_words if args.stop_words!="None" else None)
    clf = build_classifier(args.C, args.penalty, args.solver, class_weight)

    # Fit
    Xtr = vec.fit_transform(X_train)
    clf.fit(Xtr, y_train)

    # Eval
    Xte = vec.transform(X_test)
    y_pred = clf.predict(Xte)
    y_proba = clf.predict_proba(Xte)

    report = classification_report(y_test, y_pred, labels=OWASP_LABELS, zero_division=0, output_dict=True)
    cm = confusion_matrix(y_test, y_pred, labels=OWASP_LABELS).tolist()

    print("\n=== Classification Report (macro avg) ===")
    macro = report.get("macro avg", {})
    print(json.dumps(macro, indent=2))
    print("\n=== Per-class F1 ===")
    per_class = {k: v["f1-score"] for k,v in report.items() if k in OWASP_LABELS}
    print(json.dumps(per_class, indent=2))
    print("\n=== Confusion Matrix (rows=true, cols=pred) ===")
    print(json.dumps(cm))

    if args.report_json:
        os.makedirs(os.path.dirname(args.report_json), exist_ok=True)
        with open(args.report_json, "w", encoding="utf-8") as f:
            json.dump({
                "macro_avg": macro,
                "per_class_f1": per_class,
                "confusion_matrix": cm,
                "labels": OWASP_LABELS
            }, f, ensure_ascii=False, indent=2)

    # Save bundle
    out_path = args.out
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    bundle = {"vectorizer": vec, "model": clf, "labels": OWASP_LABELS}
    joblib.dump(bundle, out_path)
    print(f"\n✅ Saved model bundle to: {out_path}")

    # Sanity: ensure predict_proba works on a tiny batch
    test_sample = ["sql injection in login", "xxe attack via xml parser", "exposed s3 bucket public permission"]
    _ = clf.predict_proba(vec.transform(test_sample))

if __name__ == "__main__":
    main()
