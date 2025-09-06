#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OWASP Top 10 (2021) multi-model voting classifier (English) – MongoDB edition

This build:
- Expanded RULES vocabulary (更多 A01~A10 關鍵字)
- Default soft voting ON；若校準折數不足：
  -> 使用「非校準 soft」(只用有 predict_proba 的基模：LogReg、ComplementNB)
- Default keep-uncat ON（可用 --no-keep-uncat 關閉）
- class_weight='balanced' for linear models
- Safe BSON conversion
"""

import argparse
import json
from datetime import datetime, timezone
import os
import collections
import pandas as pd
import numpy as np
from pymongo import MongoClient
from sklearn.linear_model import LogisticRegression, RidgeClassifier
from sklearn.naive_bayes import ComplementNB
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import VotingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import make_pipeline
from joblib import load
from sklearn.base import BaseEstimator, ClassifierMixin

# ----------------------
# argparse（預設已開 soft + keep-uncat）
# ----------------------
parser = argparse.ArgumentParser(description="OWASP Top 10 voting classifier – MongoDB edition")
parser.add_argument("--mongo-uri", default="mongodb://localhost:27017",
                    help="MongoDB connection URI (default: mongodb://localhost:27017)")
parser.add_argument("--db", default="webcommentIT", help="Database name (default: webcommentIT)")
parser.add_argument("--collection", default="comment", help="Collection name (default: comment)")
parser.add_argument("--out-collection", help="Optionally write results to a new collection")
parser.add_argument("--no-update", action="store_true", help="Do NOT update in place (override default behavior)")
parser.add_argument("--voting", choices=["hard", "soft"], default="soft",
                    help="Voting method (default: soft)")
parser.add_argument("--custom-model", help="Path to custom sklearn model (joblib/pickle)")
parser.add_argument("--keep-uncat", dest="keep_uncat", action="store_true",
                    help="Include Uncategorized samples in weak-label training (default: ON)")
parser.add_argument("--no-keep-uncat", dest="keep_uncat", action="store_false",
                    help="Disable including Uncategorized in weak-label training")
parser.set_defaults(keep_uncat=True)
parser.add_argument("--since", help="Only process docs after YYYY-MM-DD")
parser.add_argument("--until", help="Only process docs before YYYY-MM-DD")
parser.add_argument("--limit", type=int, help="Limit number of documents to process")
parser.add_argument("--query", help="Additional MongoDB query filter as JSON string")
parser.add_argument("--cap-per-class", type=int, default=200,
                    help="Max weak-labeled samples per class for training (default: 200)")
args = parser.parse_args()

# ----------------------
# BSON 安全轉換工具
# ----------------------
def to_bson_safe(obj):
    if isinstance(obj, dict):
        safe = {}
        for k, v in obj.items():
            sk = str(k)
            safe[sk] = to_bson_safe(v)
        return safe
    elif isinstance(obj, (list, tuple, set)):
        return [to_bson_safe(x) for x in obj]
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, (np.integer,)):
        return int(obj)
    elif isinstance(obj, (np.floating,)):
        return float(obj)
    elif isinstance(obj, (np.bool_,)):
        return bool(obj)
    elif isinstance(obj, (np.str_, np.bytes_)):
        return str(obj)
    else:
        return obj

# ----------------------
# 規則集（擴充）
# 備註：XSS 依 2021 版納入 Injection(A03)
# ----------------------
RULES = {
    "A01": [
        "broken access", "access control", "insecure direct object", "idor",
        "unauthorized access", "bypass authorization", "missing authorization",
        "privilege escalation", "role escalation", "forced browsing",
        "path traversal access", "acl ", "access bypass",
        "vertical privilege", "horizontal privilege", "elevation of privilege"
    ],
    "A02": [
        "weak encryption", "plaintext password", "unencrypted ", "no encryption",
        "ssl 3.0", "tls 1.0", "rc4", " des ", " 3des ", " md5", " sha1",
        "hardcoded key", "exposed secret", "leaked key", "insecure cipher",
        "self-signed cert", "certificate validation disabled", "weak tls",
        "insecure ssl", "no https", "missing encryption", "cbc padding oracle",
        "weak cipher suite", "cipher downgrade"
    ],
    "A03": [
        "sql injection", "sqli", "' or 1=1", "\" or \"1\"=\"1", "union select",
        "nosql injection", "mongodb injection", "command injection", "cmd injection",
        "; rm -rf /", "ldap injection", "xml injection", "xpath injection",
        "hql injection", "orm injection", "injection", "unsanitized", "unescaped",
        "xss", "cross-site scripting", "<script>", "onerror=", "javascript:",
        "ssti", "server side template injection", "{{", "{% if", "${{", "#{",
        "xxe", "xml external entity", "path traversal", "../etc/passwd",
        "lfi", "local file inclusion", "rfi", "remote file inclusion",
        "rce", "remote code execution", "arbitrary code execution",
        "os command", "shell injection", "sqlmap", "blind sql",
        "prepared statement missing", "tainted input"
    ],
    "A04": [
        "insecure design", "lack of security controls", "no rate limit",
        "no threat model", "security not considered", "weak default design",
        "no abuse case", "no secure design pattern", "no secure defaults",
        "race condition risk", "unsafe workflow"
    ],
    "A05": [
        "security misconfiguration", "default password", "default creds",
        "directory listing", "dir listing", "open port", "debug enabled",
        "verbose error", "stack trace exposed", "traceback",
        "s3 bucket public", "public bucket", "public storage",
        "csp missing", "content-security-policy missing", "x-frame-options missing",
        "x-content-type-options missing", "cors *", "wide-open cors", "allow-origin *",
        "admin panel exposed", "index of /", "dev mode", "swagger open",
        "exposed actuator", "unauthenticated prometheus", "kibana open",
        "grafana open", "spring boot actuator open", "directory browsing",
        "http only", "no hsts", "insecure headers", "debug=true", "stacktrace"
    ],
    "A06": [
        "outdated library", "outdated component", "vulnerable dependency",
        "known vulnerability", "cve-", "end-of-life", "eol version",
        "unpatched", "dependency vulnerability", "old version",
        "log4j", "struts2", "apache struts", "openssl heartbleed", "shellshock",
        "spring4shell", "atlassian confluence", "drupalgeddon", "unfixed cve",
        "rce in", "poC available", "exploit released"
    ],
    "A07": [
        "broken authentication", "weak password", "no password policy",
        "password reuse", "credential stuffing", "bruteforce", "brute force",
        "session fixation", "session id in url", "predictable session",
        "no multifactor", "mfa disabled", "2fa disabled", "no lockout",
        "password reset", "jwt none", "session hijack", "remember me token",
        "weak session", "oauth misconfiguration", "default credentials",
        "missing account lockout", "weak jwt secret", "password sprayed"
    ],
    "A08": [
        "integrity failure", "tampering", "unverified update",
        "insecure deserialization", "supply chain attack",
        "signed but not verified", "dependency confusion",
        "ci/cd poisoning", "artifact tampering", "unsigned package",
        "malicious dependency", "update integrity not verified",
        "typosquatting package"
    ],
    "A09": [
        "no logging", "no monitoring", "logs missing",
        "audit trail missing", "undetected breach", "alerting absent",
        "insufficient logging", "no audit", "no anomaly detection",
        "logs not centralized", "logging disabled", "no siem",
        "undetected incident"
    ],
    "A10": [
        "ssrf", "server-side request forgery",
        "request to internal", "fetch internal metadata",
        "169.254.169.254", "gcp metadata", "aws metadata",
        "curl file:///etc/passwd", "http://localhost", "http://127.0.0.1",
        "exfiltrate metadata", "imds", "metadata service", "file:///",
        "gopher://", "dict://"
    ],
}

ALL_CLASSES = ["A01","A02","A03","A04","A05","A06","A07","A08","A09","A10","Uncategorized"]

def scan_rules(text: str):
    t = (text or "").lower()
    hits = []
    label_order = []
    for cls in ALL_CLASSES[:-1]:
        for term in RULES.get(cls, []):
            if term.lower() in t:
                hits.append({"class": cls, "term": term.strip()})
                label_order.append(cls)
    best = label_order[0] if label_order else "Uncategorized"
    uniq = []
    seen = set()
    for h in hits:
        key = (h["class"], h["term"])
        if key not in seen:
            seen.add(key)
            uniq.append(h)
    return best, uniq

class RuleModel(BaseEstimator, ClassifierMixin):
    def __init__(self):
        self.classes_ = np.array(ALL_CLASSES)
    def fit(self, X, y=None): return self
    def predict(self, X): return np.array([scan_rules(x)[0] for x in X])
    def predict_proba(self, X):
        preds = self.predict(X)
        proba = np.zeros((len(preds), len(self.classes_)))
        for i, label in enumerate(preds):
            idx = np.where(self.classes_ == label)[0][0]
            proba[i, idx] = 1.0
        return proba

# ----------------------
# MongoDB 抓資料
# ----------------------
client = MongoClient(args.mongo_uri)
db = client[args.db]
coll = db[args.collection]

query = {}
if args.query:
    try:
        query.update(json.loads(args.query))
    except Exception as e:
        print(f"[Warn] --query JSON parse failed: {e}")
if args.since:
    query["created_at"] = {"$gte": args.since}
if args.until:
    query.setdefault("created_at", {})["$lte"] = args.until

print(f"[Info] Mongo query: {query}")
docs = list(coll.find(query, limit=args.limit if args.limit else 0))
print(f"[Info] Loaded {len(docs)} docs from MongoDB")

texts = [d.get("content", "") for d in docs]
ids = [d.get("_id") for d in docs]

# ----------------------
# 弱標註（用規則生成訓練標籤 + 記錄命中）
# ----------------------
rule_model = RuleModel()
weak_labels = []
rule_hits_all = []
for t in texts:
    lbl, hits = scan_rules(t)
    weak_labels.append(lbl)
    rule_hits_all.append(hits)

# 決定訓練集（預設包含 Uncategorized；可用 --no-keep-uncat 關閉）
mask_train = [lbl != "Uncategorized" or args.keep_uncat for lbl in weak_labels]
X_train_full = [texts[i] for i, m in enumerate(mask_train) if m]
y_train_full = [weak_labels[i] for i, m in enumerate(mask_train) if m]

# 依類別 cap
def cap_by_class(X, y, cap=200, seed=42):
    rng = np.random.RandomState(seed)
    by_cls = collections.defaultdict(list)
    for i, cls in enumerate(y):
        by_cls[cls].append(i)
    keep_idx = []
    for cls, idxs in by_cls.items():
        if len(idxs) > cap:
            sel = rng.choice(idxs, size=cap, replace=False)
            keep_idx.extend(sel.tolist())
        else:
            keep_idx.extend(idxs)
    keep_idx = sorted(keep_idx)
    X_cap = [X[i] for i in keep_idx]
    y_cap = [y[i] for i in keep_idx]
    return X_cap, y_cap

X_train, y_train = cap_by_class(X_train_full, y_train_full, cap=args.cap_per_class)
print(f"[Info] Weak train size (capped): {len(X_train)} / {len(texts)}")

# 類別分佈與最小類數
class_counts = collections.Counter(y_train)
print("[Info] Train class counts:", dict(class_counts))
min_class_count = min(class_counts.values()) if class_counts else 0

# ----------------------
# 建立基底模型（含動態校準與「非校準 soft」fallback）
# ----------------------
def tfidf():
    # 稍微強一點的文字特徵
    return TfidfVectorizer(ngram_range=(1,2), min_df=2, max_df=0.95)

def make_estimators_soft_calibrated(cv_folds):
    return [
        ("logreg", make_pipeline(tfidf(), LogisticRegression(max_iter=1000, class_weight="balanced"))),
        ("nb",     make_pipeline(tfidf(), ComplementNB())),
        ("ridge",  CalibratedClassifierCV(make_pipeline(tfidf(), RidgeClassifier(class_weight="balanced")),
                                          cv=cv_folds, method="sigmoid")),
        ("svc",    CalibratedClassifierCV(make_pipeline(tfidf(), LinearSVC(class_weight="balanced")),
                                          cv=cv_folds, method="sigmoid")),
    ]

def make_estimators_soft_nocal():
    # 只用有 predict_proba 的基模，仍可 soft 投票
    return [
        ("logreg", make_pipeline(tfidf(), LogisticRegression(max_iter=1000, class_weight="balanced"))),
        ("nb",     make_pipeline(tfidf(), ComplementNB())),
    ]

def make_estimators_hard():
    return [
        ("logreg", make_pipeline(tfidf(), LogisticRegression(max_iter=1000, class_weight="balanced"))),
        ("nb",     make_pipeline(tfidf(), ComplementNB())),
        ("ridge",  make_pipeline(tfidf(), RidgeClassifier(class_weight="balanced"))),
        ("svc",    make_pipeline(tfidf(), LinearSVC(class_weight="balanced"))),
    ]

effective_voting = args.voting
estimators = []
calib_folds = 0

if args.voting == "soft":
    calib_folds = min(3, max(0, min_class_count))
    if calib_folds >= 2:
        estimators = make_estimators_soft_calibrated(calib_folds)
        effective_voting = "soft"
        print(f"[Info] Using calibrated SOFT voting (cv={calib_folds}).")
    else:
        # 非校準 soft fallback
        estimators = make_estimators_soft_nocal()
        effective_voting = "soft"
        print("[Info] Using NON-calibrated SOFT voting (prob-capable models only).")
else:
    estimators = make_estimators_hard()
    effective_voting = "hard"
    print("[Info] Using HARD voting.")

# 自訂模型（若 effective_voting=soft 且可校準，嘗試包 Calibrated；否則僅附加）
if args.custom_model:
    try:
        custom = load(args.custom_model)
        def has_proba(est): return hasattr(est, "predict_proba")
        def has_decision(est): return hasattr(est, "decision_function")
        if effective_voting == "soft" and calib_folds >= 2 and not has_proba(custom) and has_decision(custom):
            custom = CalibratedClassifierCV(custom, cv=calib_folds, method="sigmoid")
            estimators.append(("custom_cal", custom))
        else:
            estimators.append(("custom", custom))
    except Exception as e:
        print(f"[Warn] Could not load custom model: {e}")

use_ml = len(set(y_train)) >= 2 and len(X_train) >= 5

# ----------------------
# 訓練與推論
# ----------------------
per_model_preds = {name: None for name, _ in estimators}
if use_ml:
    voting_clf = VotingClassifier(estimators=estimators, voting=effective_voting)
    voting_clf.fit(X_train, y_train)

    for name, est in voting_clf.estimators_:
        try:
            per_model_preds[name] = est.predict(texts)
        except Exception:
            per_model_preds[name] = np.array(["Uncategorized"] * len(texts))

    ml_preds = voting_clf.predict(texts)

    ensemble_probs = None
    if effective_voting == "soft":
        try:
            ensemble_probs = voting_clf.predict_proba(texts)
            classes_order = voting_clf.classes_.tolist()
        except Exception:
            ensemble_probs = None
else:
    print("⚠ Only one (or too few) classes in training data, skipping ML ensemble")
    ml_preds = np.array(["Uncategorized"] * len(texts))
    ensemble_probs = None
    per_model_preds = {}

# ----------------------
# 規則補齊 + 準備寫回欄位
# ----------------------
final_preds = []
per_model_field = []
probs_field = []
rule_hits_field = rule_hits_all

for i, text in enumerate(texts):
    pred = ml_preds[i]
    if pred == "Uncategorized":
        pred = rule_model.predict([text])[0]
    final_preds.append(str(pred))

    pm = {}
    for name, arr in per_model_preds.items():
        if arr is not None:
            pm[str(name)] = str(arr[i])
    per_model_field.append(pm)

    top3 = None
    if 'ensemble_probs' in locals() and ensemble_probs is not None:
        row = ensemble_probs[i]
        idxs = np.argsort(-row)[:3]
        top3 = [{"class": str(classes_order[j]), "prob": float(row[j])} for j in idxs]
    probs_field.append(top3)

# ----------------------
# 寫回 Mongo
# ----------------------
now = datetime.now(timezone.utc)
updated_n = 0
if not args.no_update:
    for _id, pred, pm, p3, hits in zip(ids, final_preds, per_model_field, probs_field, rule_hits_field):
        if _id is None:
            continue
        update_doc = {
            "owasp_pred": pred,
            "owasp_per_model": pm if pm else None,
            "owasp_probs": p3,
            "owasp_rule_hits": hits,
            "owasp_updated_at": now
        }
        update_doc = {k: v for k, v in update_doc.items() if v is not None}
        update_doc = to_bson_safe(update_doc)
        res = coll.update_one({"_id": _id}, {"$set": update_doc})
        updated_n += res.modified_count
    print(f"[Info] Updated {updated_n} documents in place")

# out-collection（可選）
if args.out_collection:
    out_coll = db[args.out_collection]
    new_docs = []
    for doc, pred, pm, p3, hits in zip(docs, final_preds, per_model_field, probs_field, rule_hits_field):
        new_doc = {
            "_id": doc["_id"],
            "content": doc.get("content", ""),
            "owasp_pred": pred,
            "owasp_updated_at": now
        }
        if pm: new_doc["owasp_per_model"] = pm
        if p3 is not None: new_doc["owasp_probs"] = p3
        if hits: new_doc["owasp_rule_hits"] = hits
        new_docs.append(to_bson_safe(new_doc))
    if new_docs:
        out_coll.delete_many({})
        out_coll.insert_many(new_docs)
    print(f"[Info] Wrote {len(new_docs)} docs to collection {args.out_collection}")

# 輸出
stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
csv_path = f"owasp_preds_{stamp}.csv"
jsonl_path = f"owasp_preds_{stamp}.jsonl"
stats_path = f"owasp_stats_{stamp}.json"

df = pd.DataFrame({"_id": [str(x) for x in ids], "owasp_pred": final_preds})
df.to_csv(csv_path, index=False)
print(f"[Info] Dumped CSV: {os.path.abspath(csv_path)}")

with open(jsonl_path, "w", encoding="utf-8") as f:
    for _id, pred, pm, p3, hits in zip(ids, final_preds, per_model_field, probs_field, rule_hits_field):
        rec = {
            "_id": str(_id),
            "owasp_pred": pred,
            "owasp_per_model": pm if pm else {},
            "owasp_probs": p3,
            "owasp_rule_hits": hits
        }
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
print(f"[Info] Dumped JSONL: {os.path.abspath(jsonl_path)}")

cnt = collections.Counter(final_preds)
total = len(final_preds) if final_preds else 1
ordered_labels = ALL_CLASSES
stats = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "total": total,
    "counts": {k: int(cnt.get(k, 0)) for k in ordered_labels},
    "ratios": {k: round(cnt.get(k, 0) / total, 6) for k in ordered_labels}
}
with open(stats_path, "w", encoding="utf-8") as f:
    json.dump(stats, f, ensure_ascii=False, indent=2)
print(f"[Info] Dumped STATS JSON: {os.path.abspath(stats_path)}")
stats_line = ", ".join(f"{k}:{cnt.get(k,0)}" for k in ordered_labels)
print("[Stats] class counts =>", stats_line)
print("[Done]")
