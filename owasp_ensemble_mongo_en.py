#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OWASP Top 10 (2021) multi-model voting classifier (English) – MongoDB edition (vNext)

What's new:
- Tighten A03 rules (remove over-generic terms like "injection", "unsanitized", "unescaped" unless in specific phrases)
- Probability threshold fallback: if max-proba < --prob-threshold, set to "Uncategorized"
- Default: do NOT train on Uncategorized (can restore with --keep-uncat)
- Safer write: --out-collection + --no-update for clean A/B
- Calibrated soft voting when possible, fallback to hard/soft as available

Usage examples:
  python owasp_ensemble_mongo_en.py --no-keep-uncat --cap-per-class 400 --prob-threshold 0.45 --out-collection comment_pred_20250906b --no-update
"""

import argparse, json, os, collections
from datetime import datetime, timezone
from typing import Tuple, List, Dict, Any
import numpy as np
import pandas as pd
from pymongo import MongoClient
from sklearn.linear_model import LogisticRegression, RidgeClassifier
from sklearn.naive_bayes import ComplementNB
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import VotingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import make_pipeline
from sklearn.base import BaseEstimator, ClassifierMixin

# ---------------- argparse ----------------
parser = argparse.ArgumentParser(description="OWASP Top 10 voting classifier – MongoDB edition (vNext)")
parser.add_argument("--mongo-uri", default="mongodb://localhost:27017")
parser.add_argument("--db", default="webcommentIT")
parser.add_argument("--collection", default="comment")
parser.add_argument("--out-collection", help="Write predictions to a new collection instead of updating the source one")
parser.add_argument("--no-update", action="store_true", help="Do not update original documents in place")
parser.add_argument("--voting", choices=["hard", "soft"], default="soft")
parser.add_argument("--custom-model", help="(reserved) path to custom model")
parser.add_argument("--keep-uncat", dest="keep_uncat", action="store_true", help="Include Uncategorized in weak training")
parser.add_argument("--no-keep-uncat", dest="keep_uncat", action="store_false", help="Exclude Uncategorized from weak training")
parser.set_defaults(keep_uncat=False)  # changed default
parser.add_argument("--since", help="process docs after YYYY-MM-DD")
parser.add_argument("--until", help="process docs before YYYY-MM-DD")
parser.add_argument("--limit", type=int)
parser.add_argument("--query", help="extra Mongo query as JSON string")
parser.add_argument("--cap-per-class", type=int, default=200)
parser.add_argument("--prob-threshold", type=float, default=0.45, help="min max-proba to accept top class; else -> Uncategorized")
args = parser.parse_args()

# ---------------- RULES (tightened A03) ----------------
RULES: Dict[str, List[str]] = {
    "A01": [
        "broken access", "access control", "insecure direct object", "idor",
        "unauthorized access", "bypass authorization", "missing authorization",
        "privilege escalation", "role escalation", "forced browsing",
        "path traversal access", "acl ", "access bypass",
        "vertical privilege", "horizontal privilege", "elevation of privilege",
        "exposed admin"
    ],
    "A02": [
        "weak encryption", "plaintext password", "unencrypted ", "no encryption",
        "ssl 3.0", "tls 1.0", "rc4", " des ", " 3des ", " md5", " sha1",
        "hardcoded key", "exposed secret", "leaked key", "insecure cipher",
        "self-signed cert", "certificate validation disabled", "weak tls",
        "insecure ssl", "no https", "missing encryption", "cbc padding oracle",
        "weak cipher suite", "cipher downgrade", "insecure random"
    ],
    "A03": [
        # keep SPECIFIC injection forms; drop generic lone "injection"/"unsanitized"/"unescaped"
        "sql injection", "sqli", "' or 1=1", "\" or \"1\"=\"1", "union select",
        "nosql injection", "mongodb injection", "command injection", "cmd injection",
        "; rm -rf /", "ldap injection", "xml injection", "xpath injection",
        "hql injection", "orm injection",
        "xss", "cross-site scripting", "<script>", "onerror=", "javascript:",
        "ssti", "server side template injection", "{{", "{% if", "${{", "#{",
        "xxe", "xml external entity",
        "path traversal", "../etc/passwd",
        "lfi", "local file inclusion", "rfi", "remote file inclusion",
        "rce", "remote code execution", "arbitrary code execution",
        "os command", "shell injection", "sqlmap", "blind sql",
        "prepared statement missing", "tainted input"
    ],
    "A04": [
        "insecure design", "lack of security controls", "no rate limit",
        "no threat model", "weak default design", "no secure defaults",
        "race condition risk"
    ],
    "A05": [
        "security misconfiguration", "default password", "default creds",
        "directory listing", "dir listing", "open port", "debug enabled",
        "verbose error", "stack trace exposed", "traceback",
        "s3 bucket public", "public bucket", "public storage",
        "csp missing", "x-frame-options missing",
        "x-content-type-options missing", "cors *", "wide-open cors",
        "admin panel exposed", "index of /", "dev mode", "swagger open",
        "exposed actuator", "unauthenticated prometheus", "kibana open",
        "grafana open", "spring boot actuator open", "directory browsing",
        "no hsts", "insecure headers", "debug=true", "stacktrace"
    ],
    "A06": [
        "outdated library", "outdated component", "vulnerable dependency",
        "known vulnerability", "cve-", "end-of-life", "eol version",
        "unpatched", "dependency vulnerability", "old version",
        "log4j", "struts2", "apache struts", "openssl heartbleed", "shellshock",
        "spring4shell", "atlassian confluence", "drupalgeddon", "unfixed cve",
        "rce in", "poc available", "exploit released"
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
        "typosquatting package", "provenance", "cosign", "sigstore"
    ],
    "A09": [
        "no logging", "no monitoring", "logs missing",
        "audit trail missing", "undetected breach", "alerting absent",
        "insufficient logging", "no audit", "no anomaly detection",
        "logs not centralized", "logging disabled", "no siem", "undetected incident"
    ],
    "A10": [
        "ssrf", "server-side request forgery",
        "request to internal", "fetch internal metadata",
        "169.254.169.254", "gcp metadata", "aws metadata",
        "curl file:///etc/passwd", "http://localhost", "http://127.0.0.1",
        "exfiltrate metadata", "imds", "metadata service", "file:///", "gopher://", "dict://"
    ],
}
ALL_CLASSES = [f"A{i:02d}" for i in range(1, 11)] + ["Uncategorized"]

def scan_rules(text: str) -> Tuple[str, List[Dict[str,str]]]:
    t = (text or "").lower()
    hits, label_order = [], []
    for cls in ALL_CLASSES[:-1]:
        for term in RULES.get(cls, []):
            if term.lower() in t:
                hits.append({"class": cls, "term": term.strip()})
                label_order.append(cls)
    best = label_order[0] if label_order else "Uncategorized"
    uniq, seen = [], set()
    for h in hits:
        key = (h["class"], h["term"])
        if key not in seen:
            seen.add(key); uniq.append(h)
    return best, uniq

class RuleModel(BaseEstimator, ClassifierMixin):
    def __init__(self): self.classes_ = np.array(ALL_CLASSES)
    def fit(self, X, y=None): return self
    def predict(self, X): return np.array([scan_rules(x)[0] for x in X])
    def predict_proba(self, X):
        preds = self.predict(X)
        proba = np.zeros((len(preds), len(self.classes_)))
        for i, label in enumerate(preds):
            idx = np.where(self.classes_ == label)[0][0]
            proba[i, idx] = 1.0
        return proba

# ---------------- data ----------------
client = MongoClient(args.mongo_uri)
db = client[args.db]
src_coll = db[args.collection]
dst_coll = db[args.out_collection] if args.out_collection else src_coll

query: Dict[str, Any] = {}
if args.query:
    try:
        query.update(json.loads(args.query))
    except Exception as e:
        print(f"[Warn] --query JSON parse failed: {e}")
if args.since: query["created_at"] = {"$gte": args.since}
if args.until: query.setdefault("created_at", {})["$lte"] = args.until

print(f"[Info] Mongo query: {query}")
docs = list(src_coll.find(query, limit=args.limit if args.limit else 0))
print(f"[Info] Loaded {len(docs)} docs from MongoDB")

texts = [d.get("content", "") for d in docs]
ids = [d.get("_id") for d in docs]

# ---------------- weak labels ----------------
rule_model = RuleModel()
weak_labels, rule_hits_all = [], []
for t in texts:
    lbl, hits = scan_rules(t)
    weak_labels.append(lbl)
    rule_hits_all.append(hits)

# decide training mask
mask_train = [lbl != "Uncategorized" or args.keep_uncat for lbl in weak_labels]
X_train_full = [texts[i] for i, m in enumerate(mask_train) if m]
y_train_full = [weak_labels[i] for i, m in enumerate(mask_train) if m]

def cap_by_class(X, y, cap=200, seed=42):
    import numpy as np, collections
    rng = np.random.RandomState(seed)
    by_cls = collections.defaultdict(list)
    for i, cls in enumerate(y): by_cls[cls].append(i)
    keep_idx = []
    for cls, idxs in by_cls.items():
        if len(idxs) > cap:
            sel = rng.choice(idxs, size=cap, replace=False)
            keep_idx.extend(sel.tolist())
        else:
            keep_idx.extend(idxs)
    keep_idx = sorted(keep_idx)
    return [X[i] for i in keep_idx], [y[i] for i in keep_idx]

X_train, y_train = cap_by_class(X_train_full, y_train_full, cap=args.cap_per_class)
print(f"[Info] Weak train size (capped): {len(X_train)} / {len(texts)}")
from collections import Counter
print("[Info] Train class counts:", dict(Counter(y_train)))

# ---------------- models ----------------
def tfidf(): return TfidfVectorizer(ngram_range=(1,2), min_df=2, max_df=0.95)

def make_estimators_calibrated(cv_folds:int):
    return [
        ("logreg", make_pipeline(tfidf(), LogisticRegression(max_iter=1000, class_weight="balanced"))),
        ("nb",     make_pipeline(tfidf(), ComplementNB())),
        ("ridge",  CalibratedClassifierCV(make_pipeline(tfidf(), RidgeClassifier(class_weight="balanced")), cv=cv_folds, method="sigmoid")),
        ("svc",    CalibratedClassifierCV(make_pipeline(tfidf(), LinearSVC(class_weight="balanced")), cv=cv_folds, method="sigmoid")),
    ]

def make_estimators_soft_nocal():
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

# choose calibration folds from minority count
min_count = min(Counter(y_train).values()) if y_train else 0
estimators, effective_voting = [], args.voting
if args.voting == "soft":
    if min_count >= 2:
        estimators = make_estimators_calibrated(min(3, min_count))
    else:
        estimators = make_estimators_soft_nocal()
        effective_voting = "soft"
else:
    estimators = make_estimators_hard()
    effective_voting = "hard"

ensemble = VotingClassifier(estimators=estimators, voting=effective_voting)
ensemble.fit(X_train, y_train)

# ---------------- predict ----------------
preds = ensemble.predict(texts)
proba = None
try:
    proba = ensemble.predict_proba(texts)
except Exception:
    proba = None

def top_with_threshold(i:int) -> Tuple[str, float]:
    if proba is None:
        # hard voting → approximate by 1.0 on predicted class
        return preds[i], 1.0
    row = proba[i]
    j = int(np.argmax(row))
    return ensemble.classes_[j], float(row[j])

rows = []
for idx, _id in enumerate(ids):
    top, p = top_with_threshold(idx)
    if p < args.prob_threshold:
        top = "Uncategorized"
    rows.append({
        "_id": _id,
        "owasp_top": top,
        "owasp_hits": [h["class"] for h in rule_hits_all[idx]] if rule_hits_all[idx] else [],
        "pred_proba": round(p, 4),
    })

# ---------------- write back / export ----------------
updated = 0
now = datetime.now(timezone.utc)
csv_rows, stats = [], collections.Counter()
for r in rows:
    stats[r["owasp_top"]] += 1
    csv_rows.append({"_id": str(r["_id"]), "owasp_top": r["owasp_top"], "pred_proba": r["pred_proba"]})

    if args.no_update and args.out_collection:
        # insert new docs with only predictions (reference by _id)
        dst_coll.update_one({"_id": r["_id"]}, {"$set": {
            "owasp_top": r["owasp_top"],
            "owasp_hits": r["owasp_hits"],
            "pred_proba": r["pred_proba"],
            "pred_at": now,
        }}, upsert=True)
        updated += 1
    elif not args.no_update:
        # update in place
        src_coll.update_one({"_id": r["_id"]}, {"$set": {
            "owasp_top": r["owasp_top"],
            "owasp_hits": r["owasp_hits"],
            "pred_proba": r["pred_proba"],
            "pred_at": now,
        }})
        updated += 1

print(f"[Info] Updated {updated} documents {'(new collection)' if args.no_update and args.out_collection else '(in place)'}")
ts = now.strftime("%Y%m%d_%H%M%S")
csv_path = f"owasp_preds_{ts}.csv"
jsonl_path = f"owasp_preds_{ts}.jsonl"
stats_path = f"owasp_stats_{ts}.json"

pd.DataFrame(csv_rows).to_csv(csv_path, index=False, encoding="utf-8")
with open(jsonl_path, "w", encoding="utf-8") as f:
    for r in rows:
        f.write(json.dumps({"_id": str(r["_id"]), **{k:v for k,v in r.items() if k!='_id'}}, ensure_ascii=False) + "\n")
with open(stats_path, "w", encoding="utf-8") as f:
    json.dump({"counts": dict(stats)}, f, ensure_ascii=False, indent=2)

print(f"[Stats] class counts => " + ", ".join([f"{k}:{v}" for k,v in stats.items()]))
print("[Done]")
