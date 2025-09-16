#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# OWASP Top 10 (2021) rule-based auto-labeler v3.3 (train-writer)
# - Source:  webcommentIT.comment
# - Target:  webcommentIT_train.comment_train  (only when label ∈ {A1..A10})
# - Writes:  auto_label, auto_conf, auto_top3, auto_labeled_at
# - Keeps:   your latest RX rules, dynamic options, light reporting

import os, sys, re, json, math, argparse, statistics, time
from typing import Dict, Any, List, Tuple
from datetime import datetime, timezone, timedelta
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv(Path(".") / ".env", override=True)
    load_dotenv(Path(".") / ".env.local", override=True)
except Exception:
    pass

from pymongo import MongoClient

DEF_URL  = os.getenv("MONGO_URL", "mongodb://localhost:27017")

SRC_DB   = "webcommentIT"
SRC_COLL = "comment"
DST_DB   = "webcommentIT_train"
DST_COLL = "comment_train"

CATS = {
    "A1":  "Broken Access Control",
    "A2":  "Cryptographic Failures",
    "A3":  "Injection",
    "A4":  "Insecure Design",
    "A5":  "Security Misconfiguration",
    "A6":  "Vulnerable and Outdated Components",
    "A7":  "Identification and Authentication Failures",
    "A8":  "Software and Data Integrity Failures",
    "A9":  "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery",
}

# =========================
# RX 規則（使用你提供的版本）
# =========================
RX = {
  "A1": [
      r"\b(broken\s+access\s+control|bac)\b",
      r"\b(access\s*control\s*(bypass|failure|exposure))\b",
      r"\b(privilege\s+(?:esc|escalation)|elevation\s+of\s+privilege|eop)\b",
      r"\b(idor|insecure\s+direct\s+object\s+reference)\b",
      r"\b(acl|rbac|abac)\b",
      r"\b(cross[-\s]*tenant|multi[-\s]*tenant\s*escape)\b",
      r"\b(insecure\s*cors|cors\s+misconfig)\b",
      r"\b(open\s*redirect)\b",
      r"未授權|未授权|越權|越权|存取控制|權限檢查|权限检查|權限繞過|权限绕过",
  ],
  "A2": [
      r"\b(crypto(graph(y|ic))?\s*failure|weak\s*(encryption|cipher|hash))\b",
      r"\b(tls\s*1(?:\.0|\.1)|ssl\s*3\.0|rc4|md5|sha1)\b",
      r"\b(cert(ificate)?\s*pinning\s*(bypass|failure))\b",
      r"\b(plaintext\s*(password|secret)|hardcoded\s*(key|secret))\b",
      r"\b(keystore|hsm|fips\s*140[- ]2|pbkdf2|bcrypt|argon2)\b",
      r"加密|密碼學|密码学|明文傳輸|明文存儲|弱加密|硬編碼密鑰|硬编码密钥|證書|证书",
  ],
  "A3": [
      r"\b(sql\s*injection|sqli)\b",
      r"\b(xss|cross[-\s]*site\s*scripting)\b",
      r"\b(nosql\s*injection|ldap\s*injection|command\s*injection|rce|code\s*injection)\b",
      r"\b(deserialization\s*(bug|attack)|insecure\s*deserialization)\b",
      r"\b(template\s*injection|ssti)\b",
      r"\b(path\s*traversal|directory\s*traversal|lfi|rfi)\b",
      r"\b(xml\s*external\s*entity|xxe)\b",
      r"\b(header\s*injection|host\s*header\s*attack|crlf\s*injection)\b",
      r"\b(jwt|jwk)\s*injection\b",
      r"注入|代码注入|指令注入|反序列化|模板注入|遍歷攻擊|路径遍历|目錄遍歷",
  ],
  "A4": [
      r"\b(insecure\s*design|threat\s*model(ing)?\s*missing)\b",
      r"\b(race\s*condition|toctou)\b",
      r"\b(business\s*logic\s*(bug|flaw|bypass))\b",
      r"\b(unsafe\s*defaults|design\s*gap)\b",
      r"設計不安全|业务逻辑漏洞|邏輯缺陷|逻辑缺陷|競態條件|竞争条件",
  ],
  "A5": [
      r"\b(misconfig(uration)?|default\s*credentials|open\s*s3\s*buckets?)\b",
      r"\b(directory\s*listing|exposed\s*admin|/.git/|/.env)\b",
      r"\b(cors\s*(?:disabled|allow[-\*]\*|\*)|\bcsp\s*(?:none|disabled)|x-frame-options\s*missing)\b",
      r"\b(debug\s*(?:true|enabled)|stack\s*trace\s*exposed)\b",
      r"\b(public\s*bucket|world[-\s]*readable|0\.0\.0\.0[:/])\b",
      r"設定錯誤|配置错误|預設密碼|默认口令|目錄列出|目录列出|暴露管理端",
      r"\b(exposed|public)\s*(admin|dashboard|kibana|prometheus|grafana)\b",
      r"\b(open\s*(port|endpoint)s?\s*(?:to\s*world|0\.0\.0\.0))\b",
      r"\b(\.env|application\.ya?ml|config\.ya?ml|dockerfile)\s*(leak|exposed)\b",
      r"\b(unrestricted|unauthenticated)\s*(access|endpoint|api)\b",
  ],
  "A6": [
      r"\b(cve-\d{4}-\d{3,7})\b",
      r"\b(outdated\s*(library|dependency|component|package|plugin|framework))\b",
      r"\b(vulnerab(?:le|ility)\s*(?:in|of)?\s*(version|package|component)?)\b",
      r"\b(patch(?:ed|ing)?|advisory|security\s*update)\b",
      r"\b(end[-\s]*of[-\s]*life|eol)\b",
      r"\b(sbom|dependency\s*check|ossindex)\b",
      r"組件漏洞|第三方套件|依賴漏洞|依赖漏洞|套件更新|安全更新|修補|修补|補丁|补丁",
  ],
  "A7": [
      r"\b(auth(entication|orization)?\s*(failure|bypass)|2fa\s*missing|mfa\s*disabled)\b",
      r"\b(brute\s*force|credential\s*stuffing|password\s*reset\s*flaw|password\s*spray)\b",
      r"\b(session\s*(fixation|hijacking)|jwt\s*(none|weak|no\s*expiry|no\s*expiration)|oauth|sso)\b",
      r"\b(api[-\s]*key\s*leak|token\s*leak|password\s*exposed)\b",
      r"身份驗證|身份验证|登入繞過|登录绕过|弱口令|憑證填充|凭证填充|密碼重設|口令洩露|口令泄露",
      r"\bsession\s*cookie\s*(missing|insecure|no\s*httponly|no\s*secure)\b",
      r"\boauth\s*(misconfig|open\s*redirect)\b",
  ],
  "A8": [
      r"\b(supply\s*chain\s*(attack|compromise)|ci/cd\s*(injection|poisoning))\b",
      r"\b(code\s*sign(ing)?\s*(bypass|failure)|integrity\s*(check|violation))\b",
      r"\b(dependency\s*confusion|typo\s*squatting|package\s*takeover)\b",
      r"\b(protected\s*branch\s*bypass|malicious\s*commit|pipeline\s*poison)\b",
      r"供應鏈|供应链|依賴混淆|依赖混淆|簽章|签章|軟體完整性|软件完整性",
  ],
  "A9": [
      r"\b(logging\s*(disabled|missing)|monitoring\s*(gap|failure))\b",
      r"\b(audit\s*trail\s*missing|no\s*alerts|alerting\s*(gap|failure))\b",
      r"\b(siem|edr)\s*(?:none|missing|disabled)\b",
      r"日誌不足|日志不足|監控不足|监控不足|告警缺失|告警不足",
      r"\b(no|missing|insufficient)\s*(audit|trace|telemetry|observability)\b",
      r"\b(failed|lack\s*of)\s*(alert|alarm|siem|edr|ids|ips)\b",
      r"可觀測性|可观测性|無告警|无告警|缺乏告警|缺監控|缺监控",
  ],
  "A10": [
      r"\b(ssrf|server[-\s]*side\s*request\s*forgery)\b",
      r"\b(metadata\s*service\s*(aws|gcp|azure)|169\.254\.169\.254)\b",
      r"\b(request\s*smuggling|smuggled\s*requests?)\b",
      r"伺服器端請求偽造|服务端请求伪造|請求走私|请求走私",
  ],
}

NEG_TITLE = [
  r"\bwho\s+is\s+hiring\b",
  r"\bhiring\b",
  r"\bweekly\s+discussion\b",
  r"\blooking\s+for\s+work\b",
]

def _compile(rx_list): return [re.compile(p, re.I | re.M) for p in rx_list]
RXC = {k: _compile(v) for k, v in RX.items()}
NEG_TITLE_R = _compile(NEG_TITLE)

def _collect_hits(text: str, title: str) -> Dict[str, int]:
    low = f"{title}\n\n{text}".lower()
    hits = {}
    for k, regs in RXC.items():
        c = 0
        for r in regs:
            c += len(r.findall(low))
        if c:
            hits[k] = c
    return hits

def score_text(title: str, text: str, aggressive: bool=False) -> Dict[str, float]:
    title_l = (title or "").lower()
    low = f"{title}\n\n{text}".lower()

    for r in NEG_TITLE_R:
        if r.search(title_l):
            return {k: 0.0 for k in CATS.keys()}

    L = max(50, min(20000, len(low)))
    norm = 10.0 + math.sqrt(L) * 0.9

    boost_title = 3.0 if aggressive else 2.0
    base_hit = 1.5 if aggressive else 1.0

    scores = {k: 0.0 for k in CATS.keys()}
    for k, regs in RXC.items():
        s = 0.0
        for r in regs:
            m_all = r.findall(low)
            if not m_all:
                continue
            s += base_hit * len(m_all)
            if title and r.search(title_l):
                s += boost_title
        scores[k] = s / norm
    return scores

def pick(scores: Dict[str, float], topn: int = 3) -> Tuple[str, float, List[Tuple[str,float]]]:
    sorted_items = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    top = sorted_items[:max(1, topn)]
    best_cat, best = top[0]
    den = sum(v for _, v in top) + 1e-6
    conf = float(best / den) if den > 0 else 0.0
    return best_cat, conf, top

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mongo-url", default=DEF_URL)
    ap.add_argument("--limit", type=int, default=0, help="0 = all matched")
    ap.add_argument("--since-days", type=int, default=0, help="only docs created in last N days")
    ap.add_argument("--threshold", type=float, default=0.45, help="min conf for accepting top1")
    ap.add_argument("--min-abs", type=float, default=0.0, help="require raw top1 score >= this value")
    ap.add_argument("--aggressive", action="store_true", help="higher recall (title boost / base hits)")
    ap.add_argument("--source-in", nargs="*", default=None, help="only these sources (e.g. hn reddit stackex)")
    ap.add_argument("--source-not", nargs="*", default=None, help="exclude sources")
    ap.add_argument("--query-json", default=None, help='extra MongoDB query (JSON string), ANDed with base query')
    ap.add_argument("--debug-matches", action="store_true", help="print/store minimal hit reasons")
    args = ap.parse_args()

    cli = MongoClient(args.mongo_url, tz_aware=True)
    src = cli[SRC_DB][SRC_COLL]
    dst = cli[DST_DB][DST_COLL]

    # ---------- build query ----------
    q: Dict[str, Any] = {}
    if args.source_in:
        q["source"] = {"$in": args.source_in}
    else:
        q["source"] = {"$in": ["hn", "reddit", "stackex"]}

    if args.source_not:
        if "source" in q and "$in" in q["source"]:
            q["source"] = {"$in": q["source"]["$in"], "$nin": args.source_not}
        else:
            q["source"] = {"$nin": args.source_not}

    if args.since_days and args.since_days > 0:
        since = datetime.now(timezone.utc) - timedelta(days=args.since_days)
        q["created_at"] = {"$gte": since}

    if args.query_json:
        try:
            extra = json.loads(args.query_json)
            q = {"$and": [q, extra]} if q else extra
        except Exception as e:
            print(f"[warn] --query-json parse error: {e}; ignored", file=sys.stderr)

    fields = {
        "_id":1,"source":1,"type":1,"title":1,"content":1,"url":1,
        "created_at":1,"author":1,"score":1,"subreddit":1,"site":1
    }

    total_match = src.count_documents(q)
    total = total_match if not args.limit or args.limit<=0 else min(total_match, args.limit)
    print(f"[info] matching docs: {total_match}; processing: {total}")

    cur = src.find(q, fields, no_cursor_timeout=True).sort("created_at", -1)

    processed = 0
    inserted = 0
    counts: Dict[str, int] = {}
    confs: Dict[str, List[float]] = {}

    t0 = time.time()

    try:
        for doc in cur:
            if args.limit and processed >= total:
                break

            title = (doc.get("title") or "")[:400]
            text  = (doc.get("content") or "")[:6000]  # cap to keep perf predictable
            scores = score_text(title, text, aggressive=args.aggressive)

            cat, conf, top3 = pick(scores, topn=3)
            max_score = max(scores.values()) if scores else 0.0

            # decision
            if (conf >= args.threshold and max_score >= args.min_abs):
                label = cat
            else:
                label = "Uncertain"

            counts[label] = counts.get(label, 0) + 1
            confs.setdefault(label, []).append(conf if label != "Uncertain" else 0.0)

            # Only write A1..A10 into training collection
            if label in CATS:
                newdoc = dict(doc)
                newdoc["auto_label"] = label
                newdoc["auto_conf"]  = round(conf, 4)
                newdoc["auto_top3"]  = [(k, round(v,4)) for k,v in top3]
                newdoc["auto_labeled_at"] = datetime.now(timezone.utc)
                dst.replace_one({"_id": doc["_id"]}, newdoc, upsert=True)
                inserted += 1

            processed += 1

            if processed % 2000 == 0:
                elapsed = time.time() - t0
                rate = processed / max(1.0, elapsed)
                print(f"[progress] processed={processed}/{total}  {rate:.1f} doc/s  inserted={inserted}")

    finally:
        try:
            cur.close()
        except Exception:
            pass

    # Summary
    print("\n[report] label counts and avg_conf:")
    def _sort_key(kv):  # Uncertain first, then by count desc
        label, n = kv
        return (0 if label == "Uncertain" else 1, -n, label)
    for label, n in sorted(counts.items(), key=_sort_key):
        arr = confs.get(label, [])
        avgc = statistics.mean(arr) if arr else 0.0
        print(f"{label:12s} {n:6d}  avg_conf={avgc:.3f}")

    print(f"[done] processed={processed} inserted={inserted} "
          f"threshold={args.threshold} min_abs={args.min_abs} aggressive={args.aggressive}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
