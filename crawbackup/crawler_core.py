# -*- coding: utf-8 -*-
"""
crawler_core.py
共用核心：抓近期熱度的資安內容，打 OWASP(A01~A10) 分、每日配額、去重 upsert。
新增/強化：
- RSS/Atom（FEED_URLS）
- 規則詞庫大幅補強（特別拉升 A01/A02/A07/A08 的命中）
- 偏好命中取樣（MODE_COMMENTS=train 時，命中類別的評論優先保留）
- 訓練友善開關：INCLUDE_POSTS、REQUIRE_TOP_CLASS
- 嚴格配額 STRICT_QUOTA（超過每日配額時直接不收）
- HN HTML → Algolia API 備援；SE 節流；Mongo 索引與統計摘要
"""

import os, re, time, json, hashlib, random
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List, Tuple
from pathlib import Path

# ------- .env 載入（可用 DOTENV_FILE 指定） -------
from dotenv import load_dotenv
_DOTENV = os.getenv("DOTENV_FILE", str(Path(__file__).parent / ".env"))
load_dotenv(dotenv_path=_DOTENV, override=True)

# 另外嘗試載入 .env.secrets（若存在，且不覆蓋已存在設定）
_secrets = Path(__file__).parent / ".env.secrets"
if _secrets.exists():
    load_dotenv(dotenv_path=_secrets, override=False)

import feedparser
import requests
from requests.adapters import HTTPAdapter, Retry
from bs4 import BeautifulSoup
from pymongo import MongoClient, ASCENDING

# ============== 基本設定（可用 .env 覆蓋） ==============
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "webcommentIT")
COLLECTION = os.getenv("COLLECTION", "comment")

RECENT_DAYS = int(os.getenv("RECENT_DAYS", "7"))
HN_MIN_POINTS = int(os.getenv("HN_MIN_POINTS", "10"))
REDDIT_MIN_UPVOTES = int(os.getenv("REDDIT_MIN_UPVOTES", "10"))
REDDIT_MIN_COMMENTS = int(os.getenv("REDDIT_MIN_COMMENTS", "3"))
SE_MIN_VOTES = int(os.getenv("SE_MIN_VOTES", "1"))

HN_PAGES = int(os.getenv("HN_PAGES", "10"))
SE_PAGES = int(os.getenv("SE_PAGES", "10"))
REDDIT_LIMIT_PER_SUB = int(os.getenv("REDDIT_LIMIT_PER_SUB", "150"))
REDDIT_SUBS = [s.strip() for s in os.getenv(
    "REDDIT_SUBS",
    "netsec,cybersecurity,AskNetsec,blueteamsec,InformationSecurity"
).split(",") if s.strip()]

REDDIT_CLIENT_ID = os.getenv("REDDIT_CLIENT_ID", "")
REDDIT_CLIENT_SECRET = os.getenv("REDDIT_CLIENT_SECRET", "")
REDDIT_USER_AGENT = os.getenv("REDDIT_USER_AGENT", "windows:webcomment:1.0 (by u/yourname)")

NVD_DAYS = int(os.getenv("NVD_DAYS", "3"))
NVD_API_KEY = os.getenv("NVD_API_KEY", "")

FEED_URLS = [u for u in os.getenv("FEED_URLS", "").split(",") if u.strip()]

MIN_SCORE_TO_INSERT = float(os.getenv("MIN_SCORE_TO_INSERT", "0"))

CLASS_DAILY_TARGET = {
    "A01": int(os.getenv("Q_A01", "120")),
    "A02": int(os.getenv("Q_A02", "120")),
    "A03": int(os.getenv("Q_A03", "120")),
    "A04": int(os.getenv("Q_A04", "120")),
    "A05": int(os.getenv("Q_A05", "120")),
    "A06": int(os.getenv("Q_A06", "120")),
    "A07": int(os.getenv("Q_A07", "120")),
    "A08": int(os.getenv("Q_A08", "120")),
    "A09": int(os.getenv("Q_A09", "120")),
    "A10": int(os.getenv("Q_A10", "120")),
}
MIN_SCORE_BY_CLASS = {
    "A01": int(os.getenv("MS_A01", "1")),
    "A02": int(os.getenv("MS_A02", "1")),
    "A03": int(os.getenv("MS_A03", "1")),
    "A04": int(os.getenv("MS_A04", "1")),
    "A05": int(os.getenv("MS_A05", "1")),
    "A06": int(os.getenv("MS_A06", "2")),  # A06 資訊品質高，稍高門檻
    "A07": int(os.getenv("MS_A07", "1")),
    "A08": int(os.getenv("MS_A08", "1")),
    "A09": int(os.getenv("MS_A09", "1")),
    "A10": int(os.getenv("MS_A10", "1")),
}

# ===== 評論分流（hot/train） =====
_BUCKET = os.getenv("MODE_COMMENTS", "hot").strip().lower()  # "hot" or "train"
# 訓練友善開關
REQUIRE_TOP_CLASS = os.getenv("REQUIRE_TOP_CLASS", "0") == "1"  # 一般來源必須命中類別才收
INCLUDE_POSTS = os.getenv("INCLUDE_POSTS", "1") == "1"          # 收貼文（1）或僅評論（0）

# 嚴格配額：超過 CLASS_DAILY_TARGET 時直接不收
STRICT_QUOTA = os.getenv("STRICT_QUOTA", "0") == "1"

# hot：熱門評論門檻
HOT_COMMENT_TOP_N = int(os.getenv("HOT_COMMENT_TOP_N", "10"))
HOT_COMMENT_MIN_LEN = int(os.getenv("HOT_COMMENT_MIN_LEN", "20"))
HOT_REDDIT_COMMENT_MIN_UPVOTES = int(os.getenv("HOT_REDDIT_COMMENT_MIN_UPVOTES", "5"))

# train：訓練評論取樣 + 偏好命中
TRAIN_COMMENT_MAX_PER_THREAD = int(os.getenv("TRAIN_COMMENT_MAX_PER_THREAD", "50"))
TRAIN_COMMENT_SAMPLE_PROB = float(os.getenv("TRAIN_COMMENT_SAMPLE_PROB", "0.6"))
TRAIN_REQUIRE_MIN_SCORE = os.getenv("TRAIN_REQUIRE_MIN_SCORE", "1") == "1"
TRAIN_BIAS_KEEP_IF_HIT = os.getenv("TRAIN_BIAS_KEEP_IF_HIT", "1") == "1"   # 命中類別→優先保留
TRAIN_BIAS_PROB_NO_HIT = float(os.getenv("TRAIN_BIAS_PROB_NO_HIT", "0.3")) # 未命中時的保留機率

PRINT_SUMMARY = os.getenv("PRINT_SUMMARY", "1") == "1"

# ============== HTTP Session（重試/超時/尊重 Retry-After） ==============
def make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": "Mozilla/5.0 (security-crawler; contact:webcommentIT)"})
    retry = Retry(
        total=8,
        backoff_factor=1.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "HEAD"],
        respect_retry_after_header=True,
    )
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.mount("http://", HTTPAdapter(max_retries=retry))
    return s

SESSION = make_session()

# ============== Mongo ==============
client = MongoClient(MONGO_URI)
db = client[DB_NAME]
col = db[COLLECTION]
col.create_index([("source", ASCENDING), ("type", ASCENDING), ("url", ASCENDING), ("content_hash", ASCENDING)], unique=True)
col.create_index([("created_at", ASCENDING)])
col.create_index([("priority_score", ASCENDING)])
col.create_index([("owasp_hits.class", ASCENDING)])
col.create_index([("owasp_top", ASCENDING)])
col.create_index([("bucket", ASCENDING)])

# ============== OWASP 打分（規則詞庫補強） ==============
OWASP_RULES = {
    # A01 Broken Access Control
    "A01": [
        "broken access", "access control", "acl ", "rbac", "abac",
        "insecure direct object", "idor", "direct object reference",
        "forced browsing", "privilege escalation", "privilege bypass",
        "authorization bypass", "bypass authorization", "unauthorized access",
        "role escalation", "exposed admin"
    ],
    # A02 Cryptographic Failures
    "A02": [
        "weak encryption", "plaintext password", "unencrypted ", "no encryption",
        "ssl 3.0", "tls 1.0", "rc4", " des ", " 3des ", " md5", " sha1",
        "hardcoded key", "exposed secret", "leaked key", "insecure cipher",
        "self-signed cert", "certificate validation disabled",
        "cbc mode", "padding oracle", "kdf", "pbkdf2", "argon2", "bcrypt",
        "insecure random", "nonce reuse", "weak key",
        "certificate pinning disabled", "no https", "cert pinning disabled"
    ],
    # A03 Injection
    "A03": [
        "sql injection", "sqli", "' or 1=1", "\" or \"1\"=\"1", "union select",
        "nosql injection", "mongodb injection", "command injection", "cmd injection",
        "; rm -rf /", "ldap injection", "xml injection", "xpath injection",
        "hql injection", "orm injection", "injection", "unsanitized", "unescaped",
        "xss", "ssti", "xxe", "lfi", "rfi", "rce"
    ],
    # A04 Insecure Design
    "A04": [
        "insecure design", "lack of security controls", "no rate limit",
        "no threat model", "security not considered", "weak default design",
        "weak default"
    ],
    # A05 Security Misconfiguration
    "A05": [
        "security misconfiguration", "default password", "default creds",
        "directory listing", "open port", "debug enabled", "verbose error",
        "stack trace exposed", "s3 bucket public", "public bucket",
        "csp missing", "x-frame-options missing", "cors *", "wide-open cors",
        "admin panel exposed", "index of /", "traceback", "dev mode",
        "weak csp", "missing hsts", "insecure headers"
    ],
    # A06 Vulnerable and Outdated Components
    "A06": [
        "outdated library", "outdated component", "vulnerable dependency",
        "known vulnerability", "cve-", "end-of-life", "eol version",
        "unpatched", "dependency vulnerability", "old version",
        "log4j", "struts2", "spring4shell"
    ],
    # A07 Identification and Authentication Failures
    "A07": [
        "broken authentication", "weak password", "no password policy",
        "password reuse", "credential stuffing", "bruteforce", "brute force",
        "session fixation", "session id in url", "predictable session",
        "no multifactor", "mfa disabled", "2fa disabled", "no lockout",
        "password reset", "jwt none", "session hijack",
        "oauth", "openid connect", "oidc", "sso", "saml",
        "jwt ", "refresh token", "magic link", "session cookie",
        "remember me", "default credentials", "mfa", "2fa", "otp"
    ],
    # A08 Software and Data Integrity Failures
    "A08": [
        "integrity failure", "tampering", "unverified update",
        "insecure deserialization", "supply chain attack",
        "signed but not verified", "dependency confusion",
        "code signing", "ci/cd", "artifact tampering",
        "checksum mismatch", "sigstore", "cosign", "provenance", "slsa"
    ],
    # A09 Security Logging and Monitoring Failures
    "A09": [
        "no logging", "no monitoring", "logs missing",
        "audit trail missing", "undetected breach", "alerting absent",
        "insufficient logging"
    ],
    # A10 SSRF
    "A10": [
        "ssrf", "server-side request forgery",
        "request to internal", "fetch internal metadata",
        "169.254.169.254", "gcp metadata", "aws metadata", "localhost request"
    ],
}
GENERIC_SECURITY = ["cve-", "advisory", "vulnerability", "exploit", "patch", "mitigation", "poc"]
RGX_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
RGX_TLS10 = re.compile(r"\bTLS\s*1\.0\b", re.I)
RGX_WEAK_HASH = re.compile(r"\b(MD5|SHA1)\b", re.I)
WS_RE = re.compile(r"\s+")

def normalize_text(s: Optional[str]) -> str:
    if not s: return ""
    return WS_RE.sub(" ", s.replace("\u0000", "")).strip()

def content_hash(source: str, url: str, content: str) -> str:
    key = f"{source}||{url}||{content}".encode("utf-8", errors="ignore")
    return hashlib.sha1(key).hexdigest()

def score_text(text: str) -> Tuple[int, List[Dict[str,str]], Optional[str]]:
    t = (text or "").lower()
    score = 0
    hits: List[Dict[str,str]] = []
    per_cls: Dict[str,int] = {}

    for cls, terms in OWASP_RULES.items():
        for term in terms:
            if term in t:
                score += 2
                hits.append({"class": cls, "term": term})
                per_cls[cls] = per_cls.get(cls, 0) + 2

    for m in RGX_CVE.findall(t):
        score += 3
        hits.append({"class": "A06", "term": m})
        per_cls["A06"] = per_cls.get("A06", 0) + 3

    if RGX_TLS10.search(t):
        score += 1; hits.append({"class": "A02", "term": "TLS 1.0"}); per_cls["A02"] = per_cls.get("A02", 0) + 1
    if RGX_WEAK_HASH.search(t):
        score += 1; hits.append({"class": "A02", "term": "weak hash"}); per_cls["A02"] = per_cls.get("A02", 0) + 1

    for kw in GENERIC_SECURITY:
        if kw in t: score += 1

    uniq, seen = [], set()
    for h in hits:
        k = (h["class"], h["term"])
        if k not in seen:
            seen.add(k); uniq.append(h)

    top_class = max(per_cls.items(), key=lambda x: x[1])[0] if per_cls else None
    return score, uniq, top_class

def clean_and_enrich(doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    doc["content"] = normalize_text(doc.get("content", ""))
    if not doc["content"]: return None

    score, hits, top_class = score_text(doc["content"])
    doc["priority_score"] = int(score)
    if hits: doc["owasp_hits"] = hits
    if top_class: doc["owasp_top"] = top_class

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=RECENT_DAYS)
    dt = doc.get("created_at") or now
    if isinstance(dt, datetime):
        if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = now
    doc["created_at"] = dt
    if dt < cutoff:
        return None

    doc["content_hash"] = content_hash(doc.get("source",""), doc.get("url",""), doc["content"])
    return doc

# ====== 配額：依 bucket 分開統計 ======
def today_class_counts(bucket: str) -> Dict[str,int]:
    start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    pipeline = [
        {"$match": {
            "created_at": {"$gte": start},
            "source": {"$nin": ["nvd/cve"]},
            "owasp_top": {"$exists": True},
            "bucket": bucket
        }},
        {"$group": {"_id": "$owasp_top", "n": {"$sum": 1}}}
    ]
    return {d["_id"]: d["n"] for d in col.aggregate(pipeline)}

_TODAY_CLS_COUNTS: Dict[str,int] = {}

def upsert_doc(doc: Dict[str, Any], require_min_score: bool = True, enforce_quota: bool = True) -> bool:
    """
    NVD/RSS: 不檢查門檻與配額；其餘來源：依 bucket（hot/train）各自套配額與門檻
    """
    doc = clean_and_enrich(doc)
    if not doc: return False

    src = doc.get("source","")
    is_high_quality = src.startswith("nvd/") or src.startswith("rss/")

    if not is_high_quality:
        doc["bucket"] = _BUCKET  # 標記 hot/train

        # 訓練友善：必須有類別才收
        if REQUIRE_TOP_CLASS and not doc.get("owasp_top"):
            return False

        if require_min_score:
            topc = doc.get("owasp_top")
            min_need = MIN_SCORE_BY_CLASS.get(topc, 0)
            if doc.get("priority_score", 0) < max(min_need, MIN_SCORE_TO_INSERT):
                return False

        if enforce_quota:
            topc = doc.get("owasp_top")
            if topc and CLASS_DAILY_TARGET.get(topc, 0) > 0:
                global _TODAY_CLS_COUNTS
                if not _TODAY_CLS_COUNTS:
                    _TODAY_CLS_COUNTS = today_class_counts(_BUCKET)
                used = _TODAY_CLS_COUNTS.get(topc, 0)
                if used >= CLASS_DAILY_TARGET[topc]:
                    if STRICT_QUOTA:
                        return False  # 嚴格配額：直接不收
                    else:
                        doc["queued"] = True  # 舊行為：只打標，不擋
                else:
                    _TODAY_CLS_COUNTS[topc] = used + 1

    flt = {
        "source": doc["source"],
        "type": doc["type"],
        "url": doc["url"],
        "content_hash": doc["content_hash"],
    }
    res = col.update_one(flt, {"$setOnInsert": {**doc}}, upsert=True)
    return (res.upserted_id is not None)

# ============== HN API 備援 ==============
def hn_algolia_fallback(page:int, cutoff_dt:datetime, min_points:int) -> int:
    """HN HTML 被擋時，用 Algolia API 補抓該頁（只抓貼文，不抓留言）。"""
    try:
        cutoff_ts = int(cutoff_dt.timestamp())
        params = {
            "tags": "story",
            "page": page - 1,  # Algolia 從 0 起算
            "numericFilters": f"points>={min_points},created_at_i>={cutoff_ts}"
        }
        r = SESSION.get("https://hn.algolia.com/api/v1/search_by_date", params=params, timeout=10)
        r.raise_for_status()
        data = r.json()
        hits = data.get("hits", [])
        wrote = 0
        for h in hits:
            title = h.get("title") or h.get("story_title") or ""
            url = h.get("url") or h.get("story_url") or f"https://news.ycombinator.com/item?id={h.get('objectID')}"
            created = datetime.fromtimestamp(int(h.get("created_at_i", 0)), tz=timezone.utc)
            points = int(h.get("points") or 0)
            if INCLUDE_POSTS:
                if upsert_doc({
                    "type": "post", "source": "hackernews",
                    "content": title, "url": url,
                    "hn_discussion": f"https://news.ycombinator.com/item?id={h.get('objectID')}",
                    "created_at": created, "metrics": {"points": points, "via": "algolia"}
                }):
                    wrote += 1
        return wrote
    except Exception:
        return 0

# ============== 來源 ==============
def crawl_hackernews() -> int:
    print("🚀 HN …")
    count = 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=RECENT_DAYS)
    for page in range(1, HN_PAGES + 1):
        try:
            url = f"https://news.ycombinator.com/news?p={page}"
            r = SESSION.get(url, timeout=10); r.raise_for_status()
            soup = BeautifulSoup(r.text, "html.parser")
            items = soup.select("tr.athing")
            for it in items:
                title_tag = it.select_one(".titleline a")
                if not title_tag: continue
                title = title_tag.get_text(strip=True)
                link = title_tag["href"]
                item_id = it.get("id")
                hn_disc_url = f"https://news.ycombinator.com/item?id={item_id}" if item_id else None

                subtext = it.find_next_sibling("tr").select_one(".subtext")
                points = 0; created_at = datetime.now(timezone.utc)
                if subtext:
                    sc = subtext.select_one(".score")
                    if sc and sc.text:
                        m = re.search(r"(\d+)", sc.text)
                        if m: points = int(m.group(1))
                    age = subtext.select_one(".age a")
                    if age and age.get("title"):
                        try:
                            created_at = datetime.fromisoformat(age["title"].replace("Z","+00:00"))
                        except Exception:
                            pass

                if created_at < cutoff or points < HN_MIN_POINTS:
                    continue

                if INCLUDE_POSTS:
                    if upsert_doc({
                        "type": "post", "source": "hackernews",
                        "content": title, "url": link,
                        "hn_discussion": hn_disc_url,
                        "created_at": created_at,
                        "metrics": {"points": points}
                    }):
                        count += 1

                # HN 留言（按 bucket 分流）
                if hn_disc_url:
                    try:
                        r2 = SESSION.get(hn_disc_url, timeout=10)
                        soup2 = BeautifulSoup(r2.text, "html.parser")
                        raw_comments = [c.get_text(" ", strip=True) for c in soup2.select(".commtext")]
                        if _BUCKET == "hot":
                            kept = 0
                            for i, txt in enumerate(raw_comments):
                                if kept >= HOT_COMMENT_TOP_N: break
                                if len(txt) < HOT_COMMENT_MIN_LEN: continue
                                if upsert_doc({
                                    "type": "comment", "source": "hackernews",
                                    "content": txt, "url": hn_disc_url, "parent_id": link,
                                    "created_at": created_at,
                                    "metrics": {"post_points": points, "rank": i+1, "bucket": "hot"}
                                }, require_min_score=True, enforce_quota=True):
                                    kept += 1; count += 1
                        else:  # train（偏好命中取樣）
                            kept = 0
                            for i, txt in enumerate(raw_comments):
                                if kept >= TRAIN_COMMENT_MAX_PER_THREAD: break
                                # 偏好命中：若沒命中類別，按機率保留
                                had_hit = score_text(txt)[2] is not None
                                if not had_hit and TRAIN_BIAS_KEEP_IF_HIT:
                                    if random.random() > TRAIN_BIAS_PROB_NO_HIT:
                                        continue
                                # 再套一般的隨機取樣
                                if TRAIN_COMMENT_SAMPLE_PROB < 1.0 and random.random() > TRAIN_COMMENT_SAMPLE_PROB:
                                    continue
                                if upsert_doc({
                                    "type": "comment", "source": "hackernews",
                                    "content": txt, "url": hn_disc_url, "parent_id": link,
                                    "created_at": created_at,
                                    "metrics": {"post_points": points, "rank": i+1, "bucket": "train"}
                                }, require_min_score=TRAIN_REQUIRE_MIN_SCORE, enforce_quota=True):
                                    kept += 1; count += 1
                    except Exception:
                        pass
            time.sleep(0.6 + random.random()*0.4)
        except Exception as e:
            status = getattr(getattr(e, "response", None), "status_code", None)
            if status in (403, 429):
                added = hn_algolia_fallback(page, cutoff, HN_MIN_POINTS)
                print(f"ℹ️ HN page {page} HTML blocked ({status}), fallback via API: +{added}")
            else:
                print(f"❌ HN page {page} error: {e}")
    print(f"📦 HN new inserts: {count}")
    return count

def crawl_reddit() -> int:
    print("🚀 Reddit …")
    count = 0
    if not (REDDIT_CLIENT_ID and REDDIT_CLIENT_SECRET):
        print("⚠️ Missing Reddit creds; skip Reddit.")
        return 0
    try:
        import praw
        reddit = praw.Reddit(
            client_id=REDDIT_CLIENT_ID, client_secret=REDDIT_CLIENT_SECRET,
            user_agent=REDDIT_USER_AGENT, check_for_async=False
        )
        cutoff = datetime.now(timezone.utc) - timedelta(days=RECENT_DAYS)
        for sub in REDDIT_SUBS:
            streams = [
                reddit.subreddit(sub).hot(limit=REDDIT_LIMIT_PER_SUB),
                reddit.subreddit(sub).new(limit=REDDIT_LIMIT_PER_SUB),
                reddit.subreddit(sub).top(time_filter="week", limit=max(20, REDDIT_LIMIT_PER_SUB//2)),
            ]
            for stream in streams:
                for s in stream:
                    created = datetime.fromtimestamp(s.created_utc, tz=timezone.utc)
                    if created < cutoff: continue
                    upvotes = int(getattr(s, "score", 0))
                    ncom = int(getattr(s, "num_comments", 0))
                    if (upvotes < REDDIT_MIN_UPVOTES) and (ncom < REDDIT_MIN_COMMENTS):
                        continue
                    permalink = f"https://www.reddit.com{s.permalink}"
                    if INCLUDE_POSTS:
                        if upsert_doc({
                            "type": "post", "source": f"reddit/{sub}",
                            "content": s.title or "",
                            "url": permalink,
                            "created_at": created,
                            "metrics": {"upvotes": upvotes, "comments": ncom}
                        }):
                            count += 1
                    try:
                        s.comments.replace_more(limit=0)
                        comments = list(s.comments)
                        if _BUCKET == "hot":
                            kept = 0
                            comments.sort(key=lambda c: int(getattr(c, "score", 0) or 0), reverse=True)
                            for i, c in enumerate(comments):
                                if kept >= HOT_COMMENT_TOP_N: break
                                body = getattr(c, "body", "") or ""
                                cscore = int(getattr(c, "score", 0) or 0)
                                if len(body) < HOT_COMMENT_MIN_LEN: continue
                                if cscore < HOT_REDDIT_COMMENT_MIN_UPVOTES: continue
                                if upsert_doc({
                                    "type": "comment", "source": f"reddit/{sub}",
                                    "content": body, "url": permalink, "parent_id": s.id,
                                    "created_at": datetime.fromtimestamp(getattr(c, "created_utc", s.created_utc), tz=timezone.utc),
                                    "metrics": {"comment_upvotes": cscore, "rank": i+1, "bucket": "hot"}
                                }, require_min_score=True, enforce_quota=True):
                                    kept += 1; count += 1
                        else:  # train（偏好命中取樣）
                            kept = 0
                            random.shuffle(comments)
                            for i, c in enumerate(comments):
                                if kept >= TRAIN_COMMENT_MAX_PER_THREAD: break
                                body = getattr(c, "body", "") or ""
                                if not body.strip(): continue
                                had_hit = score_text(body)[2] is not None
                                if not had_hit and TRAIN_BIAS_KEEP_IF_HIT:
                                    if random.random() > TRAIN_BIAS_PROB_NO_HIT:
                                        continue
                                if TRAIN_COMMENT_SAMPLE_PROB < 1.0 and random.random() > TRAIN_COMMENT_SAMPLE_PROB:
                                    continue
                                if upsert_doc({
                                    "type": "comment", "source": f"reddit/{sub}",
                                    "content": body, "url": permalink, "parent_id": s.id,
                                    "created_at": datetime.fromtimestamp(getattr(c, "created_utc", s.created_utc), tz=timezone.utc),
                                    "metrics": {"comment_upvotes": int(getattr(c, "score", 0) or 0), "rank": i+1, "bucket": "train"}
                                }, require_min_score=TRAIN_REQUIRE_MIN_SCORE, enforce_quota=True):
                                    kept += 1; count += 1
                    except Exception:
                        pass
            time.sleep(0.4 + random.random()*0.4)
    except Exception as e:
        print(f"❌ Reddit error: {e}")
    print(f"📦 Reddit new inserts: {count}")
    return count

def crawl_stackexchange() -> int:
    print("🚀 StackExchange Security …")
    count = 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=RECENT_DAYS)
    for page in range(1, SE_PAGES + 1):
        try:
            url = f"https://security.stackexchange.com/questions?tab=Newest&page={page}"
            r = SESSION.get(url, timeout=10); r.raise_for_status()
            soup = BeautifulSoup(r.text, "html.parser")
            for q in soup.select("div.s-post-summary"):
                a = q.select_one("h3 a")
                if not a: continue
                title = a.get_text(strip=True)
                link = "https://security.stackexchange.com" + a["href"]
                vtag = q.select_one(".s-post-summary--stats-item-number")
                votes = int(vtag.text.strip()) if vtag and vtag.text.strip().isdigit() else 0
                if votes < SE_MIN_VOTES:
                    continue
                created = datetime.now(timezone.utc)
                if INCLUDE_POSTS:
                    if upsert_doc({
                        "type": "post", "source": "stackexchange/security",
                        "content": title, "url": link,
                        "created_at": created, "metrics": {"votes": votes}
                    }):
                        count += 1
                try:
                    r2 = SESSION.get(link, timeout=10)
                    soup2 = BeautifulSoup(r2.text, "html.parser")
                    nodes = soup2.select("div.comment")
                    cands = []
                    for n in nodes:
                        txt = n.select_one("span.comment-copy")
                        if not txt: continue
                        text = txt.get_text(" ", strip=True)
                        scnode = n.select_one("span.comment-score")
                        cscore = 0
                        if scnode and scnode.get("title"):
                            m = re.search(r"(\d+)", scnode.get("title"))
                            if m: cscore = int(m.group(1))
                        cands.append((text, cscore))
                    if _BUCKET == "hot":
                        cands.sort(key=lambda x: x[1], reverse=True)
                        kept = 0
                        for i, (text, cscore) in enumerate(cands):
                            if kept >= HOT_COMMENT_TOP_N: break
                            if len(text) < HOT_COMMENT_MIN_LEN: continue
                            if upsert_doc({
                                "type": "comment", "source": "stackexchange/security",
                                "content": text, "url": link, "parent_id": link,
                                "created_at": created,
                                "metrics": {"comment_votes": cscore, "rank": i+1, "bucket": "hot"}
                            }, require_min_score=True, enforce_quota=True):
                                kept += 1; count += 1
                    else:  # train（偏好命中取樣）
                        kept = 0
                        random.shuffle(cands)
                        for i, (text, cscore) in enumerate(cands):
                            if kept >= TRAIN_COMMENT_MAX_PER_THREAD: break
                            had_hit = score_text(text)[2] is not None
                            if not had_hit and TRAIN_BIAS_KEEP_IF_HIT:
                                if random.random() > TRAIN_BIAS_PROB_NO_HIT:
                                    continue
                            if TRAIN_COMMENT_SAMPLE_PROB < 1.0 and random.random() > TRAIN_COMMENT_SAMPLE_PROB:
                                continue
                            if upsert_doc({
                                "type": "comment", "source": "stackexchange/security",
                                "content": text, "url": link, "parent_id": link,
                                "created_at": created,
                                "metrics": {"comment_votes": cscore, "rank": i+1, "bucket": "train"}
                            }, require_min_score=TRAIN_REQUIRE_MIN_SCORE, enforce_quota=True):
                                kept += 1; count += 1
                except Exception:
                    pass
            time.sleep(1.4 + random.random()*0.8)  # 放慢避免 429
        except Exception as e:
            print(f"❌ SE page {page} error: {e}")
    print(f"📦 SE new inserts: {count}")
    return count

def crawl_nvd() -> int:
    print(f"🚀 NVD (last {NVD_DAYS} days) …")
    count = 0
    end = datetime.now(timezone.utc).replace(microsecond=0)
    start = end - timedelta(days=NVD_DAYS)
    base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "pubStartDate": start.isoformat().replace("+00:00","") + "Z",
        "pubEndDate": end.isoformat().replace("+00:00","") + "Z",
        "startIndex": 0,
        "resultsPerPage": 200,
    }
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    try:
        while True:
            r = SESSION.get(base, params=params, headers=headers, timeout=15)
            r.raise_for_status()
            data = r.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns: break
            for v in vulns:
                cve = v.get("cve", {})
                cve_id = cve.get("id")
                desc = ""
                for d in cve.get("descriptions", []):
                    if d.get("lang") == "en":
                        desc = d.get("value",""); break
                url = f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else "https://nvd.nist.gov/"
                title = f"{cve_id}: {desc[:180]}"
                if upsert_doc({
                    "type": "advisory", "source": "nvd/cve",
                    "content": title, "url": url,
                    "created_at": end
                }, require_min_score=False, enforce_quota=False):
                    count += 1
            total = data.get("totalResults", 0)
            params["startIndex"] += params["resultsPerPage"]
            if params["startIndex"] >= total: break
            time.sleep(0.6 + random.random()*0.4)
    except Exception as e:
        print(f"❌ NVD error: {e}")
    print(f"📦 NVD new inserts: {count}")
    return count

def crawl_feeds() -> int:
    if not FEED_URLS:
        print("ℹ️ No FEED_URLS; skip RSS/Atom."); return 0
    print("🚀 RSS/Atom …")
    count = 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=RECENT_DAYS)
    for url in FEED_URLS:
        url = url.strip()
        if not url: continue
        try:
            feed = feedparser.parse(url)
            for e in feed.entries[:200]:
                title = e.get("title", "")
                link = e.get("link", url)
                summary = BeautifulSoup(e.get("summary", "") or e.get("description",""), "html.parser").get_text(" ", strip=True)
                content = normalize_text(f"{title} — {summary}") if summary else normalize_text(title)
                dt = datetime.now(timezone.utc)
                for key in ["published_parsed", "updated_parsed"]:
                    tm = e.get(key)
                    if tm:
                        dt = datetime(*tm[:6], tzinfo=timezone.utc)
                        break
                if dt < cutoff:
                    continue
                if upsert_doc({
                    "type": "advisory",
                    "source": "rss/" + re.sub(r"^\w+://", "", url).split("/")[0],
                    "content": content, "url": link,
                    "created_at": dt
                }, require_min_score=False, enforce_quota=False):
                    count += 1
            time.sleep(0.3 + random.random()*0.3)
        except Exception as ex:
            print(f"❌ RSS error {url}: {ex}")
    print(f"📦 RSS/Atom new inserts: {count}")
    return count

# ============== 主流程 ==============
def crawl_all_sources() -> Dict[str, Any]:
    total = 0
    total += crawl_hackernews()
    total += crawl_reddit()
    total += crawl_stackexchange()
    total += crawl_nvd()
    total += crawl_feeds()
    print(f"✅ All done. New inserts: {total}")

    result: Dict[str, Any] = {"total": total, "by_bucket_class": []}

    if PRINT_SUMMARY:
        start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        try:
            agg = list(col.aggregate([
                {"$match": {"created_at": {"$gte": start}}},
                {"$group": {"_id": {"bucket": "$bucket", "cls": "$owasp_top"}, "n": {"$sum": 1}}},
                {"$sort": {"_id.bucket": 1, "n": -1}}
            ]))
            print("📊 Today summary (by bucket, class):")
            for a in agg:
                bucket = a["_id"].get("bucket", "-")
                cls = a["_id"].get("cls", "-")
                n = a["n"]
                print(f"  {bucket:>5}  {cls:>12}: {n}")
                result["by_bucket_class"].append({
                    "bucket": bucket,
                    "class": cls,
                    "count": n
                })
        except Exception as e:
            print(f"⚠️ Summary error: {e}")

    return result
