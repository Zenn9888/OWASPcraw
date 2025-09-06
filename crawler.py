# -*- coding: utf-8 -*-
"""
crawler.py
抓取近期且有熱度的資安內容，並在收集端做 OWASP(A01~A10) 打分與每日配額，讓弱訓練穩定均衡。

來源：
- Hacker News（HTML，失敗自動走 Algolia API 備援；含討論頁前 10 留言）
- Reddit（多安全子版 hot/new/top-week；需 .env Reddit 憑證）
- StackExchange Security（標題 + 前幾則留言；尊重 429 Retry-After）
- NVD CVE API v2（最近 N 天）
- RSS/Atom 公告源（.env 設 FEED_URLS）

特點：
- 只收近 RECENT_DAYS 天的內容（預設 7）
- 熱度門檻：HN_MIN_POINTS / REDDIT_MIN_UPVOTES / REDDIT_MIN_COMMENTS / SE_MIN_VOTES
- Upsert 去重：unique(source,type,url,content_hash)
- 打分：priority_score + owasp_hits + owasp_top
- 一般來源（HN/Reddit/SE）→ 每日每類配額 CLASS_DAILY_TARGET + 每類最小分數 MIN_SCORE_BY_CLASS
- NVD/RSS 不受配額/分數限制，但同樣做 owasp 標記
"""

import os, re, time, json, hashlib, random
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List, Tuple
from pathlib import Path

from dotenv import load_dotenv
load_dotenv(dotenv_path=Path(__file__).parent / ".env", override=True)

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
    "A06": int(os.getenv("MS_A06", "2")),
    "A07": int(os.getenv("MS_A07", "1")),
    "A08": int(os.getenv("MS_A08", "1")),
    "A09": int(os.getenv("MS_A09", "1")),
    "A10": int(os.getenv("MS_A10", "1")),
}

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

# ============== OWASP 打分 ==============
OWASP_RULES = {
    "A01": ["broken access", "access control", "idor", "unauthorized", "privilege escalation", "bypass auth"],
    "A02": ["weak encryption", "plaintext password", "md5", "sha1", "tls 1.0", "rc4", "no https", "self-signed"],
    "A03": ["sql injection", "sqli", "injection", "xss", "ssti", "xxe", "lfi", "rfi", "rce", "command injection", "unescaped", "unsanitized"],
    "A04": ["insecure design", "no rate limit", "weak default"],
    "A05": ["misconfiguration", "default creds", "directory listing", "open port", "debug enabled", "csp missing", "cors *", "x-frame-options"],
    "A06": ["outdated", "unpatched", "eol version", "cve-", "known vulnerability", "vulnerable dependency", "log4j", "struts2", "spring4shell"],
    "A07": ["broken authentication", "weak password", "credential stuffing", "bruteforce", "session fixation", "no mfa", "jwt none"],
    "A08": ["insecure deserialization", "supply chain", "dependency confusion", "tampering", "unsigned package"],
    "A09": ["no logging", "no monitoring", "insufficient logging", "no audit"],
    "A10": ["ssrf", "metadata service", "169.254.169.254", "localhost request"],
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

def today_class_counts() -> Dict[str,int]:
    start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    pipeline = [
        {"$match": {
            "created_at": {"$gte": start},
            "source": {"$nin": ["nvd/cve"]},
            "owasp_top": {"$exists": True}
        }},
        {"$group": {"_id": "$owasp_top", "n": {"$sum": 1}}}
    ]
    return {d["_id"]: d["n"] for d in col.aggregate(pipeline)}

_TODAY_CLS_COUNTS: Dict[str,int] = {}

def upsert_doc(doc: Dict[str, Any], require_min_score: bool = True, enforce_quota: bool = True) -> bool:
    doc = clean_and_enrich(doc)
    if not doc: return False

    src = doc.get("source","")
    is_high_quality = src.startswith("nvd/") or src.startswith("rss/")

    if require_min_score and not is_high_quality:
        topc = doc.get("owasp_top")
        min_need = MIN_SCORE_BY_CLASS.get(topc, 0)
        if doc.get("priority_score", 0) < max(min_need, MIN_SCORE_TO_INSERT):
            return False

    if enforce_quota and not is_high_quality:
        topc = doc.get("owasp_top")
        if topc and CLASS_DAILY_TARGET.get(topc, 0) > 0:
            global _TODAY_CLS_COUNTS
            if not _TODAY_CLS_COUNTS:
                _TODAY_CLS_COUNTS = today_class_counts()
            used = _TODAY_CLS_COUNTS.get(topc, 0)
            if used >= CLASS_DAILY_TARGET[topc]:
                doc["queued"] = True
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

                if upsert_doc({
                    "type": "post", "source": "hackernews",
                    "content": title, "url": link,
                    "hn_discussion": hn_disc_url,
                    "created_at": created_at,
                    "metrics": {"points": points}
                }):
                    count += 1

                if hn_disc_url:
                    try:
                        r2 = SESSION.get(hn_disc_url, timeout=10)
                        soup2 = BeautifulSoup(r2.text, "html.parser")
                        for c in soup2.select(".commtext")[:10]:
                            txt = c.get_text(" ", strip=True)
                            if upsert_doc({
                                "type": "comment", "source": "hackernews",
                                "content": txt,
                                "url": hn_disc_url, "parent_id": link,
                                "created_at": created_at
                            }):
                                count += 1
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
                        for c in s.comments[:10]:
                            ctime = datetime.fromtimestamp(getattr(c, "created_utc", s.created_utc), tz=timezone.utc)
                            if ctime < cutoff: continue
                            if upsert_doc({
                                "type": "comment", "source": f"reddit/{sub}",
                                "content": getattr(c, "body", "") or "",
                                "url": permalink, "parent_id": s.id,
                                "created_at": ctime
                            }):
                                count += 1
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
                if upsert_doc({
                    "type": "post", "source": "stackexchange/security",
                    "content": title, "url": link,
                    "created_at": created, "metrics": {"votes": votes}
                }):
                    count += 1
                try:
                    r2 = SESSION.get(link, timeout=10)
                    soup2 = BeautifulSoup(r2.text, "html.parser")
                    for c in soup2.select("div.comment-copy")[:8]:
                        if upsert_doc({
                            "type": "comment", "source": "stackexchange/security",
                            "content": c.get_text(" ", strip=True),
                            "url": link, "parent_id": link,
                            "created_at": created
                        }):
                            count += 1
                except Exception:
                    pass
            # 放慢，降低 429
            time.sleep(1.4 + random.random()*0.8)
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
def crawl_all_sources() -> int:
    total = 0
    total += crawl_hackernews()
    total += crawl_reddit()
    total += crawl_stackexchange()
    total += crawl_nvd()
    total += crawl_feeds()
    print(f"✅ All done. New inserts: {total}")
    return total

if __name__ == "__main__":
    crawl_all_sources()
