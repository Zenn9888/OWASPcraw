# -*- coding: utf-8 -*-
"""
crawler_train.py
訓練用評論專用啟動器（與 crawler_core.py 搭配）
- 只抓評論（預設 INCLUDE_POSTS=0）
- 一般來源必須命中 OWASP 類別才收（REQUIRE_TOP_CLASS=1）
- 偏好命中取樣（TRAIN_BIAS_KEEP_IF_HIT=1；未命中保留機率可調）
- Windows/py312 直接執行即可
"""

from pathlib import Path
import os

# 1) 指定要載入的環境檔（優先 .env.train，沒有就退回 .env）
_here = Path(__file__).parent
_env_train = _here / ".env.train"
os.environ["DOTENV_FILE"] = str(_env_train if _env_train.exists() else (_here / ".env"))

# 2) 設定本輪為「訓練評論」模式，並分流到獨立 DB / collection
os.environ["MODE_COMMENTS"] = "train"
os.environ.setdefault("DB_NAME", "webcommentIT_train")
os.environ.setdefault("COLLECTION", "comment_train")

# 3) 訓練友善預設（可在 .env.train 覆寫）
#    - 僅收評論（不收貼文）
#    - 必須有 OWASP 類別才收
#    - 最低分數（避免太模糊）
os.environ.setdefault("INCLUDE_POSTS", "0")
os.environ.setdefault("REQUIRE_TOP_CLASS", "1")
os.environ.setdefault("MIN_SCORE_TO_INSERT", "2")

# 4) 偏好命中取樣（命中類別一定收；未命中有機率收以保多樣）
os.environ.setdefault("TRAIN_BIAS_KEEP_IF_HIT", "1")
os.environ.setdefault("TRAIN_BIAS_PROB_NO_HIT", "0.3")

# 5) 抓取廣度與熱度門檻（訓練端較寬，但仍控量）
os.environ.setdefault("RECENT_DAYS", "14")
os.environ.setdefault("HN_MIN_POINTS", "30")
os.environ.setdefault("HN_PAGES", "6")
os.environ.setdefault("REDDIT_MIN_UPVOTES", "15")
os.environ.setdefault("REDDIT_MIN_COMMENTS", "3")
os.environ.setdefault("SE_MIN_VOTES", "1")
os.environ.setdefault("SE_PAGES", "10")

# 6) 訓練評論取樣參數
os.environ.setdefault("TRAIN_COMMENT_MAX_PER_THREAD", "80")
os.environ.setdefault("TRAIN_COMMENT_SAMPLE_PROB", "0.8")
os.environ.setdefault("TRAIN_REQUIRE_MIN_SCORE", "1")

# 7) 跑完印出摘要
os.environ.setdefault("PRINT_SUMMARY", "1")

# 8) 匯入核心並執行（注意：以上環境變數一定要在 import 前設定）
import crawler_core as core

if __name__ == "__main__":
    core.crawl_all_sources()
