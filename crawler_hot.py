# -*- coding: utf-8 -*-
from pathlib import Path
import os

# 指定熱門用的 .env
os.environ["DOTENV_FILE"] = str(Path(__file__).parent / ".env.hot")

# 強制這次跑在熱門評論模式 + 指定 DB/collection（可被 .env.hot 覆蓋）
os.environ["MODE_COMMENTS"] = "hot"
os.environ.setdefault("DB_NAME", "webcommentIT_hot")
os.environ.setdefault("COLLECTION", "comment_hot")

# 熱門門檻（若 .env.hot 已設定可省略）
os.environ.setdefault("HN_MIN_POINTS", "50")
os.environ.setdefault("REDDIT_MIN_UPVOTES", "30")
os.environ.setdefault("REDDIT_MIN_COMMENTS", "5")

import crawler_core as core
core.crawl_all_sources()
