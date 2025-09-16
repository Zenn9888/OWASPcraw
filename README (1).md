# Unified Security Crawler

Single-file crawler with three modes:
- `default` (posts + comments)
- `hot` (top comments only, higher thresholds)
- `train` (comment-focused with class-aware sampling)

## Quickstart

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cp .env .env.local || true
python crawler_unified.py            # default
python crawler_unified.py --mode hot
python crawler_unified.py --mode train
```

### Environment
Edit `.env`, and override with `.env.hot` / `.env.train` for each mode.

### Docker
```bash
docker compose up --build
# or run a one-off hot job:
docker compose run --rm crawler python crawler_unified.py --mode hot
```

### Scheduling
- Systemd timer or cron, or use an orchestrator (GitHub Actions, k8s CronJob).
- Keep `RECENT_DAYS` aligned with your cadence.
