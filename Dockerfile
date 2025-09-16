# syntax=docker/dockerfile:1
FROM python:3.11-slim

WORKDIR /app

# Install system deps (if any SSL/cert or lxml needs, extend here)
RUN apt-get update && apt-get install -y --no-install-recommends \    ca-certificates \    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy code
COPY crawler_unified.py ./
# Optional: copy envs at build time (or mount at runtime)
# COPY .env .env.hot .env.train ./

# Default to base mode; override with: --mode hot/train
ENV PYTHONUNBUFFERED=1

CMD ["python", "crawler_unified.py"]
