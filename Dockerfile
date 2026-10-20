FROM python:3.12-slim
# Node + Claude Code CLI, only used when BACKEND=claude-cli
RUN apt-get update && apt-get install -y --no-install-recommends nodejs npm \
    && npm install -g @anthropic-ai/claude-code && npm cache clean --force \
    && rm -rf /var/lib/apt/lists/*
ENV HOME=/data
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY digest.py app.py rules.md entrypoint.sh ./
RUN mkdir /data && chmod 777 /data
ENV PUID=1000 PGID=100
EXPOSE 8000
# one worker: the Gmail poller runs as a thread inside it
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["gunicorn", "-w", "1", "--threads", "4", "-b", "0.0.0.0:8000", "app:app"]
