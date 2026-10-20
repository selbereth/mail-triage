# mail-triage

A small web app. Every 30 minutes it reads new Gmail (read-only), has Claude sort it, and keeps a short record of each email: sender, subject, a one-line summary, why it matters and any deadline. Email bodies are never stored. Log in to see the "needs your input" list, tick items done, and open the original in Gmail.

## Setup
1. Gmail: turn on 2-Step Verification, create an App password, make sure IMAP is enabled.
2. `cp .env.example .env`, fill it in (`SECRET_KEY`, a long `APP_PASSWORD`). Edit `rules.md` with your own priorities.
3. `docker compose up -d --build`, then open `http://<server>:8000`.

## Security notes
- Do not put it on the open internet over plain http. Use an https reverse proxy (set `COOKIE_SECURE=1`) or keep it on your LAN/VPN.
- The first 1500 characters of each new email are sent to the Anthropic API for triage.
- Data lives in the `triage-data` volume (SQLite). Delete the volume to wipe it.
