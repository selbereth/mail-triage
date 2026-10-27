# mail-triage

A small web app. Every 30 minutes it reads new Gmail (read-only), has Claude sort it, and keeps a short record of each email: sender, subject, a one-line summary, why it matters and any deadline. Email bodies are never stored: click a subject and the app fetches that one message from Gmail (read-only) on the spot, shows it as plain text, and offers a sandboxed "Formatted" view (no scripts, remote images blocked unless you choose to load them). Log in to see the "needs your input" list, tick items done, and open the original in Gmail.

## Setup
1. Gmail: turn on 2-Step Verification, create an App password (see below), make sure IMAP is enabled.
2. `cp .env.example .env`, fill it in (a long `APP_PASSWORD`; the session `SECRET_KEY` is generated on first start and saved in the data volume). Edit `rules.md` with your own priorities.
3. `docker compose up -d --build`, then open `http://<server>:8000`.
4. Open **Settings** and add your Gmail address(es) with their app passwords. Any number of accounts can be listed; they share the same Claude credentials and are shown together on the home page (with a per-account filter). Passwords are tested on save and stored encrypted in the data volume, with a key derived from `SECRET_KEY` (keep it, or re-enter the passwords). If `GMAIL_ADDRESS` / `GMAIL_APP_PASSWORD` are set when the database has no accounts, they become the first entry.

## Creating a Gmail app password
Each Gmail account you add needs its own app password, a 16-character code that lets this app read that mailbox without your real password.
1. Turn on 2-Step Verification for the account at <https://myaccount.google.com/security> (app passwords are unavailable without it).
2. Open <https://myaccount.google.com/apppasswords> (signed in as that account).
3. Enter a name such as `mail-triage` and click **Create**.
4. Copy the 16-character code Google shows. It is displayed only once; spaces in it are ignored, so paste it as is.
5. In the app, open **Settings**, enter the Gmail address and the code, and click **Test and add**.
6. Make sure IMAP is on: Gmail > Settings (gear) > See all settings > Forwarding and POP/IMAP > Enable IMAP.

To revoke access later, delete the app password on the same page. Google Workspace accounts may need an admin to allow app passwords.

## Teaching it what is junk
Every email has a "Wrong category?" control (on the list and on the email page). Pick the right category, including **Junk**, and the app moves it and remembers the sender. The latest 60 corrections (`MAX_CORRECTIONS`) go into every future triage prompt, so mail from that sender, or clearly like it, is sorted the same way. "What I have learned" at the bottom of the home page lists them, each with a Forget button. Only sender, subject and category are kept, never the body.

## Using a Claude subscription instead of an API key
Set `BACKEND=claude-cli`. Triage then runs through the Claude Code CLI inside the container and counts against your Claude plan limits, not API credit.
1. On a machine where you are logged in to Claude Code, run `claude setup-token` and copy the token.
2. Set `CLAUDE_CODE_OAUTH_TOKEN` to it. `ANTHROPIC_API_KEY` is not needed.
3. `MODEL` defaults to `claude-haiku-5-5` in this mode.

Check Anthropic's current usage policy before relying on this for automation. Plan limits are shared with your normal Claude use.

## Running as a specific user
The container runs as `PUID:PGID` (default `1000:100`) and chowns its data volume to match. Change them in `.env` or the Portainer environment. Setting `user:` in compose instead also works.

## Security notes
- Do not put it on the open internet over plain http. Use an https reverse proxy (set `COOKIE_SECURE=1`) or keep it on your LAN/VPN.
- The first 1500 characters of each new email are sent to the Anthropic API for triage.
- Data lives in the `triage-data` volume (SQLite). Delete the volume to wipe it.
