"""Small login-protected web app: polls Gmail, triages new mail, keeps the important items."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timezone
from email.utils import parseaddr

from cryptography.fernet import Fernet
from flask import Flask, abort, make_response, redirect, render_template_string, request, session, url_for

import digest

DB_PATH = os.environ.get("DB_PATH", "/data/digest.db")
MAX_CORRECTIONS = int(os.environ.get("MAX_CORRECTIONS", "60"))
POLL_MINUTES = int(os.environ.get("POLL_MINUTES", "30"))
USERNAME = os.environ.get("APP_USERNAME", "admin")
PASSWORD = os.environ.get("APP_PASSWORD", "")



def load_secret_key() -> str:
    """SECRET_KEY if set, else a random key generated on first start and kept in the data volume."""
    if os.environ.get("SECRET_KEY"):
        return os.environ["SECRET_KEY"]
    path = os.path.join(os.path.dirname(DB_PATH), "secret_key")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secrets.token_hex(32))
    except FileExistsError:
        pass
    with open(path) as f:
        return f.read().strip()


app = Flask(__name__)
app.secret_key = load_secret_key()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE") == "1",  # set when served over https
    PERMANENT_SESSION_LIFETIME=60 * 60 * 24 * 14,
)

EMAIL_RE = re.compile(r"([\w.+-]+)@([\w-]+\.[\w.-]+)")
_poll_lock = threading.Lock()
_failures: dict[str, list[float]] = {}


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _fernet() -> Fernet:
    """App passwords are encrypted at rest with a key derived from the session secret."""
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(app.secret_key.encode()).digest()))


def encrypt(text: str) -> str:
    return _fernet().encrypt(text.encode()).decode()


def decrypt(token: str) -> str:
    return _fernet().decrypt(token.encode()).decode()


EMAILS_SQL = """
    CREATE TABLE IF NOT EXISTS emails (
        account_id INTEGER NOT NULL, gmail_id TEXT NOT NULL, sender TEXT, subject TEXT, received TEXT,
        category TEXT, summary TEXT, reason TEXT, deadline TEXT,
        status TEXT NOT NULL DEFAULT 'open', first_seen TEXT,
        PRIMARY KEY (account_id, gmail_id))"""
EMAIL_COLS = "account_id, gmail_id, sender, subject, received, category, summary, reason, deadline, status, first_seen"


def init_db() -> None:
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    with db() as c:
        c.executescript("""
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT, address TEXT NOT NULL UNIQUE, password TEXT NOT NULL,
                last_run TEXT, last_error TEXT);
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE IF NOT EXISTS feedback (
                sender_addr TEXT PRIMARY KEY, sender TEXT, subject TEXT, category TEXT, at TEXT);
        """)
        # first start after upgrading: the single account from the environment becomes the first list entry
        if os.environ.get("GMAIL_ADDRESS") and os.environ.get("GMAIL_APP_PASSWORD") \
                and not c.execute("SELECT 1 FROM accounts").fetchone():
            c.execute("INSERT INTO accounts (address, password) VALUES (?, ?)",
                      (os.environ["GMAIL_ADDRESS"].strip().lower(), encrypt(os.environ["GMAIL_APP_PASSWORD"])))
        old = [r[1] for r in c.execute("PRAGMA table_info(emails)")]
        if old and "account_id" not in old:  # single-account database from before: move rows under the first account
            c.execute("ALTER TABLE emails RENAME TO emails_old")
            c.execute(EMAILS_SQL)
            first = c.execute("SELECT MIN(id) FROM accounts").fetchone()[0] or 0
            c.execute(f"INSERT INTO emails ({EMAIL_COLS}) SELECT ?, gmail_id, sender, subject, received, category, "
                      "summary, reason, deadline, status, first_seen FROM emails_old", (first,))
            c.execute("DROP TABLE emails_old")
        else:
            c.execute(EMAILS_SQL)


def set_meta(key: str, value: str) -> None:
    with db() as c:
        c.execute("INSERT INTO meta VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))


def poll_account(a: sqlite3.Row) -> int:
    """Fetch one account's unseen mail, triage it, store the result. Returns how many need input."""
    with db() as c:
        known = {r[0] for r in c.execute("SELECT gmail_id FROM emails WHERE account_id=?", (a["id"],))}
    emails = digest.fetch_emails(a["address"], decrypt(a["password"]), digest.LOOKBACK_HOURS, known)
    new_needs = 0
    if emails:
        with db() as c:
            corrections = [
                {"sender": r["sender"], "subject": r["subject"], "category": r["category"]}
                for r in c.execute("SELECT * FROM feedback ORDER BY at DESC LIMIT ?", (MAX_CORRECTIONS,))]
        result = digest.triage(emails, corrections)
        by_id = {e["id"]: e for e in emails}
        seen = set()
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        insert = f"INSERT OR IGNORE INTO emails ({EMAIL_COLS}) VALUES (?,?,?,?,?,?,?,?,?,?,?)"
        with db() as c:
            for item in result["emails"]:
                e = by_id.get(item["id"])
                if not e or item["category"] not in digest.CATEGORIES:
                    continue
                seen.add(e["id"])
                new_needs += item["category"] == "needs_input"
                c.execute(insert, (
                    a["id"], e["gmail_id"], e["from"], e["subject"], e["date"], item["category"],
                    item["summary"], item["reason"], item["deadline"],
                    "open" if item["category"] == "needs_input" else "n/a", now))
            for e in emails:  # anything the model skipped is kept as fyi, not lost
                if e["id"] not in seen:
                    c.execute(insert, (a["id"], e["gmail_id"], e["from"], e["subject"], e["date"], "fyi",
                                       "(not classified)", "", "", "n/a", now))
    return new_needs


def poll() -> None:
    """Check every account in turn; one failing account does not stop the others. Bodies are never stored."""
    if not _poll_lock.acquire(blocking=False):
        return
    try:
        with db() as c:
            accounts = c.execute("SELECT * FROM accounts ORDER BY id").fetchall()
        new_needs = 0
        errors = []
        for a in accounts:
            now = datetime.now(timezone.utc).isoformat(timespec="seconds")
            try:
                new_needs += poll_account(a)
                err = ""
            except Exception as exc:
                err = repr(exc)
                errors.append(f"{a['address']}: {err}")
            with db() as c:
                c.execute("UPDATE accounts SET last_run=?, last_error=? WHERE id=?",
                          (now if not err else a["last_run"], err, a["id"]))
        set_meta("last_run", datetime.now(timezone.utc).isoformat(timespec="seconds"))
        set_meta("last_error", "; ".join(errors) if accounts else "No mail accounts yet. Add one in Settings.")
        if new_needs:
            try:
                digest.ping(f"{new_needs} new email(s) need your input.")
            except Exception as exc:
                set_meta("last_error", f"alert failed: {exc!r}")
    except Exception as exc:
        set_meta("last_error", repr(exc))
    finally:
        _poll_lock.release()


def poller() -> None:
    while True:
        poll()
        time.sleep(POLL_MINUTES * 60)


# ---- auth -----------------------------------------------------------------

def logged_in() -> bool:
    return session.get("user") == USERNAME


def csrf_token() -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(24)
    return session["csrf"]


def check_csrf() -> None:
    if not hmac.compare_digest(request.form.get("csrf", ""), session.get("csrf", "")):
        abort(400)


@app.before_request
def guard():
    if request.endpoint in ("login", "static", "health") or logged_in():
        return None
    return redirect(url_for("login"))


@app.after_request
def headers(resp):
    resp.headers["Cache-Control"] = "no-store"
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers.setdefault("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'")
    if resp.mimetype == "text/html" and not resp.direct_passthrough:
        # Cloudflare would otherwise rewrite every address into a /cdn-cgi/l/email-protection link
        text = resp.get_data(as_text=True)
        if request.endpoint != "view_email_html":  # our own pages: Cloudflare's detector skips "&#64;"
            text = EMAIL_RE.sub(r"\1&#64;\2", text)
        head = re.match(r"\s*<!doctype[^>]*>", text, re.I)
        cut = head.end() if head else 0
        resp.set_data(text[:cut] + "<!--email_off-->" + text[cut:] + "<!--/email_off-->")
    return resp


@app.route("/health")
def health():
    return "ok"


@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        ip = request.remote_addr or "?"
        recent = [t for t in _failures.get(ip, []) if time.time() - t < 900]
        if len(recent) >= 5:
            error = "Too many attempts. Try again in 15 minutes."
        elif PASSWORD and hmac.compare_digest(request.form.get("username", ""), USERNAME) \
                and hmac.compare_digest(request.form.get("password", ""), PASSWORD):
            session.clear()
            session.permanent = True
            session["user"] = USERNAME
            return redirect(url_for("index"))
        else:
            recent.append(time.time())
            error = "Wrong username or password."
        _failures[ip] = recent
    return render_template_string(LOGIN, error=error)


@app.route("/logout", methods=["POST"])
def logout():
    check_csrf()
    session.clear()
    return redirect(url_for("login"))


# ---- pages ----------------------------------------------------------------

@app.route("/")
def index():
    acct = request.args.get("account", type=int)

    def rows(c, where: str, limit: int) -> list:
        sql = ("SELECT e.*, a.address AS account FROM emails e LEFT JOIN accounts a ON a.id=e.account_id WHERE "
               + where + (" AND e.account_id=?" if acct else "") + " ORDER BY e.received DESC LIMIT ?")
        return c.execute(sql, ([acct] if acct else []) + [limit]).fetchall()

    with db() as c:
        needs = rows(c, "e.category='needs_input' AND e.status='open'", 1000)
        done = rows(c, "e.category='needs_input' AND e.status='done'", 20)
        other = rows(c, "e.category NOT IN ('needs_input','junk')", 100)
        junk = rows(c, "e.category='junk'", 50)
        learned = c.execute("SELECT * FROM feedback ORDER BY at DESC").fetchall()
        accounts = c.execute("SELECT id, address FROM accounts ORDER BY id").fetchall()
        meta = {r["key"]: r["value"] for r in c.execute("SELECT * FROM meta")}
    return render_template_string(
        HOME, needs=needs, done=done, other=other, junk=junk, learned=learned, meta=meta, csrf=csrf_token(),
        poll_minutes=POLL_MINUTES, accounts=accounts, acct=acct, multi=len(accounts) > 1)


def gmail_link(address: str | None, gid: str) -> str:
    return f"https://mail.google.com/mail/u/{address or 0}/#all/{gid}"


app.jinja_env.globals["gmail_link"] = gmail_link


def load_message(aid: int, gid: str):
    """The stored row plus the live message from Gmail. 404 for ids we never triaged."""
    if not re.fullmatch(r"[0-9a-f]{1,32}", gid):
        abort(404)
    with db() as c:
        row = c.execute(
            "SELECT e.*, a.address AS account, a.password AS secret FROM emails e "
            "LEFT JOIN accounts a ON a.id=e.account_id WHERE e.account_id=? AND e.gmail_id=?", (aid, gid)).fetchone()
    if row is None or row["account"] is None:
        abort(404)
    try:
        msg = digest.fetch_message(row["account"], decrypt(row["secret"]), gid)
    except Exception as exc:
        return row, None, repr(exc)
    return row, msg, "" if msg is not None else "Gmail no longer has this message (deleted or moved to trash)."


@app.route("/email/<int:aid>/<gid>")
def view_email(aid: int, gid: str):
    row, msg, error = load_message(aid, gid)
    detail = {}
    if msg is not None:
        detail = {
            "from": digest.decode(msg["From"]), "to": digest.decode(msg["To"]),
            "date": digest.decode(msg["Date"]), "text": digest.full_text(msg),
            "has_html": digest.html_body(msg) is not None, "attachments": digest.attachment_names(msg),
        }
    resp = make_response(render_template_string(
        VIEW, e=row, d=detail, error=error, formatted=request.args.get("view") == "html",
        images=request.args.get("images") == "1", csrf=csrf_token()))
    resp.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; frame-src 'self'; form-action 'self'"
    return resp


@app.route("/email/<int:aid>/<gid>/html")
def view_email_html(aid: int, gid: str):
    """Sender's HTML in a sandbox: no scripts, no forms, remote images only when asked for."""
    row, msg, error = load_message(aid, gid)
    body = digest.html_body(msg) if msg is not None else None
    if body is None:
        abort(404)
    img = "data: https:" if request.args.get("images") == "1" else "data:"
    resp = make_response('<base target="_blank"><meta name="referrer" content="no-referrer">' + body)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    resp.headers["Content-Security-Policy"] = (
        f"sandbox allow-popups allow-popups-to-escape-sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src {img}")
    resp.headers["X-Frame-Options"] = "SAMEORIGIN"
    return resp


LABELS = {"needs_input": "Needs my input", "fyi": "FYI", "promo_or_newsletter": "Promo / newsletter",
          "automated": "Automated", "junk": "Junk"}
app.jinja_env.globals["LABELS"] = LABELS


@app.route("/reclassify/<int:aid>/<gid>", methods=["POST"])
def reclassify(aid: int, gid: str):
    """Fix a category and remember it, so future triage runs follow the correction."""
    check_csrf()
    new = request.form.get("to", "")
    if new not in digest.CATEGORIES:
        abort(400)
    with db() as c:
        row = c.execute("SELECT * FROM emails WHERE account_id=? AND gmail_id=?", (aid, gid)).fetchone()
        if row is None:
            abort(404)
        status = "open" if new == "needs_input" else "n/a"
        c.execute("UPDATE emails SET category=?, status=? WHERE account_id=? AND gmail_id=?", (new, status, aid, gid))
        addr = parseaddr(row["sender"])[1].lower() or row["sender"]
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        c.execute(
            "INSERT INTO feedback VALUES (?,?,?,?,?) ON CONFLICT(sender_addr) DO UPDATE SET "
            "sender=excluded.sender, subject=excluded.subject, category=excluded.category, at=excluded.at",
            (addr, row["sender"], row["subject"], new, now))
    nxt = request.form.get("next", "")
    return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("index"))


@app.route("/forget", methods=["POST"])
def forget():
    check_csrf()
    with db() as c:
        c.execute("DELETE FROM feedback WHERE sender_addr=?", (request.form.get("sender_addr", ""),))
    return redirect(url_for("index"))


@app.route("/status/<int:aid>/<gid>", methods=["POST"])
def status(aid: int, gid: str):
    check_csrf()
    new = "done" if request.form.get("to") == "done" else "open"
    with db() as c:
        c.execute("UPDATE emails SET status=? WHERE account_id=? AND gmail_id=? AND category='needs_input'", (new, aid, gid))
    return redirect(url_for("index"))


@app.route("/refresh", methods=["POST"])
def refresh():
    check_csrf()
    threading.Thread(target=poll, daemon=True).start()
    return redirect(url_for("index"))


@app.route("/settings")
def settings():
    return render_settings()


def render_settings(error: str = ""):
    with db() as c:
        accounts = c.execute("SELECT id, address, last_run, last_error FROM accounts ORDER BY id").fetchall()
    return render_template_string(SETTINGS, accounts=accounts, error=error, csrf=csrf_token())


@app.route("/settings/accounts", methods=["POST"])
def add_account():
    """Add a mailbox, or replace the app password of one already listed. The login is tested before saving."""
    check_csrf()
    address = request.form.get("address", "").strip().lower()
    password = re.sub(r"\s+", "", request.form.get("password", ""))  # Google shows app passwords in groups of four
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", address) or not password:
        return render_settings("Enter a Gmail address and its app password.")
    try:
        digest.check_login(address, password)
    except Exception as exc:
        return render_settings(f"Gmail rejected that login ({exc}). Check the app password and that IMAP is enabled.")
    with db() as c:
        c.execute("INSERT INTO accounts (address, password) VALUES (?, ?) "
                  "ON CONFLICT(address) DO UPDATE SET password=excluded.password, last_error=''",
                  (address, encrypt(password)))
    threading.Thread(target=poll, daemon=True).start()
    return redirect(url_for("settings"))


@app.route("/settings/accounts/<int:aid>/remove", methods=["POST"])
def remove_account(aid: int):
    check_csrf()
    with db() as c:
        c.execute("DELETE FROM emails WHERE account_id=?", (aid,))
        c.execute("DELETE FROM accounts WHERE id=?", (aid,))
    return redirect(url_for("settings"))


STYLE = """
:root{--bg:#f6f6f4;--card:#fff;--fg:#1d1d1b;--mute:#6b6b66;--line:#e2e2dd;--accent:#b4410f;--btn:#1d1d1b;--btnfg:#fff}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--card:#201f1e;--fg:#ecebe7;--mute:#9a9992;--line:#34332f;--accent:#f09060;--btn:#ecebe7;--btnfg:#161615}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,sans-serif}
main{max-width:720px;margin:0 auto;padding:16px}
h1{font-size:1.3rem;margin:8px 0}h2{font-size:1rem;margin:28px 0 8px;color:var(--mute);text-transform:uppercase;letter-spacing:.04em}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px;margin:8px 0}
.card.need{border-left:4px solid var(--accent)}
.subj{font-weight:600}.mute{color:var(--mute);font-size:.88rem}.dl{color:var(--accent);font-weight:600;font-size:.9rem}
a{color:inherit}button{font:inherit;background:var(--btn);color:var(--btnfg);border:0;border-radius:8px;padding:8px 14px;min-height:40px;cursor:pointer}
button.ghost{background:none;color:var(--mute);border:1px solid var(--line)}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:8px}.bar{display:flex;justify-content:space-between;align-items:center;gap:8px}
input{font:inherit;width:100%;padding:10px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--fg);margin:6px 0 12px}
.err{color:var(--accent)}details summary{cursor:pointer;color:var(--mute)}
.tag{font-size:.75rem;font-weight:400;color:var(--mute);border:1px solid var(--line);border-radius:6px;padding:0 6px;margin-left:6px}
.filters{display:flex;gap:12px;flex-wrap:wrap;font-size:.88rem;margin:6px 0}.filters .on{font-weight:600}
.gh{display:flex;justify-content:flex-end;max-width:720px;margin:0 auto;padding:12px 16px 0}
.gh a{display:inline-flex;align-items:center;gap:6px;color:var(--mute);font-size:.88rem;text-decoration:none}
.gh a:hover{color:var(--fg)}.gh svg{width:18px;height:18px;fill:currentColor}
"""

GITHUB_URL = "https://github.com/selbereth/mail-triage"
GH_LINK = (
    '<div class="gh"><a href="' + GITHUB_URL + '/issues/new" target="_blank" rel="noreferrer noopener" '
    'title="Report a bug on GitHub"><svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 '
    '2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13'
    '-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64'
    '-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 '
    '2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07'
    '-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>Report a bug</a></div>'
)

LOGIN = """<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mail Triage</title><style>""" + STYLE + """</style>""" + GH_LINK + """<main style="max-width:360px;margin-top:12vh">
<h1>Mail Triage</h1><form method="post">
<label>Username<input name="username" autocomplete="username" autofocus></label>
<label>Password<input name="password" type="password" autocomplete="current-password"></label>
{% if error %}<p class="err">{{ error }}</p>{% endif %}<button>Sign in</button></form></main></html>"""

HOME = """{% macro tag(e) %}{% if multi %}<span class="tag">{{ e.account or 'removed account' }}</span>{% endif %}{% endmacro %}
{% macro fix(e, csrf, next='/') %}<details class="fix"><summary>Wrong category?</summary>
<form method="post" action="/reclassify/{{ e.account_id }}/{{ e.gmail_id }}" class="row"><input type="hidden" name="csrf" value="{{ csrf }}">
<input type="hidden" name="next" value="{{ next }}">
{% for k, label in LABELS.items() if k != e.category %}<button name="to" value="{{ k }}" class="ghost">{{ label }}</button>{% endfor %}
</form><div class="mute">Future runs will treat mail from this sender the same way.</div></details>{% endmacro %}
<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mail Triage</title><style>""" + STYLE + """</style>""" + GH_LINK + """<main>
<div class="bar"><h1>Needs your input ({{ needs|length }})</h1>
<div class="row"><a class="mute" href="/settings">Settings</a>
<form method="post" action="/logout"><input type="hidden" name="csrf" value="{{ csrf }}"><button class="ghost">Log out</button></form></div></div>
{% if multi %}<div class="filters"><a href="/"{% if not acct %} class="on"{% endif %}>All accounts</a>
{% for a in accounts %}<a href="/?account={{ a.id }}"{% if acct == a.id %} class="on"{% endif %}>{{ a.address }}</a>{% endfor %}</div>{% endif %}
<form method="post" action="/refresh" class="row"><input type="hidden" name="csrf" value="{{ csrf }}">
<button class="ghost">Check now</button>
<span class="mute">Last checked {{ meta.get('last_run', 'never') }} UTC, then every {{ poll_minutes }} min</span></form>
{% if meta.get('last_error') %}<p class="err">Last error: {{ meta.last_error }}</p>{% endif %}

{% for e in needs %}<div class="card need">
<div class="subj"><a href="/email/{{ e.account_id }}/{{ e.gmail_id }}">{{ e.subject }}</a>{{ tag(e) }}</div>
<div class="mute">{{ e.sender }} &middot; {{ e.received[:16].replace('T', ' ') }}</div>
<div>{{ e.summary }}</div><div class="mute">{{ e.reason }}</div>
{% if e.deadline %}<div class="dl">Deadline: {{ e.deadline }}</div>{% endif %}
<form method="post" action="/status/{{ e.account_id }}/{{ e.gmail_id }}" class="row"><input type="hidden" name="csrf" value="{{ csrf }}">
<input type="hidden" name="to" value="done"><button>Done</button>
<a class="mute" href="{{ gmail_link(e.account, e.gmail_id) }}" target="_blank" rel="noreferrer noopener">Open in Gmail</a></form>{{ fix(e, csrf) }}</div>
{% else %}<p class="mute">{% if accounts %}Nothing needs you right now.{% else %}No mail accounts yet. <a href="/settings">Add one in Settings.</a>{% endif %}</p>{% endfor %}

{% if done %}<h2>Done</h2><details><summary>{{ done|length }} recent</summary>
{% for e in done %}<div class="card"><div class="subj"><a href="/email/{{ e.account_id }}/{{ e.gmail_id }}">{{ e.subject }}</a>{{ tag(e) }}</div><div class="mute">{{ e.sender }}</div>
<form method="post" action="/status/{{ e.account_id }}/{{ e.gmail_id }}" class="row"><input type="hidden" name="csrf" value="{{ csrf }}">
<input type="hidden" name="to" value="open"><button class="ghost">Reopen</button></form></div>{% endfor %}</details>{% endif %}

<h2>Everything else</h2><details><summary>{{ other|length }} recent emails</summary>
{% for e in other %}<div class="card"><div class="subj"><a href="/email/{{ e.account_id }}/{{ e.gmail_id }}">{{ e.subject }}</a>{{ tag(e) }}</div>
<div class="mute">{{ e.sender }} &middot; {{ e.category.replace('_', ' ') }}</div>
{% if e.category == 'fyi' %}<div>{{ e.summary }}</div>{% endif %}{{ fix(e, csrf) }}</div>{% endfor %}</details>

{% if junk %}<h2>Junk</h2><details><summary>{{ junk|length }} recent</summary>
{% for e in junk %}<div class="card"><div class="subj"><a href="/email/{{ e.account_id }}/{{ e.gmail_id }}">{{ e.subject }}</a>{{ tag(e) }}</div>
<div class="mute">{{ e.sender }}</div>{{ fix(e, csrf) }}</div>{% endfor %}</details>{% endif %}

<h2>What I have learned</h2><details><summary>{{ learned|length }} sender corrections</summary>
{% for l in learned %}<div class="card"><div class="mute">{{ l.sender }}</div><div>{{ LABELS.get(l.category, l.category) }}</div>
<form method="post" action="/forget" class="row"><input type="hidden" name="csrf" value="{{ csrf }}">
<input type="hidden" name="sender_addr" value="{{ l.sender_addr }}"><button class="ghost">Forget</button></form></div>
{% else %}<p class="mute">Nothing yet. Use "Wrong category?" on any email.</p>{% endfor %}</details>
</main></html>"""


VIEW = """{% macro tag(e) %}<span class="tag">{{ e.account }}</span>{% endmacro %}
{% macro fix(e, csrf, next='/') %}<details class="fix"><summary>Wrong category?</summary>
<form method="post" action="/reclassify/{{ e.account_id }}/{{ e.gmail_id }}" class="row"><input type="hidden" name="csrf" value="{{ csrf }}">
<input type="hidden" name="next" value="{{ next }}">
{% for k, label in LABELS.items() if k != e.category %}<button name="to" value="{{ k }}" class="ghost">{{ label }}</button>{% endfor %}
</form><div class="mute">Future runs will treat mail from this sender the same way.</div></details>{% endmacro %}
<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ e.subject }}</title><style>""" + STYLE + """
pre{white-space:pre-wrap;word-wrap:break-word;font:inherit;margin:12px 0}
iframe{width:100%;height:70vh;border:1px solid var(--line);border-radius:8px;background:#fff}</style>""" + GH_LINK + """<main>
<p><a href="/">&larr; Back</a></p>
<h1>{{ e.subject }}</h1>
<div class="card"><div class="mute">{{ d.get('from') or e.sender }}{{ tag(e) }}</div>
{% if d.to %}<div class="mute">To: {{ d.to }}</div>{% endif %}
<div class="mute">{{ d.date or e.received[:16].replace('T', ' ') }}</div>
<div>{{ e.summary }}</div>{% if e.deadline %}<div class="dl">Deadline: {{ e.deadline }}</div>{% endif %}</div>
{% if error %}<p class="err">{{ error }}</p>{% else %}
<div class="row">
{% if formatted %}<a href="/email/{{ e.account_id }}/{{ e.gmail_id }}">Plain text</a>
{% if images %}<a href="/email/{{ e.account_id }}/{{ e.gmail_id }}?view=html">Hide images</a>{% else %}<a href="/email/{{ e.account_id }}/{{ e.gmail_id }}?view=html&images=1">Load images (tells the sender you read it)</a>{% endif %}
{% elif d.has_html %}<a href="/email/{{ e.account_id }}/{{ e.gmail_id }}?view=html">Formatted</a>{% endif %}
<a class="mute" href="{{ gmail_link(e.account, e.gmail_id) }}" target="_blank" rel="noreferrer noopener">Open in Gmail</a></div>
{{ fix(e, csrf, '/email/' ~ e.account_id ~ '/' ~ e.gmail_id) }}
{% if formatted %}<iframe sandbox="allow-popups allow-popups-to-escape-sandbox" src="/email/{{ e.account_id }}/{{ e.gmail_id }}/html{% if images %}?images=1{% endif %}"></iframe>
{% else %}<pre>{{ d.text or '(no text)' }}</pre>{% endif %}
{% if d.attachments %}<p class="mute">Attachments (open in Gmail): {{ d.attachments|join(', ') }}</p>{% endif %}
{% endif %}
</main></html>"""


SETTINGS = """<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Settings</title><style>""" + STYLE + """</style>""" + GH_LINK + """<main>
<p><a href="/">&larr; Back</a></p>
<h1>Mail accounts</h1>
<p class="mute">Every account is checked in turn and shown together on the home page. App passwords are stored encrypted in the data volume.</p>
{% for a in accounts %}<div class="card"><div class="subj">{{ a.address }}</div>
<div class="mute">{% if a.last_run %}Last checked {{ a.last_run }} UTC{% else %}Not checked yet{% endif %}</div>
{% if a.last_error %}<div class="err">{{ a.last_error }}</div>{% endif %}
<form method="post" action="/settings/accounts/{{ a.id }}/remove" class="row"><input type="hidden" name="csrf" value="{{ csrf }}">
<button class="ghost">Remove</button><span class="mute">Also deletes its stored summaries here (nothing is touched in Gmail).</span></form></div>
{% else %}<p class="mute">No accounts yet.</p>{% endfor %}
<h2>Add an account</h2>
<form method="post" action="/settings/accounts" class="card"><input type="hidden" name="csrf" value="{{ csrf }}">
<label>Gmail address<input name="address" type="email" autocomplete="off" required></label>
<label>App password<input name="password" type="password" autocomplete="new-password" required></label>
{% if error %}<p class="err">{{ error }}</p>{% endif %}
<div class="mute">Google Account &gt; Security &gt; 2-Step Verification &gt; App passwords, with IMAP enabled. Adding an address already listed replaces its password.</div>
<div class="row"><button>Test and add</button></div></form>
</main></html>"""


init_db()
if os.environ.get("DISABLE_POLLER") != "1":
    threading.Thread(target=poller, daemon=True).start()
