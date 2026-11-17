#!/usr/bin/env bash
# Install the guard webhook receiver on a Linux server with systemd. Run as root.
# Re-running updates the files and keeps the existing token and webhook secret.
set -euo pipefail
GUARD_COMMIT=92b09ece929f8b642e1a51c6f887cd7b411cf4ab
GUARD_SHA256=5a5f3be565b86304df5cb749186136c470b3d5a122f90ce1cad8f9e7c27611af
DIR=/opt/homura-guard ENV=/etc/homura-guard.env UNIT=/etc/systemd/system/homura-guard.service

[ "$(id -u)" = 0 ] || { echo "run as root (sudo bash)"; exit 1; }
missing=""; for c in python3 gh jq curl systemctl; do command -v $c >/dev/null || missing="$missing $c"; done
[ -z "$missing" ] || { echo "install first:$missing"; exit 1; }

id homura-guard >/dev/null 2>&1 || useradd --system --home-dir "$DIR" --shell /usr/sbin/nologin homura-guard
install -d -o root -g root -m 755 "$DIR"

curl -sfL "https://raw.githubusercontent.com/01-1/homura-ai-guard/$GUARD_COMMIT/guard.sh" -o "$DIR/guard.sh.new"
echo "$GUARD_SHA256  $DIR/guard.sh.new" | sha256sum -c --quiet
mv "$DIR/guard.sh.new" "$DIR/guard.sh"; chmod 755 "$DIR/guard.sh"

cat > "$DIR/guard-hook.py" <<'PYEOF'
#!/usr/bin/env python3
"""Run guard.sh for one repo as soon as GitHub reports a change to it.

Receives org webhooks (repository and repository_ruleset events), checks the
HMAC signature, answers 202 at once and runs `guard.sh <repo>` in the
background, one run at a time. Settings come from the environment:
WEBHOOK_SECRET, GH_TOKEN, ORG, BOT, GUARD_SH (path to guard.sh),
LISTEN (host:port, default 127.0.0.1:8787).
"""
import hashlib
import hmac
import json
import os
import queue
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SECRET = os.environ["WEBHOOK_SECRET"].encode()
ORG = os.environ["ORG"]
GUARD_SH = os.environ.get("GUARD_SH", "/opt/homura-guard/guard.sh")
HOST, PORT = os.environ.get("LISTEN", "127.0.0.1:8787").rsplit(":", 1)
EVENTS = {"repository", "repository_ruleset"}
MAX_BODY = 5 * 1024 * 1024

jobs: "queue.Queue[str]" = queue.Queue()


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def worker() -> None:
    while True:
        repo = jobs.get()
        # Skip duplicates already waiting (one push of events often names the same repo).
        pending = set()
        while not jobs.empty():
            pending.add(jobs.get_nowait())
        for name in [repo, *sorted(pending - {repo})]:
            r = subprocess.run([GUARD_SH, name], capture_output=True, text=True, timeout=300)
            out = (r.stdout + r.stderr).strip()
            log(f"guard {name}: exit {r.returncode}" + (f"\n{out}" if out else ""))


class Hook(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_BODY:
            return self.reply(400)
        body = self.rfile.read(length)
        sig = self.headers.get("X-Hub-Signature-256", "")
        want = "sha256=" + hmac.new(SECRET, body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, want):
            return self.reply(401)
        event = self.headers.get("X-GitHub-Event", "")
        if event == "ping":
            return self.reply(200)
        if event not in EVENTS:
            return self.reply(204)
        try:
            data = json.loads(body)
            repo = data["repository"]["name"]
            owner = data["repository"]["owner"]["login"]
        except (ValueError, KeyError, TypeError):
            return self.reply(400)
        if owner.lower() != ORG.lower() or data.get("action") == "deleted" and event == "repository":
            return self.reply(204)
        log(f"{event}.{data.get('action')} {repo}")
        jobs.put(repo)
        self.reply(202)

    def do_GET(self) -> None:
        self.reply(200 if self.path == "/healthz" else 404)

    def reply(self, code: int) -> None:
        self.send_response(code)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args) -> None:  # quiet default access log
        pass


if __name__ == "__main__":
    threading.Thread(target=worker, daemon=True).start()
    log(f"listening on {HOST}:{PORT} for {ORG}")
    ThreadingHTTPServer((HOST, int(PORT)), Hook).serve_forever()
PYEOF
chmod 755 "$DIR/guard-hook.py"

if [ ! -f "$ENV" ]; then
  read -rsp "Paste the fine-grained token (owner homura-ai, all repos, Administration read/write): " tok; echo
  [ -n "$tok" ] || { echo "no token given"; exit 1; }
  umask 077
  printf 'GH_TOKEN=%s\nWEBHOOK_SECRET=%s\nORG=homura-ai\nBOT=meowc-at\nGUARD_SH=%s/guard.sh\nLISTEN=127.0.0.1:8787\nGH_CONFIG_DIR=%s/.gh\n' \
    "$tok" "$(python3 -c 'import secrets; print(secrets.token_hex(32))')" "$DIR" "$DIR" > "$ENV"
  chown root:homura-guard "$ENV"; chmod 640 "$ENV"
fi
install -d -o homura-guard -g homura-guard -m 700 "$DIR/.gh"

cat > "$UNIT" <<EOF
[Unit]
Description=homura-ai guard webhook receiver
After=network-online.target
Wants=network-online.target

[Service]
User=homura-guard
EnvironmentFile=$ENV
ExecStart=/usr/bin/env python3 $DIR/guard-hook.py
Restart=always
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$DIR/.gh
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now homura-guard.service
systemctl restart homura-guard.service
sleep 1
curl -sf -o /dev/null http://127.0.0.1:8787/healthz && echo "receiver is up on 127.0.0.1:8787"
echo
echo "Webhook secret (paste into the org webhook):"
grep '^WEBHOOK_SECRET=' "$ENV" | cut -d= -f2
echo
echo "Logs: journalctl -u homura-guard -f"
