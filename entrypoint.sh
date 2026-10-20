#!/bin/sh
# Run the app as PUID:PGID (default 1000:100). If started non-root (e.g. `user:` in compose), just exec.
set -e
if [ "$(id -u)" != "0" ]; then
  exec "$@"
fi
PUID="${PUID:-1000}"
PGID="${PGID:-100}"
getent group "$PGID" >/dev/null || groupadd -g "$PGID" app
getent passwd "$PUID" >/dev/null || useradd -u "$PUID" -g "$PGID" -M -d /data -s /usr/sbin/nologin app
chown -R "$PUID:$PGID" /data
exec setpriv --reuid="$PUID" --regid="$PGID" --clear-groups "$@"
