#!/bin/sh
set -e

# Ensure the data volume is writable by the unprivileged runtime user.
if [ -d /data ]; then
  chown -R node:node /data 2>/dev/null || true
fi

exec su-exec node "$@"
