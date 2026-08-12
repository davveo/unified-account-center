#!/bin/sh
set -e

echo "[entrypoint] waiting for mysql:3306 ..."
i=0
while [ "$i" -lt 60 ]; do
  if nc -z mysql 3306 >/dev/null 2>&1; then
    echo "[entrypoint] mysql is reachable"
    break
  fi
  i=$((i + 1))
  sleep 2
done

echo "[entrypoint] waiting for redis:6379 ..."
i=0
while [ "$i" -lt 30 ]; do
  if nc -z redis 6379 >/dev/null 2>&1; then
    echo "[entrypoint] redis is reachable"
    break
  fi
  i=$((i + 1))
  sleep 1
done

exec "$@"
