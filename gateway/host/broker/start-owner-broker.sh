#!/bin/sh
# Exact Nexus host maintenance. No caller paths, credentials or shell payloads.
set -eu
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset DOCKER_HOST DOCKER_CONTEXT DOCKER_TLS_VERIFY DOCKER_CERT_PATH
test "$#" -eq 0
test "$(id -u)" -eq 0
test "$(hostname | tr '[:upper:]' '[:lower:]')" = nexus
root=/var/lib/reach-owner/broker
/usr/bin/php "$root/owner_broker.php" check >/dev/null
test "$(/usr/bin/docker info --format '{{.Name}}' | tr '[:upper:]' '[:lower:]')" = nexus
/usr/bin/docker image inspect 'python:3.12.12-slim-bookworm@sha256:593bd06efe90efa80dc4eee3948be7c0fde4134606dd40d8dd8dbcade98e669c' >/dev/null 2>&1
if /usr/bin/php "$root/owner_broker.php" ping >/dev/null 2>&1; then exit 0; fi
nohup /usr/bin/php -d memory_limit=256M "$root/owner_broker.php" serve </dev/null >/dev/null 2>&1 &
attempt=0
while test "$attempt" -lt 6; do
  if /usr/bin/php "$root/owner_broker.php" ping >/dev/null 2>&1; then exit 0; fi
  attempt=$((attempt+1))
  sleep 0.2
done
exit 1
