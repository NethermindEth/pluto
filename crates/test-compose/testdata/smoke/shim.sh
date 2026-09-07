#!/bin/sh
# Stand-in for the external programs the compose harness spawns (docker, sudo,
# git, cat). Installed under all four names in a temporary bin directory that
# is put first on PATH. Every invocation is appended to ../transcript.log as
# "<program> <args>\t<cwd>" so the command sequence of a harness run can be
# compared without a docker daemon.
#
# Canned behaviour, enough to drive the harness through a full run:
#   - `git rev-parse --short=7 HEAD` prints a fixed hash;
#   - the prometheus rules query answers a successful, empty rule set;
#   - `docker compose up --no-start --build` drops a marker, after which the
#     final `docker compose up ...` blocks like a live cluster until killed;
#   - everything else exits 0 silently.
root=$(dirname "$0")/..
program=$(basename "$0")
line=$program
for arg in "$@"; do
    line="$line $arg"
done
printf '%s\t%s\n' "$line" "$PWD" >> "$root/transcript.log"

case "$program $*" in
    "git rev-parse --short=7 HEAD")
        printf 'abcdef0\n'
        ;;
    "docker compose exec -T curl curl -s http://prometheus:9090/api/v1/rules?type=alert")
        printf '{"status":"success","data":{"groups":[]}}\n'
        ;;
    "docker compose up --no-start --build")
        : > "$root/created"
        ;;
    "docker compose up --remove-orphans --abort-on-container-exit --quiet-pull")
        if [ -e "$root/created" ]; then
            exec sleep 3600
        fi
        ;;
esac
exit 0
