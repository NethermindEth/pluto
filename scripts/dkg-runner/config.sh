#!/usr/bin/env bash
# config.sh — shared environment defaults for the DKG runner scripts.
# Source this file at the top of every script in this directory.
#
# All variables can be overridden by setting them in the environment before
# invoking any script.

: "${NODES:=4}"
: "${THRESHOLD:=3}"
: "${PLUTO_NODES:=2}"
: "${CHARON_NODES:=2}"
: "${RELAY_URL:=https://0.relay.obol.tech}"
: "${TIMEOUT:=120}"
: "${PLUTO_BIN:=./target/debug/pluto}"
: "${CHARON_BIN:=charon}"
: "${WORK_DIR:=/tmp/dkg-run}"
: "${KEEP_NODES:=0}"
: "${NETWORK:=holesky}"
: "${FEE_RECIPIENT:=0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF}"
: "${WITHDRAWAL_ADDR:=0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF}"
