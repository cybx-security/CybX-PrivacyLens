#!/bin/sh
# Removes PrivacyLens (needs root). Pass -purge to delete settings and logs too.
BIN=/usr/local/bin/privacylens
[ -x "$BIN" ] || BIN="$(dirname "$0")/privacylens"
if [ ! -x "$BIN" ]; then
  echo "PrivacyLens does not appear to be installed." >&2
  exit 1
fi
if [ "$(id -u)" -eq 0 ]; then
  exec "$BIN" uninstall "$@"
fi
exec sudo "$BIN" uninstall "$@"
