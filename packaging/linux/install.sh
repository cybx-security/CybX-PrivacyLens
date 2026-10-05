#!/bin/sh
# Installs PrivacyLens for every user of this machine (needs root).
cd "$(dirname "$0")" || exit 1
if [ ! -x ./privacylens ]; then
  echo "install.sh must sit next to the privacylens binary (extract the whole archive first)." >&2
  exit 1
fi
if [ "$(id -u)" -eq 0 ]; then
  exec ./privacylens install "$@"
fi
echo "Installing PrivacyLens needs root; you may be asked for your password."
exec sudo ./privacylens install "$@"
