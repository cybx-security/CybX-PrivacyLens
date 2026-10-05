#!/bin/bash
# Double-click uninstaller for PrivacyLens on macOS.
cd "$(dirname "$0")" || exit 1
clear
echo "PrivacyLens Uninstall"
echo "====================="
echo
BIN=/usr/local/bin/privacylens
[ -x "$BIN" ] || BIN=./privacylens
if [ ! -x "$BIN" ]; then
  echo "PrivacyLens does not appear to be installed on this Mac."
else
  echo "Type your Mac password when asked (nothing shows as you type) and press Return."
  echo
  sudo "$BIN" uninstall
fi
echo
read -n 1 -s -r -p "Press any key to close this window."
echo
