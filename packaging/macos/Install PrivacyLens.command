#!/bin/bash
# Double-click installer for PrivacyLens on macOS. Opens in Terminal and
# runs "privacylens install", which needs an administrator password.
cd "$(dirname "$0")" || exit 1
clear
echo "PrivacyLens Setup"
echo "================="
echo
if [ ! -x ./privacylens ]; then
  echo "Setup cannot find its files. Unzip the download first, then"
  echo "double-click \"Install PrivacyLens\" inside the unzipped folder."
  echo
  read -n 1 -s -r -p "Press any key to close this window."
  exit 1
fi
# Downloads are quarantined by macOS; clear that for PrivacyLens's own
# files so the installer and the app can start.
xattr -dr com.apple.quarantine . 2>/dev/null
echo "Installing for every user of this Mac needs an administrator password."
echo "Type your Mac password when asked (nothing shows as you type) and press Return."
echo
sudo ./privacylens install
echo
read -n 1 -s -r -p "Press any key to close this window."
echo
