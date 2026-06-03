#!/usr/bin/env bash
# =====================================================================
#  ONE-TIME SETUP — run this once on your phone (in Termux).
#  After this, you only ever need:  bash deploy.sh
# =====================================================================
set -e

echo ""
echo "==> (1/3) Installing Node.js and Git..."
pkg update -y && pkg install -y nodejs git

echo ""
echo "==> (2/3) Installing Firebase tools..."
npm install -g firebase-tools

echo ""
echo "==> (3/3) Logging in to Firebase."
echo "    A link will appear below."
echo "    1. Open it in your phone's browser"
echo "    2. Pick your Google account"
echo "    3. Copy the code it gives you and paste it back here, then press Enter"
echo ""
firebase login --no-localhost

echo ""
echo "====================================================================="
echo "  All set! From now on, to push changes live just run:"
echo ""
echo "      bash deploy.sh"
echo ""
echo "====================================================================="
