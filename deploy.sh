#!/usr/bin/env bash
# =====================================================================
#  DEPLOY — run this any time you want to push changes live.
#  Just type:   bash deploy.sh
# =====================================================================
set -e

# Always work from the folder this script lives in.
cd "$(dirname "$0")"

echo ""
echo "==> Getting the latest changes..."
# This phone is deploy-only (you never edit code here), so we just make the
# folder match GitHub exactly. Avoids "divergent branches" errors completely.
git fetch origin main
git reset --hard origin/main

echo ""
echo "==> Publishing your app to the web..."
firebase deploy --only hosting --project inventory-setup-b3f20

echo ""
echo "====================================================================="
echo "  Done! Your app is live. ✅"
echo "  Open it on your phone and pull down to refresh to see the changes."
echo "====================================================================="
