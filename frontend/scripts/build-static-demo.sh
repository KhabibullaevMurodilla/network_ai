#!/usr/bin/env bash
# Builds the GitHub Pages site as a static export in LOCAL MODE: the whole dashboard runs in the
# visitor's browser against a browser-local database (IndexedDB). No backend, no Supabase, no login.
# Only server-only code (login, onboarding, team, alert delivery ...) is moved aside for the build.
# Usage (from frontend/):  NEXT_PUBLIC_BASE_PATH=/<repo-name> bash scripts/build-static-demo.sh
set -euo pipefail
cd "$(dirname "$0")/.."
STASH="$(mktemp -d)"
MOVE="login dashboard/team dashboard/onboarding dashboard/alerts dashboard/response-actions dashboard/settings dashboard/physical"
restore() { for d in $MOVE; do [ -d "$STASH/$d" ] && mv "$STASH/$d" "app/$d"; done; rm -rf "$STASH"; }
trap restore EXIT
for d in $MOVE; do mkdir -p "$STASH/$(dirname "$d")"; mv "app/$d" "$STASH/$d"; done
export NEXT_PUBLIC_STATIC_DEMO=1
export NEXT_PUBLIC_LOCAL_MODE=1
rm -rf .next out
npx next build
touch out/.nojekyll
echo "local-mode site built in $(pwd)/out"
