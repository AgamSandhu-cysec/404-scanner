#!/usr/bin/env bash
# deploy.sh — push latest changes to GitHub and update GitHub Pages
# Usage: ./deploy.sh "Your commit message"

set -e  # Exit on any error

COMMIT_MSG="${1:-"chore: update site $(date '+%Y-%m-%d %H:%M')"}"

echo "📦  Staging all changes..."
git add -A

echo "💬  Committing: $COMMIT_MSG"
git commit -m "$COMMIT_MSG"

echo "🚀  Pushing to GitHub (main)..."
git push origin main

echo "✅  Done! GitHub Pages will rebuild in ~30 seconds."
echo "    🔗  https://<YOUR-USERNAME>.github.io/404-scanner/"
