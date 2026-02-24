#!/usr/bin/env bash
# =============================================================================
# fix-and-push.sh
# Cleans bad git history (with leaked secrets), rebuilds a fresh repo,
# and force-pushes only safe files to GitHub.
#
# Usage:
#   chmod +x fix-and-push.sh
#   ./fix-and-push.sh
#
# Run from the project root: ~/Desktop/replitzip
# =============================================================================

set -euo pipefail

REPO_URL="https://github.com/AgamSandhu-cysec/404-scanner.git"
GITHUB_USER="AgamSandhu-cysec"
BRANCH="main"

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()  { echo -e "${CYAN}[INFO]${RESET}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
ok()    { echo -e "${GREEN}[OK]${RESET}    $*"; }
fatal() { echo -e "${RED}[FATAL]${RESET} $*"; exit 1; }

# ── 0. Sanity checks ─────────────────────────────────────────────────────────
[[ "$(basename "$PWD")" != "replitzip" && ! -f "server.js" ]] && \
  fatal "Please run this script from the project root (~/Desktop/replitzip)."

command -v git &>/dev/null || fatal "git is not installed."

echo -e "\n${BOLD}╔══════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║   404-scanner — Clean Git Push Fix                  ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════╝${RESET}\n"

# ── 1. Securely read GitHub Personal Access Token ────────────────────────────
echo -e "${YELLOW}Enter your GitHub Personal Access Token (classic, repo scope).${RESET}"
echo -e "${YELLOW}Input is hidden — it will NOT appear on screen or be saved.${RESET}"
read -rsp "Token: " GH_TOKEN
echo ""
[[ -z "$GH_TOKEN" ]] && fatal "No token provided. Aborting."

# Build authenticated remote URL (used only for this push, never stored)
AUTH_URL="https://${GITHUB_USER}:${GH_TOKEN}@github.com/AgamSandhu-cysec/404-scanner.git"

# ── 2. Remove existing .git (erase bad history) ──────────────────────────────
if [ -d ".git" ]; then
  warn "An existing .git directory was found — this contains the commit history"
  warn "with the leaked secret. It must be removed to create a clean history."
  echo ""
  read -rp "$(echo -e "${RED}Delete .git and start fresh? [y/N]: ${RESET}")" CONFIRM
  [[ "${CONFIRM,,}" != "y" ]] && fatal "Aborted by user."
  rm -rf .git
  ok ".git removed."
else
  info "No existing .git directory found — starting fresh."
fi

# ── 3. Write / overwrite .gitignore ──────────────────────────────────────────
info "Writing .gitignore …"
cat > .gitignore << 'GITIGNORE'
# ── Node ──────────────────────────────────────────────────────────────────────
node_modules/
.npm
.pnp
.pnp.js

# ── Secrets / Environment (NEVER commit) ─────────────────────────────────────
.env
.env.*
!.env.example

# ── Local system / Replit artefacts ──────────────────────────────────────────
.local/
.replit
replit.nix
.cache/

# ── Databases (may contain tokens) ───────────────────────────────────────────
*.db
*.db-wal
*.db-shm
*.sqlite
*.sqlite3

# ── Logs ──────────────────────────────────────────────────────────────────────
*.log
logs/
npm-debug.log*

# ── Build output ──────────────────────────────────────────────────────────────
dist/
build/
out/
.next/

# ── OS / Editor ────────────────────────────────────────────────────────────────
.DS_Store
Thumbs.db
.idea/
.vscode/
*.swp
*~

# ── Misc ───────────────────────────────────────────────────────────────────────
*.tgz
coverage/
tmp/
temp/
GITIGNORE
ok ".gitignore written."

# ── 4. Initialise fresh repo ─────────────────────────────────────────────────
info "Initialising fresh git repository …"
git init -b "$BRANCH"
ok "git init done."

# ── 5. Configure git user (use existing config if already set) ────────────────
if ! git config user.email &>/dev/null; then
  git config user.email "${GITHUB_USER}@users.noreply.github.com"
  git config user.name  "$GITHUB_USER"
  info "Git user identity set to GitHub no-reply address."
fi

# ── 6. Stage safe project files ──────────────────────────────────────────────
info "Staging project files …"

# Explicitly add only known-safe paths
SAFE_PATHS=()

# Core backend/config files in root
for f in server.js package.json package-lock.json \
          .env.example README.md wordlist.txt wordlist.json \
          .gitignore deploy.sh; do
  [ -f "$f" ] && SAFE_PATHS+=("$f")
done

# Directories (all safe after .gitignore filtering)
for d in public/ lib/ routes/ middleware/ owaspScanner.js fix-and-push.sh; do
  [ -e "$d" ] && SAFE_PATHS+=("$d")
done

if [ ${#SAFE_PATHS[@]} -eq 0 ]; then
  fatal "Nothing safe to stage. Is this the right directory?"
fi

git add -- "${SAFE_PATHS[@]}"

# Show what will be committed
echo ""
info "Files staged for commit:"
git diff --cached --name-only | sed 's/^/    ✓ /'
echo ""

# Final double-check: make sure .env (real) and .local are NOT staged
# .env.example is safe — it only contains placeholder values, so we allow it
if git diff --cached --name-only | grep -E '(^\.env$|^\.env\.|^\.local/)' | grep -qv '\.env\.example'; then
  fatal "SAFETY CHECK FAILED: a real .env or .local file is about to be committed! Aborting."
fi

# ── 7. Initial commit ─────────────────────────────────────────────────────────
info "Creating initial commit …"
git commit -m "Initial commit of 404 scanner"
ok "Commit created."

# ── 8. Add remote ─────────────────────────────────────────────────────────────
info "Adding remote origin …"
git remote add origin "$REPO_URL" 2>/dev/null || {
  warn "Remote 'origin' already exists — updating URL."
  git remote set-url origin "$REPO_URL"
}
ok "Remote set to $REPO_URL"

# ── 9. Push (with embedded token — one-time, not stored in config) ────────────
info "Pushing to GitHub (force — replaces previous history) …"
git push --force "$AUTH_URL" "$BRANCH"
ok "Push successful!"

# ── 10. Unset the token variable from memory ──────────────────────────────────
unset GH_TOKEN AUTH_URL

# ── Done ─────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}${BOLD}║   ✅  All done!                                      ║${RESET}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "  🔗  Repository : ${CYAN}https://github.com/AgamSandhu-cysec/404-scanner${RESET}"
echo -e "  🌐  Pages URL  : ${CYAN}https://AgamSandhu-cysec.github.io/404-scanner/${RESET}"
echo -e "       ${YELLOW}(Pages won't work until you enable it — see steps below)${RESET}"
echo ""
echo -e "${BOLD}Manual step required to enable GitHub Pages:${RESET}"
echo -e "  1. Go to  → https://github.com/AgamSandhu-cysec/404-scanner/settings/pages"
echo -e "  2. Source → Deploy from branch"
echo -e "  3. Branch → main   |   Folder → /public"
echo -e "  4. Click Save  →  live in ~30 seconds"
echo ""
