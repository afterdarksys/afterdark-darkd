#!/bin/bash
# Git commit and push OAuth changes to all services

set -e

COMMIT_MESSAGE="Migrate to After Dark Authentication

- Integrate Authentik OAuth/SSO for centralized authentication
- Add OAuth login, callback, and logout endpoints
- Support both local auth and SSO
- Configure production OAuth credentials
- Launch date: February 2, 2026"

ALL_SERVICES=(
  # Next.js services
  "viralvisions.io"
  "aeims.app"
  "telcocloud.io"
  "cats.center"
  "dogs.institute"

  # PHP services
  "veribits.com"
  "purrr.love"
  "purrr.me"

  # Python services
  "promptery.io"
  "flipdomain.io"
  "itz.agency"
  "onedns.io"
  "betterphish.io"
)

echo "🚀 Committing OAuth changes to all services..."
echo ""

for service in "${ALL_SERVICES[@]}"; do
  SERVICE_DIR="/Users/ryan/development/$service"

  if [ ! -d "$SERVICE_DIR" ]; then
    echo "⚠️  $service - Directory not found, skipping"
    continue
  fi

  echo "📦 Processing $service..."
  cd "$SERVICE_DIR"

  # Check if it's a git repo
  if [ ! -d ".git" ]; then
    echo "  ⚠️  Not a git repository, skipping"
    continue
  fi

  # Check for changes
  if [ -n "$(git status --porcelain)" ]; then
    # Add all changes
    git add .
    echo "  ✅ Staged changes"

    # Commit
    git commit -m "$COMMIT_MESSAGE"
    echo "  ✅ Committed changes"

    # Push
    git push
    echo "  ✅ Pushed to remote"
  else
    echo "  ℹ️  No changes to commit"
  fi

  echo ""
done

echo "✅ All services committed and pushed!"
