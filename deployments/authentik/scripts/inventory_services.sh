#!/bin/bash
# Inventory all 29 services - find them and detect tech stack

SERVICES=(
  "viralvisions.io" "aeims.app" "veribits.com" "afterdarksys.com"
  "telcocloud.io" "computeapi.io" "systemapi.io"
  "purrr.love" "purrr.me" "cats.center" "dogs.institute"
  "darkstorage.io" "shipshack.io" "console.darkapi.io"
  "promptery.io" "aiserve.farm" "lonely.fyi"
  "llmsecurity.dev" "model2go.com" "flipdomain.io" "flipid.io"
  "petalarm.ai" "web3dns.io" "itz.agency" "onedns.io"
  "betterphish.io" "basebot.ai" "filehashes.io" "afterapps.io"
)

BASE_DIR=~/development

echo "Service|Tech Stack|Path|OAuth Ready"
echo "-------|----------|----|-----------"

for service in "${SERVICES[@]}"; do
  # Try multiple path variations
  for variation in "$service" "${service//./-}" "${service//./}"; do
    path="$BASE_DIR/$variation"

    if [ -d "$path" ]; then
      tech="unknown"

      # Detect tech stack
      if [ -f "$path/package.json" ]; then
        if grep -q "next" "$path/package.json" 2>/dev/null; then
          tech="nextjs"
        else
          tech="nodejs"
        fi
      elif [ -f "$path/go.mod" ]; then
        tech="go"
      elif [ -f "$path/composer.json" ] || [ -f "$path/index.php" ]; then
        tech="php"
      elif [ -f "$path/requirements.txt" ] || [ -f "$path/main.py" ]; then
        tech="python"
      fi

      # Check if .env.production exists
      oauth_ready="no"
      [ -f "$path/.env.production" ] && oauth_ready="yes"

      echo "$service|$tech|$path|$oauth_ready"
      break
    fi
  done
done | column -t -s '|'
