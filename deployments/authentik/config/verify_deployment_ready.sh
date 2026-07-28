#!/bin/bash
# Verify all OAuth deployment files are ready

echo "🔍 OAuth Deployment Readiness Check"
echo "===================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

TOTAL_CHECKS=0
PASSED_CHECKS=0

check() {
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✅${NC} $2"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        echo -e "${RED}❌${NC} $2"
    fi
}

# Check 1: Master .env.production exists
[ -f "config/.env.production" ]
check $? "Master .env.production exists"

# Check 2: Production secrets JSON exists
[ -f "config/production_oauth_secrets.json" ]
check $? "Production OAuth secrets JSON exists"

# Check 3: Production domains JSON exists
[ -f "config/production_domains.json" ]
check $? "Production domains JSON exists"

# Check 4: Services directory exists
[ -d "config/services" ]
check $? "Services directory exists"

# Check 5: Count service .env files
SERVICE_COUNT=$(find config/services -name ".env.production" | wc -l | tr -d ' ')
[ "$SERVICE_COUNT" -eq 29 ]
check $? "All 29 service .env files exist (found: $SERVICE_COUNT)"

# Check 6: OAuth middleware template exists
[ -f "OAUTH_MIDDLEWARE_TEMPLATE.md" ]
check $? "OAuth middleware template exists"

# Check 7: Launch checklist exists
[ -f "LAUNCH_CHECKLIST_FEB2.md" ]
check $? "Launch checklist exists"

# Check 8: Deployment summary exists
[ -f "DEPLOYMENT_SUMMARY.md" ]
check $? "Deployment summary exists"

# Check 9: Quick start guide exists
[ -f "QUICK_START.md" ]
check $? "Quick start guide exists"

# Check 10: Deploy script exists
[ -f "config/deploy_env_files.sh" ]
check $? "Deployment helper script exists"

# Check 11: adsyslib OAuth module exists
[ -f "/Users/ryan/development/adsyslib/src/adsyslib/authentik/oauth.py" ]
check $? "adsyslib OAuth module exists"

# Check 12: Verify .gitignore protects secrets
grep -q "config/services/\*\*/\.env\*" .gitignore
check $? ".gitignore protects service .env files"

# Check 13: Verify all 29 services have unique CLIENT_ID
UNIQUE_IDS=$(grep -h "AUTHENTIK_CLIENT_ID=" config/services/*/.env.production | sort -u | wc -l | tr -d ' ')
[ "$UNIQUE_IDS" -eq 29 ]
check $? "All 29 services have unique client IDs (found: $UNIQUE_IDS)"

# Check 14: Verify all 29 services have unique SESSION_SECRET
UNIQUE_SECRETS=$(grep -h "SESSION_SECRET=" config/services/*/.env.production | sort -u | wc -l | tr -d ' ')
[ "$UNIQUE_SECRETS" -eq 29 ]
check $? "All 29 services have unique session secrets (found: $UNIQUE_SECRETS)"

# Check 15: Verify Authentik container running
docker ps | grep -q "authentik-server"
check $? "Authentik container is running"

echo ""
echo "===================================="
echo -e "${GREEN}${PASSED_CHECKS}${NC} / ${TOTAL_CHECKS} checks passed"
echo ""

if [ $PASSED_CHECKS -eq $TOTAL_CHECKS ]; then
    echo -e "${GREEN}🚀 All checks passed! Ready to deploy OAuth to services.${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Review QUICK_START.md for deployment instructions"
    echo "  2. Start with infrastructure services (see LAUNCH_CHECKLIST_FEB2.md)"
    echo "  3. Copy .env.production files to service directories"
    echo "  4. Add OAuth middleware code (see OAUTH_MIDDLEWARE_TEMPLATE.md)"
    echo "  5. Deploy and test each service"
    exit 0
else
    echo -e "${RED}❌ Some checks failed. Fix issues before deploying.${NC}"
    exit 1
fi
